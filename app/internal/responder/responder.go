package responder

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Labels and annotations the responder puts on a pod it contains.
const (
	LabelQuarantine          = "aegis.dev/quarantine"
	AnnotationIncident       = "aegis.dev/incident"
	AnnotationRule           = "aegis.dev/falco-rule"
	AnnotationQuarantinedAt  = "aegis.dev/quarantined-at"
	AnnotationTerminateAfter = "aegis.dev/terminate-after"
	AnnotationOriginalLabels = "aegis.dev/original-labels"
	LabelIncident            = "aegis.dev/incident"
	LabelSourceNamespace     = "aegis.dev/source-namespace"
	LabelPriority            = "aegis.dev/priority"

	component     = "aegis-responder"
	logTailLines  = 500
	maxLogBytes   = 256 << 10
	handledMemory = time.Hour
)

// Decision is the outcome of handling one alert.
type Decision string

// Possible decisions.
const (
	DecisionContained Decision = "contained" // pod isolated (and evidence taken)
	DecisionRecorded  Decision = "recorded"  // Event recorded, no containment
	DecisionNotified  Decision = "notified"  // dry run: would have contained
	DecisionDuplicate Decision = "duplicate" // pod is already contained
	DecisionIgnored   Decision = "ignored"   // not in scope of the playbook
	DecisionRejected  Decision = "rejected"  // alert does not match the live pod
	DecisionFailed    Decision = "failed"    // containment could not be applied
)

// Responder executes the playbook against the cluster.
type Responder struct {
	playbook *Playbook
	kube     Cluster
	log      *slog.Logger
	metrics  *Metrics
	now      func() time.Time

	mu      sync.Mutex
	handled map[string]time.Time // namespace/pod -> containment time
}

// New returns a Responder.
func New(pb *Playbook, kube Cluster, metrics *Metrics, log *slog.Logger) *Responder {
	metrics.Initialize(pb)
	return &Responder{
		playbook: pb,
		kube:     kube,
		log:      log,
		metrics:  metrics,
		now:      time.Now,
		handled:  make(map[string]time.Time),
	}
}

// Handle runs the playbook for one Falco alert.
func (r *Responder) Handle(ctx context.Context, ev Event) Decision {
	rule := r.playbook.Decide(ev)
	ruleName := "none"
	if rule != nil {
		ruleName = rule.Name
	}
	decision := r.handle(ctx, ev, rule)
	r.metrics.events.WithLabelValues(string(decision), ruleName).Inc()
	r.log.Info("falco alert handled",
		"decision", decision, "falco_rule", ev.Rule, "playbook_rule", ruleName,
		"priority", ev.Priority.String(), "namespace", ev.Namespace(), "pod", ev.Pod())
	return decision
}

func (r *Responder) handle(ctx context.Context, ev Event, rule *Rule) Decision {
	ns, name := ev.Namespace(), ev.Pod()
	if rule == nil || ns == "" || name == "" || !r.playbook.Protects(ns) {
		return DecisionIgnored
	}
	key := ns + "/" + name
	if rule.Contains(ActionQuarantine) && r.alreadyHandled(key) {
		return DecisionDuplicate
	}

	pod, err := r.kube.GetPod(ctx, ns, name)
	if errors.Is(err, ErrNotFound) {
		return DecisionIgnored
	}
	if err != nil {
		r.log.Error("get pod", "namespace", ns, "pod", name, "error", err)
		return DecisionFailed
	}
	// The alert names a pod; make sure it is the pod that raised it and not a
	// newer pod that reused the name after the original was replaced.
	if id := ev.ContainerID(); id != "" && !pod.RunsContainer(id) {
		return DecisionRejected
	}

	if !rule.Contains(ActionQuarantine) {
		err := r.event(ctx, pod, "Warning", "SuspiciousActivity",
			fmt.Sprintf("Falco rule %q matched playbook rule %q (record only)", ev.Rule, rule.Name))
		r.metrics.action(ActionRecord, err)
		return DecisionRecorded
	}
	if pod.Metadata.Labels[LabelQuarantine] == "true" {
		r.markHandled(key)
		return DecisionDuplicate
	}
	if r.playbook.ModeOf(rule) == ModeNotify {
		return r.notify(ctx, ev, rule, pod, key)
	}
	return r.contain(ctx, ev, rule, pod, key)
}

// notify is the dry run of contain: it reports exactly what would have
// happened, once per pod, and changes nothing.
func (r *Responder) notify(ctx context.Context, ev Event, rule *Rule, pod *Pod, key string) Decision {
	r.markHandled(key)
	err := r.event(ctx, pod, "Warning", "WouldQuarantine",
		fmt.Sprintf("Notify-only: Falco rule %q matched playbook rule %q, which would have run %v. No action taken.",
			ev.Rule, rule.Name, rule.Actions))
	r.metrics.action(ActionRecord, err)
	r.log.Warn("containment skipped (notify-only)",
		"namespace", pod.Metadata.Namespace, "pod", pod.Metadata.Name,
		"falco_rule", ev.Rule, "playbook_rule", rule.Name)
	return DecisionNotified
}

// contain isolates the pod first, because that is what stops the attacker,
// and only then spends time on evidence.
func (r *Responder) contain(ctx context.Context, ev Event, rule *Rule, pod *Pod, key string) Decision {
	incident := newIncidentID(r.now())
	err := r.quarantine(ctx, ev, rule, pod, incident, r.now().UTC())
	r.metrics.action(ActionQuarantine, err)
	if err != nil {
		r.log.Error("quarantine failed", "namespace", pod.Metadata.Namespace, "pod", pod.Metadata.Name, "error", err)
		return DecisionFailed
	}
	// Measured once the API server has accepted the patch: from here on the
	// NetworkPolicy applies to the pod.
	quarantinedAt := r.now().UTC()
	r.markHandled(key)
	containment := quarantinedAt.Sub(ev.Time)
	if containment >= 0 {
		r.metrics.containment.Observe(containment.Seconds())
	}
	r.log.Warn("pod quarantined",
		"incident", incident, "namespace", pod.Metadata.Namespace, "pod", pod.Metadata.Name,
		"falco_rule", ev.Rule, "containment_seconds", containment.Seconds())

	evidenceRef := "not collected"
	if rule.Contains(ActionEvidence) {
		cm, err := r.collectEvidence(ctx, ev, rule, pod, incident, quarantinedAt)
		r.metrics.action(ActionEvidence, err)
		if err != nil {
			r.log.Error("evidence collection failed", "incident", incident, "error", err)
		} else {
			evidenceRef = "configmap " + r.playbook.EvidenceNamespace + "/" + cm
		}
	}

	msg := fmt.Sprintf("Incident %s: Falco rule %q matched playbook rule %q. Pod isolated from the network and detached from its controller; evidence: %s.",
		incident, ev.Rule, rule.Name, evidenceRef)
	if rule.Contains(ActionTerminate) {
		msg += fmt.Sprintf(" Terminating after a %s forensic hold.", r.playbook.Hold())
	}
	if err := r.event(ctx, pod, "Warning", "Quarantined", msg); err != nil {
		r.log.Error("record event", "incident", incident, "error", err)
	}
	return DecisionContained
}

func (r *Responder) quarantine(ctx context.Context, ev Event, rule *Rule, pod *Pod, incident string, at time.Time) error {
	original, err := json.Marshal(pod.Metadata.Labels)
	if err != nil {
		return err
	}
	labels := map[string]*string{LabelQuarantine: ptr("true")}
	// Removing the labels the ReplicaSet selects on releases the pod: the
	// controller starts a clean replacement and the Service stops routing to
	// it, while the isolated original stays around for forensics.
	if owner := pod.Controller(); owner != nil && owner.Kind == "ReplicaSet" {
		selector, err := r.kube.ReplicaSetSelector(ctx, pod.Metadata.Namespace, owner.Name)
		if err != nil {
			r.log.Error("read replicaset selector; isolating without detaching", "error", err)
		}
		for k := range selector {
			labels[k] = nil
		}
	}
	annotations := map[string]string{
		AnnotationIncident:       incident,
		AnnotationRule:           ev.Rule,
		AnnotationQuarantinedAt:  at.Format(time.RFC3339Nano),
		AnnotationOriginalLabels: string(original),
	}
	if rule.Contains(ActionTerminate) {
		annotations[AnnotationTerminateAfter] = at.Add(r.playbook.Hold()).Format(time.RFC3339)
	}
	patch := map[string]any{"metadata": map[string]any{
		"uid":         pod.Metadata.UID, // precondition: never patch a different pod
		"labels":      labels,
		"annotations": annotations,
	}}
	return r.kube.PatchPod(ctx, pod.Metadata.Namespace, pod.Metadata.Name, patch)
}

// collectEvidence stores everything an investigator needs in an immutable
// ConfigMap: the alert, the full pod object and recent container logs.
func (r *Responder) collectEvidence(ctx context.Context, ev Event, rule *Rule, pod *Pod, incident string, quarantinedAt time.Time) (string, error) {
	data := map[string]string{
		"falco-alert.json": string(ev.Raw),
		"pod.json":         string(pod.Raw),
	}
	budget := maxLogBytes
	for _, c := range pod.Spec.Containers {
		logs, err := r.kube.PodLogs(ctx, pod.Metadata.Namespace, pod.Metadata.Name, c.Name, logTailLines)
		if err != nil {
			logs = "log collection failed: " + err.Error()
		}
		if len(logs) > budget {
			logs = logs[len(logs)-budget:]
		}
		budget -= len(logs)
		data["logs-"+c.Name+".txt"] = logs
	}

	images := make([]string, 0, len(pod.Spec.Containers))
	for _, c := range pod.Spec.Containers {
		images = append(images, c.Image)
	}
	summary := map[string]any{
		"incident":         incident,
		"falcoRule":        ev.Rule,
		"priority":         ev.Priority.String(),
		"playbookRule":     rule.Name,
		"actions":          rule.Actions,
		"namespace":        pod.Metadata.Namespace,
		"pod":              pod.Metadata.Name,
		"podUID":           pod.Metadata.UID,
		"node":             pod.Spec.NodeName,
		"images":           images,
		"detectedAt":       ev.Time.UTC().Format(time.RFC3339Nano),
		"quarantinedAt":    quarantinedAt.Format(time.RFC3339Nano),
		"containmentSec":   quarantinedAt.Sub(ev.Time).Seconds(),
		"evidenceTakenAt":  r.now().UTC().Format(time.RFC3339Nano),
		"originalLabels":   pod.Metadata.Labels,
		"falcoOutput":      ev.Output,
		"falcoTags":        ev.Tags,
		"falcoHostname":    ev.Hostname,
		"terminationAfter": "",
	}
	if rule.Contains(ActionTerminate) {
		summary["terminationAfter"] = quarantinedAt.Add(r.playbook.Hold()).Format(time.RFC3339)
	}
	b, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return "", err
	}
	data["incident.json"] = string(b)

	name := "incident-" + incident
	cm := &ConfigMap{
		Metadata: ObjectMeta{
			Name:      name,
			Namespace: r.playbook.EvidenceNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": component,
				LabelIncident:                  incident,
				LabelSourceNamespace:           pod.Metadata.Namespace,
				LabelPriority:                  ev.Priority.String(),
			},
			Annotations: map[string]string{
				"aegis.dev/pod":        pod.Metadata.Name,
				"aegis.dev/falco-rule": ev.Rule,
			},
		},
		// Evidence must not be edited after the fact.
		Immutable: true,
		Data:      data,
	}
	return name, r.kube.CreateConfigMap(ctx, cm)
}

// Reconcile terminates quarantined pods whose forensic hold has expired and
// refreshes the quarantine gauge. It is stateless, so a restarted responder
// picks up where the previous one left off.
func (r *Responder) Reconcile(ctx context.Context) {
	now := r.now()
	remaining := 0
	for _, ns := range r.playbook.Namespaces {
		pods, err := r.kube.ListPods(ctx, ns, LabelQuarantine+"=true")
		if err != nil {
			r.log.Error("list quarantined pods", "namespace", ns, "error", err)
			continue
		}
		for _, pod := range pods {
			deadline, err := time.Parse(time.RFC3339, pod.Metadata.Annotations[AnnotationTerminateAfter])
			if err != nil || now.Before(deadline) {
				remaining++ // no termination scheduled, or still on hold
				continue
			}
			err = r.kube.DeletePod(ctx, ns, pod.Metadata.Name, pod.Metadata.UID)
			if errors.Is(err, ErrNotFound) {
				continue
			}
			r.metrics.action(ActionTerminate, err)
			if err != nil {
				remaining++
				r.log.Error("terminate quarantined pod", "namespace", ns, "pod", pod.Metadata.Name, "error", err)
				continue
			}
			r.log.Warn("quarantined pod terminated",
				"incident", pod.Metadata.Annotations[AnnotationIncident], "namespace", ns, "pod", pod.Metadata.Name)
		}
	}
	r.metrics.quarantined.Set(float64(remaining))

	r.mu.Lock()
	for k, t := range r.handled {
		if now.Sub(t) > handledMemory {
			delete(r.handled, k)
		}
	}
	r.mu.Unlock()
}

// Run reconciles on a fixed interval until the context ends.
func (r *Responder) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		r.Reconcile(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (r *Responder) event(ctx context.Context, pod *Pod, typ, reason, message string) error {
	now := r.now().UTC()
	return r.kube.CreateEvent(ctx, &KubeEvent{
		Metadata: ObjectMeta{GenerateName: pod.Metadata.Name + ".", Namespace: pod.Metadata.Namespace},
		InvolvedObject: ObjectReference{
			APIVersion: "v1", Kind: "Pod",
			Namespace: pod.Metadata.Namespace, Name: pod.Metadata.Name, UID: pod.Metadata.UID,
		},
		Reason:         reason,
		Message:        message,
		Type:           typ,
		Source:         EventSource{Component: component},
		FirstTimestamp: now,
		LastTimestamp:  now,
		Count:          1,
	})
}

func (r *Responder) alreadyHandled(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.handled[key]
	return ok
}

func (r *Responder) markHandled(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handled[key] = r.now()
}

// newIncidentID returns a sortable, unique, DNS-safe incident identifier.
func newIncidentID(t time.Time) string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return strings.ToLower(t.UTC().Format("20060102-150405")) + "-" + hex.EncodeToString(b)
}

func ptr[T any](v T) *T { return &v }
