package responder

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// Action is one step of a response.
type Action string

// Supported actions. Quarantine always runs first because it is the step
// that stops the attacker; evidence and termination follow.
const (
	// ActionRecord emits a Kubernetes Event on the pod and nothing else.
	ActionRecord Action = "record"
	// ActionQuarantine cuts the pod off the network and detaches it from its
	// controller, so a clean replacement takes over its traffic.
	ActionQuarantine Action = "quarantine"
	// ActionEvidence stores the alert, pod spec and logs in an immutable
	// ConfigMap before anything is deleted.
	ActionEvidence Action = "evidence"
	// ActionTerminate deletes the quarantined pod after the forensic hold.
	ActionTerminate Action = "terminate"
)

// Mode decides whether a containing rule acts or only reports.
type Mode string

// Rule modes.
const (
	// ModeEnforce runs the rule's actions. It is the default.
	ModeEnforce Mode = "enforce"
	// ModeNotify is a dry run: the responder records what it would have done
	// (a WouldQuarantine Event and a metric) but leaves the pod untouched.
	// New rules start here until they have proven they do not fire on
	// legitimate behaviour.
	ModeNotify Mode = "notify"
)

// Match selects the alerts a response rule applies to. Every field that is
// set must match.
type Match struct {
	Rules       []string  `json:"rules,omitempty"`
	MinPriority *Priority `json:"minPriority,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
}

// Rule maps matching alerts to a list of actions.
type Rule struct {
	Name    string   `json:"name"`
	Match   Match    `json:"match"`
	Actions []Action `json:"actions"`
	// Mode is enforce (default) or notify.
	Mode Mode `json:"mode,omitempty"`
}

// Playbook is the responder's configuration: where it may act and how.
type Playbook struct {
	// Namespaces the responder is allowed to act in. Alerts from anywhere
	// else are ignored, whatever their priority.
	Namespaces []string `json:"namespaces"`
	// EvidenceNamespace receives one immutable ConfigMap per incident.
	EvidenceNamespace string `json:"evidenceNamespace"`
	// QuarantineHoldSeconds keeps an isolated pod alive for live forensics
	// before it is terminated.
	QuarantineHoldSeconds int `json:"quarantineHoldSeconds"`
	// Rules are evaluated in order; the first match wins.
	Rules []Rule `json:"rules"`

	// NotifyOnly turns every rule into a dry run, whatever its own mode. It
	// is set from RESPONDER_MODE=notify, a single switch to roll the
	// responder out to a new cluster without it touching any pod.
	NotifyOnly bool `json:"-"`
}

// LoadPlaybook reads and validates a JSON playbook.
func LoadPlaybook(path string) (*Playbook, error) {
	b, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- operator-controlled path from the pod spec
	if err != nil {
		return nil, fmt.Errorf("read playbook: %w", err)
	}
	var pb Playbook
	if err := json.Unmarshal(b, &pb); err != nil {
		return nil, fmt.Errorf("decode playbook: %w", err)
	}
	if err := pb.Validate(); err != nil {
		return nil, err
	}
	return &pb, nil
}

// Validate rejects playbooks that could not be executed safely.
func (pb *Playbook) Validate() error {
	if len(pb.Namespaces) == 0 {
		return errors.New("playbook: at least one namespace is required")
	}
	if pb.EvidenceNamespace == "" {
		return errors.New("playbook: evidenceNamespace is required")
	}
	if slices.Contains(pb.Namespaces, pb.EvidenceNamespace) {
		return errors.New("playbook: the evidence namespace must not be a protected namespace")
	}
	if pb.QuarantineHoldSeconds < 0 {
		return errors.New("playbook: quarantineHoldSeconds must not be negative")
	}
	if len(pb.Rules) == 0 {
		return errors.New("playbook: at least one rule is required")
	}
	for i, r := range pb.Rules {
		if r.Name == "" {
			return fmt.Errorf("playbook: rule %d has no name", i)
		}
		if len(r.Match.Rules) == 0 && r.Match.MinPriority == nil && len(r.Match.Tags) == 0 {
			return fmt.Errorf("playbook: rule %q matches everything; set rules, minPriority or tags", r.Name)
		}
		if len(r.Actions) == 0 {
			return fmt.Errorf("playbook: rule %q has no actions", r.Name)
		}
		switch r.Mode {
		case "", ModeEnforce, ModeNotify:
		default:
			return fmt.Errorf("playbook: rule %q has unknown mode %q (use enforce or notify)", r.Name, r.Mode)
		}
		for _, a := range r.Actions {
			switch a {
			case ActionRecord, ActionQuarantine, ActionEvidence, ActionTerminate:
			default:
				return fmt.Errorf("playbook: rule %q has unknown action %q", r.Name, a)
			}
		}
		// Deleting a pod that was never isolated would destroy the evidence
		// and let the attacker keep the network until the very last moment.
		if slices.Contains(r.Actions, ActionTerminate) && !slices.Contains(r.Actions, ActionQuarantine) {
			return fmt.Errorf("playbook: rule %q terminates without quarantining first", r.Name)
		}
	}
	return nil
}

// Hold is the forensic hold as a duration.
func (pb *Playbook) Hold() time.Duration {
	return time.Duration(pb.QuarantineHoldSeconds) * time.Second
}

// Protects reports whether the responder may act in the namespace.
func (pb *Playbook) Protects(namespace string) bool {
	return slices.Contains(pb.Namespaces, namespace)
}

// Decide returns the first rule matching the event, or nil.
func (pb *Playbook) Decide(ev Event) *Rule {
	for i := range pb.Rules {
		if pb.Rules[i].Match.matches(ev) {
			return &pb.Rules[i]
		}
	}
	return nil
}

// ModeOf returns the mode a rule effectively runs in.
func (pb *Playbook) ModeOf(r *Rule) Mode {
	if pb.NotifyOnly || r.Mode == ModeNotify {
		return ModeNotify
	}
	return ModeEnforce
}

// Contains reports whether the rule runs the action.
func (r *Rule) Contains(a Action) bool {
	return slices.Contains(r.Actions, a)
}

func (m Match) matches(ev Event) bool {
	if len(m.Rules) > 0 && !slices.Contains(m.Rules, ev.Rule) {
		return false
	}
	if m.MinPriority != nil && ev.Priority < *m.MinPriority {
		return false
	}
	for _, t := range m.Tags {
		if !ev.HasTag(t) {
			return false
		}
	}
	return true
}
