// Package responder turns Falco runtime alerts into automated incident
// response: it isolates the affected pod, preserves forensic evidence and
// lets the workload controller replace it with a clean copy.
package responder

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Priority mirrors Falco's alert priorities, ordered by severity.
type Priority int

// Falco priorities, lowest to highest.
const (
	PriorityDebug Priority = iota
	PriorityInformational
	PriorityNotice
	PriorityWarning
	PriorityError
	PriorityCritical
	PriorityAlert
	PriorityEmergency
)

var priorityNames = []string{"debug", "informational", "notice", "warning", "error", "critical", "alert", "emergency"}

// ParsePriority accepts Falco's spelling in any case ("Warning", "CRITICAL").
func ParsePriority(s string) (Priority, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "info" {
		return PriorityInformational, nil
	}
	for i, name := range priorityNames {
		if s == name {
			return Priority(i), nil
		}
	}
	return 0, fmt.Errorf("unknown priority %q", s)
}

func (p Priority) String() string {
	if p < 0 || int(p) >= len(priorityNames) {
		return "unknown"
	}
	return priorityNames[p]
}

// UnmarshalJSON lets playbooks and events carry priorities as strings.
func (p *Priority) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	parsed, err := ParsePriority(s)
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}

// Event is the subset of a Falco JSON alert (http_output) that drives a
// response. Raw keeps the original payload for the evidence bundle.
type Event struct {
	UUID         string         `json:"uuid"`
	Rule         string         `json:"rule"`
	Priority     Priority       `json:"priority"`
	Time         time.Time      `json:"time"`
	Output       string         `json:"output"`
	Tags         []string       `json:"tags"`
	Hostname     string         `json:"hostname"`
	OutputFields map[string]any `json:"output_fields"`

	Raw json.RawMessage `json:"-"`
}

// ParseEvent decodes and validates one Falco alert.
func ParseEvent(b []byte) (Event, error) {
	var ev Event
	if err := json.Unmarshal(b, &ev); err != nil {
		return Event{}, fmt.Errorf("decode falco event: %w", err)
	}
	if ev.Rule == "" {
		return Event{}, errors.New("falco event has no rule")
	}
	if ev.Time.IsZero() {
		return Event{}, errors.New("falco event has no time")
	}
	ev.Raw = append(json.RawMessage(nil), b...)
	return ev, nil
}

// Namespace and Pod identify the workload the alert is about. They are empty
// for host-level alerts, which the responder never acts on.
func (e Event) Namespace() string   { return e.field("k8s.ns.name") }
func (e Event) Pod() string         { return e.field("k8s.pod.name") }
func (e Event) ContainerID() string { return e.field("container.id") }

func (e Event) field(key string) string {
	v, ok := e.OutputFields[key].(string)
	if !ok || v == "<NA>" {
		return ""
	}
	return v
}

// HasTag reports whether the Falco rule carries the given tag.
func (e Event) HasTag(tag string) bool {
	for _, t := range e.Tags {
		if t == tag {
			return true
		}
	}
	return false
}
