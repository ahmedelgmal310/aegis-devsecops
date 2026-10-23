package responder

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestShippedPlaybook(t *testing.T) {
	pb, err := LoadPlaybook(shippedPlaybook)
	if err != nil {
		t.Fatal(err)
	}
	if !pb.Protects("aegis") || pb.Protects("kube-system") || pb.Protects("aegis-response") {
		t.Errorf("namespace scope is wrong: %v", pb.Namespaces)
	}
	if pb.Hold() != 5*time.Minute {
		t.Errorf("hold = %s", pb.Hold())
	}
	cases := map[string]string{
		"Aegis Credential File Read":      "contain-credential-access",
		"Aegis Shell Spawned in Workload": "contain-interactive-shell",
		"Aegis Discovery Tool Executed":   "record-discovery",
	}
	for falcoRule, want := range cases {
		if r := pb.Decide(Event{Rule: falcoRule, Priority: PriorityNotice}); r == nil || r.Name != want {
			t.Errorf("%s -> %v, want %s", falcoRule, r, want)
		}
	}
	if r := pb.Decide(Event{Rule: "Some Rule", Priority: PriorityCritical}); r != nil {
		t.Errorf("critical alert without the container tag must not match, got %s", r.Name)
	}
	// High-confidence rules enforce; the broad catch-all only notifies.
	for name, want := range map[string]Mode{
		"contain-credential-access": ModeEnforce,
		"contain-interactive-shell": ModeEnforce,
		"contain-critical":          ModeNotify,
	} {
		for i := range pb.Rules {
			if pb.Rules[i].Name == name {
				if got := pb.ModeOf(&pb.Rules[i]); got != want {
					t.Errorf("%s mode = %s, want %s", name, got, want)
				}
			}
		}
	}
	pb.NotifyOnly = true
	if got := pb.ModeOf(&pb.Rules[0]); got != ModeNotify {
		t.Errorf("the global switch must force notify, got %s", got)
	}
}

func TestPlaybookValidation(t *testing.T) {
	valid := `"namespaces":["app"],"evidenceNamespace":"evidence","quarantineHoldSeconds":60`
	rule := `{"name":"r","match":{"rules":["X"]},"actions":["quarantine","terminate"]}`
	tests := map[string]string{
		"no namespaces":         `{"evidenceNamespace":"e","rules":[` + rule + `]}`,
		"no evidence namespace": `{"namespaces":["app"],"rules":[` + rule + `]}`,
		"evidence is protected": `{"namespaces":["app","e"],"evidenceNamespace":"e","rules":[` + rule + `]}`,
		"negative hold":         `{"namespaces":["app"],"evidenceNamespace":"e","quarantineHoldSeconds":-1,"rules":[` + rule + `]}`,
		"no rules":              `{` + valid + `,"rules":[]}`,
		"unnamed rule":          `{` + valid + `,"rules":[{"match":{"rules":["X"]},"actions":["record"]}]}`,
		"match everything":      `{` + valid + `,"rules":[{"name":"r","match":{},"actions":["record"]}]}`,
		"no actions":            `{` + valid + `,"rules":[{"name":"r","match":{"rules":["X"]},"actions":[]}]}`,
		"unknown action":        `{` + valid + `,"rules":[{"name":"r","match":{"rules":["X"]},"actions":["nuke"]}]}`,
		"terminate unisolated":  `{` + valid + `,"rules":[{"name":"r","match":{"rules":["X"]},"actions":["evidence","terminate"]}]}`,
		"bad priority":          `{` + valid + `,"rules":[{"name":"r","match":{"minPriority":"Huge"},"actions":["record"]}]}`,
		"unknown mode":          `{` + valid + `,"rules":[{"name":"r","match":{"rules":["X"]},"actions":["record"],"mode":"yolo"}]}`,
		"not json":              `{`,
	}
	dir := t.TempDir()
	for name, body := range tests {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPlaybook(path); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
	if _, err := LoadPlaybook(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("missing file must fail")
	}

	ok := filepath.Join(dir, "ok.json")
	if err := os.WriteFile(ok, []byte(`{`+valid+`,"rules":[`+rule+`]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPlaybook(ok); err != nil {
		t.Errorf("valid playbook rejected: %v", err)
	}
}

func TestMatchCombinesConditions(t *testing.T) {
	warning := PriorityWarning
	m := Match{Rules: []string{"A"}, MinPriority: &warning, Tags: []string{"container"}}
	cases := []struct {
		ev   Event
		want bool
	}{
		{Event{Rule: "A", Priority: PriorityError, Tags: []string{"container"}}, true},
		{Event{Rule: "B", Priority: PriorityError, Tags: []string{"container"}}, false},
		{Event{Rule: "A", Priority: PriorityNotice, Tags: []string{"container"}}, false},
		{Event{Rule: "A", Priority: PriorityError}, false},
	}
	for i, c := range cases {
		if got := m.matches(c.ev); got != c.want {
			t.Errorf("case %d: matches = %v, want %v", i, got, c.want)
		}
	}
}
