package ledger

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func valid() NewTransaction {
	return NewTransaction{Amount: 1250, Currency: "EGP", Description: "Invoice 1042"}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name  string
		mod   func(*NewTransaction)
		field string
	}{
		{"valid", func(*NewTransaction) {}, ""},
		{"zero amount", func(n *NewTransaction) { n.Amount = 0 }, "amount"},
		{"negative amount", func(n *NewTransaction) { n.Amount = -5 }, "amount"},
		{"amount over max", func(n *NewTransaction) { n.Amount = MaxAmount + 1 }, "amount"},
		{"max amount", func(n *NewTransaction) { n.Amount = MaxAmount }, ""},
		{"unknown currency", func(n *NewTransaction) { n.Currency = "BTC" }, "currency"},
		{"lowercase currency", func(n *NewTransaction) { n.Currency = "egp" }, "currency"},
		{"empty description", func(n *NewTransaction) { n.Description = "   " }, "description"},
		{"long description", func(n *NewTransaction) { n.Description = strings.Repeat("a", MaxDescription+1) }, "description"},
		{"max description", func(n *NewTransaction) { n.Description = strings.Repeat("ب", MaxDescription) }, ""},
		{"control character", func(n *NewTransaction) { n.Description = "line\nbreak" }, "description"},
		{"invalid utf8", func(n *NewTransaction) { n.Description = "bad \xff byte" }, "description"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n := valid()
			tc.mod(&n)
			err := n.Validate()
			if tc.field == "" {
				if err != nil {
					t.Fatalf("expected valid payload, got %v", err)
				}
				return
			}
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("expected ValidationError, got %v", err)
			}
			if ve.Field != tc.field {
				t.Fatalf("expected field %q, got %q", tc.field, ve.Field)
			}
		})
	}
}

func TestStoreCreateGetList(t *testing.T) {
	s := NewStore(10)
	base := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	tick := 0
	s.now = func() time.Time { tick++; return base.Add(time.Duration(tick) * time.Second) }

	first, err := s.Create(valid())
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Create(NewTransaction{Amount: 99, Currency: "USD", Description: "  Refund  "})
	if err != nil {
		t.Fatal(err)
	}
	if !ValidID(first.ID) || !ValidID(second.ID) {
		t.Fatalf("unexpected id format: %q %q", first.ID, second.ID)
	}
	if second.Description != "Refund" {
		t.Fatalf("description not trimmed: %q", second.Description)
	}

	got, err := s.Get(first.ID)
	if err != nil || got != first {
		t.Fatalf("Get returned %+v, %v", got, err)
	}

	list := s.List(0)
	if len(list) != 2 || list[0].ID != second.ID {
		t.Fatalf("expected newest first, got %+v", list)
	}
	if l := s.List(1); len(l) != 1 {
		t.Fatalf("limit not applied: %d", len(l))
	}
	if s.Len() != 2 {
		t.Fatalf("Len = %d", s.Len())
	}
}

func TestStoreRejectsInvalid(t *testing.T) {
	s := NewStore(10)
	if _, err := s.Create(NewTransaction{Amount: 1, Currency: "XXX", Description: "x"}); err == nil {
		t.Fatal("expected validation error")
	}
	if s.Len() != 0 {
		t.Fatal("invalid transaction was stored")
	}
}

func TestStoreGetUnknown(t *testing.T) {
	s := NewStore(10)
	for _, id := range []string{"", "txn_123", "../etc/passwd", "txn_" + strings.Repeat("0", 32)} {
		if _, err := s.Get(id); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Get(%q) = %v, want ErrNotFound", id, err)
		}
	}
}

func TestStoreCapacity(t *testing.T) {
	s := NewStore(2)
	for i := 0; i < 2; i++ {
		if _, err := s.Create(valid()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Create(valid()); !errors.Is(err, ErrFull) {
		t.Fatalf("expected ErrFull, got %v", err)
	}
}

func TestNewStoreDefaultCapacity(t *testing.T) {
	if s := NewStore(0); s.capacity != DefaultCapacity {
		t.Fatalf("capacity = %d", s.capacity)
	}
}

func TestStoreConcurrentAccess(t *testing.T) {
	s := NewStore(1000)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, err := s.Create(valid()); err != nil {
				t.Error(err)
			}
		}()
		go func() {
			defer wg.Done()
			_ = s.List(10)
		}()
	}
	wg.Wait()
	if s.Len() != 50 {
		t.Fatalf("Len = %d, want 50", s.Len())
	}
}

func TestValidationErrorMessage(t *testing.T) {
	err := (&ValidationError{Field: "amount", Reason: "too big"}).Error()
	if err != "amount: too big" {
		t.Fatalf("got %q", err)
	}
}
