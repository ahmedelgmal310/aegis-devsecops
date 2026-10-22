package ledger

import (
	"testing"
	"unicode/utf8"
)

// FuzzValidate checks that validation never panics and that every payload it
// accepts respects the documented invariants.
func FuzzValidate(f *testing.F) {
	f.Add(int64(1250), "EGP", "Invoice 1042")
	f.Add(int64(0), "USD", "")
	f.Add(int64(-1), "egp", "\x00\xff")
	f.Add(MaxAmount, "EUR", "<script>alert(1)</script>")
	f.Add(int64(42), "SAR", "'; DROP TABLE transactions; --")

	f.Fuzz(func(t *testing.T, amount int64, currency, description string) {
		n := NewTransaction{Amount: amount, Currency: currency, Description: description}
		if err := n.Validate(); err != nil {
			return
		}
		if amount <= 0 || amount > MaxAmount {
			t.Fatalf("accepted out-of-range amount %d", amount)
		}
		if !currencies[currency] {
			t.Fatalf("accepted unknown currency %q", currency)
		}
		if !utf8.ValidString(description) || utf8.RuneCountInString(description) > MaxDescription {
			t.Fatalf("accepted invalid description %q", description)
		}
	})
}
