// Package ledger holds the domain model of the demo workload: an in-memory
// store of payment transactions with strict input validation.
package ledger

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// MaxAmount is the largest accepted amount in minor units (1,000,000.00).
	MaxAmount int64 = 100_000_000
	// MaxDescription is the maximum description length in characters.
	MaxDescription = 140
	// DefaultCapacity bounds the store so a client cannot exhaust memory.
	DefaultCapacity = 10_000
)

var (
	// ErrNotFound is returned when a transaction ID does not exist.
	ErrNotFound = errors.New("transaction not found")
	// ErrFull is returned when the store reached its capacity.
	ErrFull = errors.New("ledger is full")

	idPattern = regexp.MustCompile(`^txn_[0-9a-f]{32}$`)

	currencies = map[string]bool{
		"AED": true, "EGP": true, "EUR": true, "GBP": true, "SAR": true, "USD": true,
	}
)

// Transaction is a stored ledger entry.
type Transaction struct {
	ID          string    `json:"id"`
	Amount      int64     `json:"amount"`
	Currency    string    `json:"currency"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

// NewTransaction is the client payload for creating a transaction.
type NewTransaction struct {
	Amount      int64  `json:"amount"`
	Currency    string `json:"currency"`
	Description string `json:"description"`
}

// ValidationError describes which field was rejected and why.
type ValidationError struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Reason)
}

// Validate checks the payload against an allowlist-style schema.
func (n NewTransaction) Validate() error {
	if n.Amount <= 0 || n.Amount > MaxAmount {
		return &ValidationError{Field: "amount", Reason: fmt.Sprintf("must be between 1 and %d minor units", MaxAmount)}
	}
	if !currencies[n.Currency] {
		return &ValidationError{Field: "currency", Reason: "must be one of AED, EGP, EUR, GBP, SAR, USD"}
	}
	if !utf8.ValidString(n.Description) {
		return &ValidationError{Field: "description", Reason: "must be valid UTF-8"}
	}
	if strings.TrimSpace(n.Description) == "" {
		return &ValidationError{Field: "description", Reason: "must not be empty"}
	}
	if utf8.RuneCountInString(n.Description) > MaxDescription {
		return &ValidationError{Field: "description", Reason: fmt.Sprintf("must be at most %d characters", MaxDescription)}
	}
	for _, r := range n.Description {
		if unicode.IsControl(r) {
			return &ValidationError{Field: "description", Reason: "must not contain control characters"}
		}
	}
	return nil
}

// ValidID reports whether id has the shape of a transaction ID.
func ValidID(id string) bool {
	return idPattern.MatchString(id)
}

// Store is a concurrency-safe, bounded, in-memory transaction store.
type Store struct {
	mu       sync.RWMutex
	items    map[string]Transaction
	capacity int
	now      func() time.Time
}

// NewStore returns an empty store that holds at most capacity transactions.
func NewStore(capacity int) *Store {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	return &Store{
		items:    make(map[string]Transaction),
		capacity: capacity,
		now:      func() time.Time { return time.Now().UTC() },
	}
}

// Create validates n and stores it as a new transaction.
func (s *Store) Create(n NewTransaction) (Transaction, error) {
	if err := n.Validate(); err != nil {
		return Transaction{}, err
	}
	id, err := newID()
	if err != nil {
		return Transaction{}, fmt.Errorf("generate id: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.items) >= s.capacity {
		return Transaction{}, ErrFull
	}
	t := Transaction{
		ID:          id,
		Amount:      n.Amount,
		Currency:    n.Currency,
		Description: strings.TrimSpace(n.Description),
		CreatedAt:   s.now(),
	}
	s.items[id] = t
	return t, nil
}

// Get returns the transaction with the given ID.
func (s *Store) Get(id string) (Transaction, error) {
	if !ValidID(id) {
		return Transaction{}, ErrNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.items[id]
	if !ok {
		return Transaction{}, ErrNotFound
	}
	return t, nil
}

// List returns up to limit transactions, newest first.
func (s *Store) List(limit int) []Transaction {
	s.mu.RLock()
	out := make([]Transaction, 0, len(s.items))
	for _, t := range s.items {
		out = append(out, t)
	}
	s.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Len returns the number of stored transactions.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.items)
}

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "txn_" + hex.EncodeToString(b), nil
}
