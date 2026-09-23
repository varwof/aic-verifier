// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	pki "github.com/varwof/types"
)

// TimeRange bounds a query window.  Zero values are unbounded on that end.
type TimeRange struct {
	Start time.Time `json:"start,omitempty"`
	End   time.Time `json:"end,omitempty"`
}

// SignedSupervisionEvent is a supervision event with an optional RFC 3161 TSA
// timestamp attestation, mirroring SignedAuditEntry.
type SignedSupervisionEvent struct {
	Event pki.SupervisionEvent `json:"event"`
	TST   string               `json:"tst,omitempty"`
}

// SupervisionQuery filters supervision events read from the store.  Empty
// fields are ignored.  Type filters on a specific SupervisionEventType.
type SupervisionQuery struct {
	OperationID string
	DaHash      string
	AgentID     string
	Type        pki.SupervisionEventType
	TimeRange   *TimeRange
	Limit       int
}

// SupervisionStore is the append-only supervision event store: JSON Lines with
// the same durability rules as the audit chain (audit.go).  Critical events
// are written synchronously and can be TSA-attested.  A nil store disables
// event persistence; the decision path stays fail-closed regardless.
type SupervisionStore struct {
	file   string
	w      *RotatingFile
	tsa    *TSAClient
	mu     sync.Mutex
	closed bool
}

// NewSupervisionStore creates an append-only event store at file.  When file
// is empty it returns a nil store (no persistence).  tsa, when non-nil, signs
// every recorded event with a timestamp token.
func NewSupervisionStore(file string, tsa *TSAClient, maxSize int64, maxBak int) (*SupervisionStore, error) {
	if file == "" {
		return nil, nil
	}
	w, err := NewRotatingFile(file, maxSize, maxBak)
	if err != nil {
		return nil, err
	}
	return &SupervisionStore{file: file, w: w, tsa: tsa}, nil
}

// File returns the store file path (empty for a nil store).
func (s *SupervisionStore) File() string {
	if s == nil {
		return ""
	}
	return s.file
}

// Record validates and synchronously appends a supervision event.  TSA
// attestation is best-effort: a signing failure records the event unsigned and
// returns the underlying TSA error only if the write itself also failed.
func (s *SupervisionStore) Record(ev *pki.SupervisionEvent) error {
	if s == nil {
		return fmt.Errorf("supervision_store: nil store")
	}
	if s.closed {
		return fmt.Errorf("supervision_store: closed")
	}
	if err := pki.ValidateSupervisionEvent(ev); err != nil {
		return err
	}

	signed := SignedSupervisionEvent{Event: *ev}
	if s.tsa != nil {
		evJSON, _ := json.Marshal(ev)
		tst, err := s.tsa.Sign(evJSON)
		if err == nil {
			signed.TST = EncodeBase64(tst)
		} else {
			// L2: a TSA attestation failure previously recorded the event
			// unsigned in silence, so operators would never notice the
			// supervision chain had lost its tamper-evidence coverage.
			fmt.Printf("supervision_store: WARNING TSA signing failed for operation %q (event recorded unsigned): %v\n", ev.OperationID, err)
		}
	}
	data, err := json.Marshal(signed)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.w.Write(data); err != nil {
		return fmt.Errorf("supervision_store: write: %w", err)
	}
	return nil
}

// Close closes the store file.  Further Record calls fail.  It is idempotent:
// a second Close returns nil instead of re-closing the file (which would return
// "file already closed" and make Config.Close non-idempotent).
func (s *SupervisionStore) Close() error {
	if s == nil || s.w == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.w.Close()
}

// Query reads supervision events from the store in append order and filters
// them.  Events are returned newest-correlation-friendly in file order; an
// empty result is a non-nil empty slice.  A nil store returns an error.
func (s *SupervisionStore) Query(filter SupervisionQuery) ([]pki.SupervisionEvent, error) {
	if s == nil {
		return nil, fmt.Errorf("supervision_store: nil store")
	}
	if s.file == "" {
		return nil, fmt.Errorf("supervision_store: no file configured")
	}
	// H5: snapshot the current file path under the mutex, then read it after
	// releasing the lock so a concurrent rotation/close does not corrupt the
	// read (and Query never blocks Record on the write path).
	s.mu.Lock()
	file := s.file
	s.mu.Unlock()
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []pki.SupervisionEvent
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var signed SignedSupervisionEvent
		if err := json.Unmarshal([]byte(line), &signed); err != nil {
			continue
		}
		ev := signed.Event
		if !matchesSupervisionQuery(ev, filter) {
			continue
		}
		out = append(out, ev)
		if filter.Limit > 0 && len(out) >= filter.Limit {
			break
		}
	}
	if out == nil {
		out = make([]pki.SupervisionEvent, 0)
	}
	return out, scanner.Err()
}

func matchesSupervisionQuery(ev pki.SupervisionEvent, f SupervisionQuery) bool {
	if f.OperationID != "" && ev.OperationID != f.OperationID {
		return false
	}
	if f.DaHash != "" && ev.DaHash != f.DaHash {
		return false
	}
	if f.AgentID != "" && ev.AgentID != f.AgentID {
		return false
	}
	if f.Type != "" && ev.Type != f.Type {
		return false
	}
	if f.TimeRange != nil {
		if !f.TimeRange.Start.IsZero() && ev.Ts.Before(f.TimeRange.Start) {
			return false
		}
		if !f.TimeRange.End.IsZero() && ev.Ts.After(f.TimeRange.End) {
			return false
		}
	}
	return true
}
