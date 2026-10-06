// Package session provides in-memory, TTL-bounded stores used during the biometric flow.
//
// LivenessStore holds FaceMaps (derived biometric templates) between the liveness and ID-scan
// steps. Entries expire after a configurable TTL (default 2 minutes) and are one-time-use.
// Nothing in this store is ever written to disk.
//
// OfferStore holds signed credential tokens between issuance and wallet redemption. Entries
// expire after a configurable TTL (default 5 minutes) and are one-time-use.
//
// The liveness proof store holds FaceTec Server's livenessProven verdict for a FaceTec 10
// process-request session, between the session's liveness step and its final photo ID match
// result, which arrive in separate requests. Entries expire after a configurable TTL (default
// 15 minutes, a whole session: face scan, both sides of the document and the chip read) and are
// one-time-use. They hold a boolean, no biometric data.
package session

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// LivenessEntry holds a FaceMap and liveness score between the liveness and id-scan steps.
// The FaceMap field is sensitive biometric data and must never be persisted.
type LivenessEntry struct {
	// FaceMap is the biometric template derived by the FaceTec Server; never log or persist.
	// Stored as []byte so the backing array can be zeroed with clear() after use.
	FaceMap       []byte
	LivenessScore float64
	ExpiresAt     time.Time
}

// OfferEntry holds signed credential tokens for wallet redemption.
type OfferEntry struct {
	Credentials []string
	Scope       string
	ExpiresAt   time.Time
}

// livenessProof is FaceTec Server's liveness verdict for one process-request session.
type livenessProof struct {
	proven    bool
	expiresAt time.Time
}

// Manager holds the in-memory stores with automatic TTL eviction.
type Manager struct {
	mu       sync.Mutex
	liveness map[string]*LivenessEntry
	offers   map[string]*OfferEntry
	proofs   map[string]*livenessProof
	livTTL   time.Duration
	offerTTL time.Duration
	proofTTL time.Duration
	done     chan struct{} // closed by Close() to stop the reaper goroutine
}

// New creates a Manager with the given TTLs.
// livTTL is the lifetime of a liveness session (FaceMap hold time).
// offerTTL is the lifetime of a credential offer after issuance.
// proofTTL is the lifetime of a process-request session's liveness verdict.
func New(livTTL, offerTTL, proofTTL time.Duration) *Manager {
	m := &Manager{
		liveness: make(map[string]*LivenessEntry),
		offers:   make(map[string]*OfferEntry),
		proofs:   make(map[string]*livenessProof),
		livTTL:   livTTL,
		offerTTL: offerTTL,
		proofTTL: proofTTL,
		done:     make(chan struct{}),
	}
	go m.reap()
	return m
}

// Close stops the background eviction goroutine and immediately zeros all
// in-memory biometric data. Must be called once when the Manager is no longer needed.
func (m *Manager) Close() {
	close(m.done)
}

// PutLiveness stores a FaceMap for the given liveness result and returns an opaque session ID.
// faceMap must be a []byte so the caller can later zero the backing array with clear().
func (m *Manager) PutLiveness(faceMap []byte, livenessScore float64) (string, error) {
	id, err := newID()
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	m.liveness[id] = &LivenessEntry{
		FaceMap:       faceMap,
		LivenessScore: livenessScore,
		ExpiresAt:     time.Now().Add(m.livTTL),
	}
	m.mu.Unlock()
	return id, nil
}

// TakeLiveness retrieves and atomically removes a liveness entry.
// Returns an error if the ID is unknown or the entry has expired.
func (m *Manager) TakeLiveness(id string) (*LivenessEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.liveness[id]
	if !ok {
		return nil, fmt.Errorf("session: liveness %q not found or expired", id)
	}
	delete(m.liveness, id)
	if time.Now().After(e.ExpiresAt) {
		return nil, fmt.Errorf("session: liveness %q expired", id)
	}
	return e, nil
}

// PutOffer stores signed credentials for wallet redemption and returns a transaction ID.
func (m *Manager) PutOffer(credentials []string, scope string) (string, error) {
	id, err := newID()
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	m.offers[id] = &OfferEntry{
		Credentials: credentials,
		Scope:       scope,
		ExpiresAt:   time.Now().Add(m.offerTTL),
	}
	m.mu.Unlock()
	return id, nil
}

// TakeOffer retrieves and atomically removes a credential offer (one-time use).
// Returns an error if the ID is unknown or the entry has expired.
func (m *Manager) TakeOffer(id string) (*OfferEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.offers[id]
	if !ok {
		return nil, fmt.Errorf("session: offer %q not found or expired", id)
	}
	delete(m.offers, id)
	if time.Now().After(e.ExpiresAt) {
		return nil, fmt.Errorf("session: offer %q expired", id)
	}
	return e, nil
}

// RecordLivenessProof stores FaceTec Server's livenessProven verdict for the
// process-request session identified by key. The latest verdict wins, so a
// liveness step the user retried and then passed counts as proven.
func (m *Manager) RecordLivenessProof(key string, proven bool) {
	m.mu.Lock()
	m.proofs[key] = &livenessProof{proven: proven, expiresAt: time.Now().Add(m.proofTTL)}
	m.mu.Unlock()
}

// TakeLivenessProof reports whether liveness was proven for the session
// identified by key, and removes the record (one-time use). An unknown,
// expired or unproven session reports false.
func (m *Manager) TakeLivenessProof(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.proofs[key]
	if !ok {
		return false
	}
	delete(m.proofs, key)
	return p.proven && !time.Now().After(p.expiresAt)
}

// reap periodically removes expired entries from the stores.
// It stops when Close() is called and zeros all remaining biometric data before returning.
func (m *Manager) reap() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			m.mu.Lock()
			for id, e := range m.liveness {
				if now.After(e.ExpiresAt) {
					clear(e.FaceMap) // zero biometric bytes before eviction
					delete(m.liveness, id)
				}
			}
			for id, e := range m.offers {
				if now.After(e.ExpiresAt) {
					delete(m.offers, id)
				}
			}
			for key, p := range m.proofs {
				if now.After(p.expiresAt) {
					delete(m.proofs, key)
				}
			}
			m.mu.Unlock()
		case <-m.done:
			// Zero all remaining biometric data before the goroutine exits.
			m.mu.Lock()
			for id, e := range m.liveness {
				clear(e.FaceMap)
				delete(m.liveness, id)
			}
			m.mu.Unlock()
			return
		}
	}
}

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("session: generate id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
