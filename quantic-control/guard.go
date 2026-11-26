package control

import (
    "crypto/ed25519"
    "encoding/json"
    "errors"
    "fmt"
    "sync"
    "time"
)

// Claims is the canonical, domain-separated content that an administrator signs.
// No command line, executable path, or arbitrary script is accepted as an action.
type Claims struct {
    Version int
    MachineID string
    Action string
    KeyID string
    Nonce string
    IssuedAt int64
    ExpiresAt int64
}

type SignedRequest struct {
    Claims Claims
    Signature []byte
}

var readOnlyActions = map[string]bool{
    "status.read": true,
    "integrity.scan": true,
    "alerts.read": true,
}

// SigningBytes is deterministic for this fixed struct, and separates
// Quantic Control signatures from signatures produced by other protocols.
func SigningBytes(c Claims) ([]byte, error) {
    payload, err := json.Marshal(c)
    if err != nil { return nil, err }
    return append([]byte("QUANTIC-CONTROL/authorization/v1\n"), payload...), nil
}

type Guard struct {
    mu sync.Mutex
    machineID string
    keys map[string]ed25519.PublicKey
    revoked map[string]bool
    seen map[string]int64
}

func NewGuard(machineID string, enrolledKeys map[string]ed25519.PublicKey) (*Guard, error) {
    if machineID == "" { return nil, errors.New("machine identity required") }
    keys := make(map[string]ed25519.PublicKey, len(enrolledKeys))
    for id, key := range enrolledKeys {
        if id == "" || len(key) != ed25519.PublicKeySize { return nil, errors.New("invalid enrolled key") }
        keys[id] = append(ed25519.PublicKey(nil), key...)
    }
    return &Guard{machineID: machineID, keys: keys, revoked: make(map[string]bool), seen: make(map[string]int64)}, nil
}

// Revoke stops authorizations from the given key for the life of this guard.
// Durable enrollment and revocation are intentionally out of scope for Alpha 1.
func (g *Guard) Revoke(keyID string) {
    g.mu.Lock()
    defer g.mu.Unlock()
    g.revoked[keyID] = true
}

// Authorize accepts only three read-only actions. It verifies identity,
// device binding, expiry, signature and in-process nonce uniqueness.
// Alpha 1 exposes no remote endpoint or command executor.
func (g *Guard) Authorize(r SignedRequest, now time.Time) error {
    c := r.Claims
    if c.Version != 1 || c.MachineID != g.machineID || !readOnlyActions[c.Action] {
        return errors.New("action, version or machine not authorized")
    }
    if len(c.Nonce) < 16 || len(c.Nonce) > 128 || c.KeyID == "" {
        return errors.New("invalid nonce or key identifier")
    }
    nowUnix := now.Unix()
    if c.IssuedAt > nowUnix+5 || c.IssuedAt < nowUnix-120 ||
        c.ExpiresAt <= nowUnix || c.ExpiresAt <= c.IssuedAt ||
        c.ExpiresAt-c.IssuedAt > 120 {
        return errors.New("request outside permitted time window")
    }
    bytes, err := SigningBytes(c)
    if err != nil { return err }

    g.mu.Lock()
    defer g.mu.Unlock()
    key, ok := g.keys[c.KeyID]
    if !ok || g.revoked[c.KeyID] || !ed25519.Verify(key, bytes, r.Signature) {
        return errors.New("signature invalid, key unknown or key revoked")
    }
    for nonce, until := range g.seen {
        if until <= nowUnix { delete(g.seen, nonce) }
    }
    // Scope nonces by key to prevent accidental collision across operators.
    replayKey := fmt.Sprintf("%s:%s", c.KeyID, c.Nonce)
    if _, exists := g.seen[replayKey]; exists {
        return errors.New("request already used")
    }
    g.seen[replayKey] = c.ExpiresAt
    return nil
}
