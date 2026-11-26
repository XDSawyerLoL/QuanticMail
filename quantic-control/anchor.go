package control

import (
    "bytes"
    "crypto/ed25519"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "strings"
)

// AnchorPayload pins the exact journal bytes at a specific committed sequence.
// The authority that signs it MUST hold a key independently from this machine.
// It is a proposed integration boundary for Identity Vault, not that integration.
type AnchorPayload struct {
    Version       int    `json:"version"`
    MachineID     string `json:"machine_id"`
    Sequence      uint64 `json:"sequence"`
    JournalHead   string `json:"journal_head"`
    JournalSHA256 string `json:"journal_sha256"`
    AuthorityID   string `json:"authority_id"`
}

type SignedAnchor struct {
    Payload   AnchorPayload `json:"payload"`
    Signature []byte        `json:"signature"`
}

// AnchorSigningBytes is deterministic and domain separated. It accepts no
// arbitrary script, machine command or instruction to be signed.
func AnchorSigningBytes(p AnchorPayload) ([]byte, error) {
    if p.Version != 1 || p.MachineID == "" || p.Sequence == 0 || p.AuthorityID == "" ||
       !validSHA256(p.JournalHead) || !validSHA256(p.JournalSHA256) {
        return nil, errors.New("invalid anchor payload")
    }
    b, err := json.Marshal(p)
    if err != nil { return nil, err }
    return append([]byte("QUANTIC-CONTROL/state-anchor/v1\n"), b...), nil
}

func validSHA256(s string) bool {
    if len(s) != 64 || strings.ToLower(s) != s { return false }
    _, err := hex.DecodeString(s)
    return err == nil
}

// journalFileSHA256 checks the complete committed file, including record
// framing, to catch modifications that preserve a syntactically valid chain.
// Call with DurableGuard.mu held.
func (d *DurableGuard) journalFileSHA256() (string, error) {
    if d.poisoned || d.file == nil { return "", errStateUnavailable }
    st, err := d.file.Stat()
    if err != nil { return "", err }
    if st.Size() != d.bytesWritten || d.bytesWritten <= 0 || d.bytesWritten > maxJournalBytes {
        return "", errors.New("journal changed or invalid length")
    }
    h := sha256.New()
    n, err := io.Copy(h, io.NewSectionReader(d.file, 0, d.bytesWritten))
    if err != nil { return "", err }
    if n != d.bytesWritten { return "", io.ErrUnexpectedEOF }
    return hex.EncodeToString(h.Sum(nil)), nil
}

// AnchorProposal returns public-only metadata for an independent signing
// authority. It does NOT generate, store, or access any private signing key.
func (d *DurableGuard) AnchorProposal(authorityID string) (AnchorPayload, error) {
    d.mu.Lock()
    defer d.mu.Unlock()
    if authorityID == "" { return AnchorPayload{}, errors.New("authority identifier required") }
    hash, err := d.journalFileSHA256()
    if err != nil { return AnchorPayload{}, err }
    return AnchorPayload{Version:1, MachineID:d.machineID, Sequence:d.sequence,
        JournalHead:d.head, JournalSHA256:hash, AuthorityID:authorityID}, nil
}

// VerifyPinnedAnchor requires an anchor delivered by an independent trusted
// channel, with a public key pinned independently of the local journal.
// Exact-state matching is intentional: after any new journal append, a fresh
// signature must be obtained before reopening with this API.
// It cannot detect rollback if an attacker also replaces the caller's trusted
// anchor and key. Host-level protection and independent monotonic pinning remain required.
func (d *DurableGuard) VerifyPinnedAnchor(a SignedAnchor, authorityID string, authorityPub ed25519.PublicKey) error {
    d.mu.Lock()
    defer d.mu.Unlock()
    if d.poisoned || d.file == nil || d.guard == nil { return errStateUnavailable }
    if len(authorityPub) != ed25519.PublicKeySize || a.Payload.AuthorityID != authorityID ||
       a.Payload.MachineID != d.machineID { return errors.New("untrusted anchor authority or machine") }
    for _, operatorKey := range d.guard.keys {
        if bytes.Equal(operatorKey, authorityPub) {
            return errors.New("anchor signing key must be independent from enrolled operator keys")
        }
    }
    message, err := AnchorSigningBytes(a.Payload)
    if err != nil { return err }
    if !ed25519.Verify(authorityPub, message, a.Signature) {
        return errors.New("anchor signature invalid")
    }
    if a.Payload.Sequence != d.sequence || a.Payload.JournalHead != d.head {
        return fmt.Errorf("journal sequence or head does not match pinned anchor")
    }
    actualHash, err := d.journalFileSHA256()
    if err != nil { return err }
    if actualHash != a.Payload.JournalSHA256 {
        return errors.New("journal contents do not match pinned anchor")
    }
    return nil
}

// OpenPinnedDurableGuard fails closed on a stale or forged independent anchor.
// The trusted anchor MUST be retained outside the rollback-capable host; the
// API cannot enforce where the caller obtained it.
func OpenPinnedDurableGuard(path, machineID string, operatorKeys map[string]ed25519.PublicKey,
    anchor SignedAnchor, authorityID string, authorityPub ed25519.PublicKey) (*DurableGuard, error) {
    d, err := OpenDurableGuard(path, machineID, operatorKeys)
    if err != nil { return nil, err }
    if err := d.VerifyPinnedAnchor(anchor, authorityID, authorityPub); err != nil {
        _ = d.Close()
        return nil, fmt.Errorf("pinned state refused: %w", err)
    }
    return d, nil
}
