package control

import (
    "crypto/ed25519"
    "crypto/rand"
    "testing"
    "time"
)

func TestGuardAuthorizationAndReplay(t *testing.T) {
    pub, priv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { t.Fatal(err) }
    g, err := NewGuard("machine-1", map[string]ed25519.PublicKey{"admin-1": pub})
    if err != nil { t.Fatal(err) }
    now := time.Unix(1795450000, 0)
    c := Claims{Version: 1, MachineID: "machine-1", Action: "integrity.scan", KeyID: "admin-1", Nonce: "0123456789abcdef", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix()}
    sign := func(claims Claims) SignedRequest {
        t.Helper()
        bytes, err := SigningBytes(claims)
        if err != nil { t.Fatal(err) }
        return SignedRequest{Claims: claims, Signature: ed25519.Sign(priv, bytes)}
    }
    req := sign(c)
    if err := g.Authorize(req, now); err != nil { t.Fatal(err) }
    if err := g.Authorize(req, now); err == nil { t.Fatal("replay accepted") }
    modified := req
    modified.Claims.Nonce = "different-0123456"
    if err := g.Authorize(modified, now); err == nil { t.Fatal("tampering accepted") }

    unauthorized := c
    unauthorized.Nonce = "aaaaaaaaaaaaaaaa"
    unauthorized.Action = "shell.execute"
    if err := g.Authorize(sign(unauthorized), now); err == nil { t.Fatal("arbitrary action accepted") }

    wrongMachine := c
    wrongMachine.Nonce = "bbbbbbbbbbbbbbbb"
    wrongMachine.MachineID = "other"
    if err := g.Authorize(sign(wrongMachine), now); err == nil { t.Fatal("wrong machine accepted") }

    expired := c
    expired.Nonce = "cccccccccccccccc"
    expired.ExpiresAt = now.Unix()-1
    if err := g.Authorize(sign(expired), now); err == nil { t.Fatal("expired accepted") }

    g.Revoke("admin-1")
    valid := c
    valid.Nonce = "dddddddddddddddd"
    if err := g.Authorize(sign(valid), now); err == nil { t.Fatal("revoked key accepted") }
}

func TestGuardRejectsUnknownAndInvalidKeys(t *testing.T) {
    if _, err := NewGuard("", nil); err == nil { t.Fatal("missing machine ID accepted") }
    if _, err := NewGuard("machine", map[string]ed25519.PublicKey{"bad": {1}}); err == nil { t.Fatal("invalid key accepted") }
    g, err := NewGuard("machine", nil)
    if err != nil { t.Fatal(err) }
    now := time.Now()
    c := Claims{Version: 1, MachineID: "machine", Action: "status.read", KeyID: "unknown", Nonce: "0123456789abcdef", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix()}
    if err := g.Authorize(SignedRequest{Claims: c}, now); err == nil { t.Fatal("unknown key accepted") }
}
