package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
)

// Classical QuanticMail envelope compatibility, not a new wire format.
// Only the manifest-bound compact quorum broker can invoke this path.
// Never accept a hybrid or one-time-prekey record as a static envelope.
type mailPublicJWK struct {
	Kty    string   `json:"kty"`
	Crv    string   `json:"crv"`
	X      string   `json:"x"`
	Y      string   `json:"y"`
	Ext    *bool    `json:"ext,omitempty"`
	KeyOps []string `json:"key_ops,omitempty"`
}
type mailEnvelope struct {
	Ciphertext         string        `json:"ciphertext"`
	IV                 string        `json:"iv"`
	EphemeralPublicKey mailPublicJWK `json:"ephemeralPublicKey"`
}

func mailB64(s string, min, max int) ([]byte, error) {
	if len(s) > base64.StdEncoding.EncodedLen(max) {
		return nil, errors.New("size")
	}
	b, e := base64.StdEncoding.Strict().DecodeString(s)
	if e != nil || len(b) < min || len(b) > max || base64.StdEncoding.EncodeToString(b) != s {
		return nil, errors.New("encoding")
	}
	return b, nil
}
func mailOpen(key agreementKey, p mailEnvelope) ([]byte, error) {
	j := p.EphemeralPublicKey
	if j.Kty != "EC" || j.Crv != "P-256" || len(j.KeyOps) != 0 {
		return nil, errors.New("invalid public point")
	}
	x, e := decode(j.X, 32, 32)
	if e != nil {
		return nil, e
	}
	y, e := decode(j.Y, 32, 32)
	if e != nil {
		return nil, e
	}
	ep, e := public(b64.EncodeToString(append(append([]byte{4}, x...), y...)))
	if e != nil {
		return nil, e
	}
	iv, e := mailB64(p.IV, 12, 12)
	if e != nil {
		return nil, e
	}
	ct, e := mailB64(p.Ciphertext, 16, maxPlain+16)
	if e != nil {
		return nil, e
	}
	z, e := key.ECDH(ep)
	if e != nil {
		return nil, e
	}
	defer clear(z)
	if len(z) != 32 {
		return nil, errors.New("invalid ECDH output")
	}
	// WebCrypto ECDH deriveKey(AES-GCM 256) uses the raw 32-byte P-256 shared secret.
	block, e := aes.NewCipher(z)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	return a.Open(nil, iv, ct, nil)
}

// Replay ID hashes the cryptographic fields, not optional WebCrypto metadata.
func mailReplay(p mailEnvelope) [32]byte {
	return replayID("quantic-mail-classical-static-v1", []byte(p.EphemeralPublicKey.X+":"+p.EphemeralPublicKey.Y+":"+p.IV+":"+p.Ciphertext))
}
