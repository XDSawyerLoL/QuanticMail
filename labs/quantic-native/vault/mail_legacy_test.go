package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestClassicalMailInterop(t *testing.T) {
	r, e := ecdh.P256().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	p, e := ecdh.P256().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	z, e := p.ECDH(r.PublicKey())
	if e != nil {
		t.Fatal(e)
	}
	b, _ := aes.NewCipher(z)
	a, _ := cipher.NewGCM(b)
	iv := make([]byte, 12)
	rand.Read(iv)
	plain := []byte(`{"subject":"test","body":"native only"}`)
	raw := p.PublicKey().Bytes()
	env := mailEnvelope{base64.StdEncoding.EncodeToString(a.Seal(nil, iv, plain, nil)), base64.StdEncoding.EncodeToString(iv), mailPublicJWK{Kty: "EC", Crv: "P-256", X: b64.EncodeToString(raw[1:33]), Y: b64.EncodeToString(raw[33:])}}
	got, e := mailOpen(r, env)
	if e != nil || !bytes.Equal(got, plain) {
		t.Fatal("interop", e)
	}
	h := mailReplay(env)
	flag := true
	env.EphemeralPublicKey.Ext = &flag
	if mailReplay(env) != h {
		t.Fatal("metadata changes replay ID")
	}
	wrong, _ := ecdh.P256().GenerateKey(rand.Reader)
	if _, e = mailOpen(wrong, env); e == nil {
		t.Fatal("wrong recipient accepted")
	}
	env.Ciphertext = base64.StdEncoding.EncodeToString(make([]byte, 32))
	if _, e = mailOpen(r, env); e == nil {
		t.Fatal("tampering accepted")
	}
	env.IV = "!!!"
	if _, e = mailOpen(r, env); e == nil {
		t.Fatal("invalid encoding")
	}
}
func TestMailOpenUnanchoredRefused(t *testing.T) {
	var out bytes.Buffer
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	if e := serveBroker(softwareSigner{k}, "test", bytes.NewBufferString("{\"op\":\"mail-open-static-lab\",\"mail\":{}}\n"), &out); e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(out.Bytes(), []byte(`"ok":false`)) {
		t.Fatal(out.String())
	}
}
