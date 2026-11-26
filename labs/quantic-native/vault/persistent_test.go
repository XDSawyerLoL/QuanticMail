package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
)

func TestRawSecretEndian(t *testing.T) {
	z := make([]byte, 32)
	for i := range z {
		z[i] = byte(i)
	}
	want := append([]byte(nil), z...)
	reverseSecret(z)
	if z[0] != 31 || z[31] != 0 || equalSecret(z, want) {
		t.Fatal("incorrect endian")
	}
	reverseSecret(z)
	if !equalSecret(z, want) {
		t.Fatal("roundtrip")
	}
}
func TestConsentIndependentOfIPC(t *testing.T) {
	s, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	e, _ := ecdh.P256().GenerateKey(rand.Reader)
	p, _ := seal(e.PublicKey(), []byte("synthetic"))
	raw, _ := json.Marshal(request{Op: "open", Packet: &p, Approved: true})
	var output bytes.Buffer
	called := 0
	err := serveWithKey(softwareSigner{s}, e, "test", strings.NewReader(string(raw)+"\n"), &output, func(string) bool { called++; return false })
	if err != nil || called != 1 {
		t.Fatal(err, called)
	}
	var r reply
	if json.Unmarshal(output.Bytes(), &r) != nil || r.OK || r.Message != nil {
		t.Fatal("denial bypassed")
	}
}
func TestConsentAllowsDecryption(t *testing.T) {
	s, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	e, _ := ecdh.P256().GenerateKey(rand.Reader)
	p, _ := seal(e.PublicKey(), []byte("synthetic"))
	raw, _ := json.Marshal(request{Op: "open", Packet: &p})
	var output bytes.Buffer
	calls := 0
	err := serveWithKey(softwareSigner{s}, e, "test", strings.NewReader(string(raw)+"\n"+string(raw)+"\n"), &output, func(string) bool { calls++; return true })
	if err != nil || calls != 1 {
		t.Fatal(err, calls)
	}
	d := json.NewDecoder(&output)
	var a, b reply
	if d.Decode(&a) != nil || d.Decode(&b) != nil || !a.OK || a.Message == nil || b.OK {
		t.Fatal("approval or replay failed")
	}
}
