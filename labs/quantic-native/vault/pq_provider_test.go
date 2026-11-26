//go:build (linux || windows) && cgo && pqopenssl

package main

import (
	"bytes"
	"testing"
)

// Exercises the real OpenSSL provider, never the fail-closed stub.
func TestPQProviderRoundTrip(t *testing.T) {
	kem, err := pqGenerate("ML-KEM-768")
	if err != nil { t.Fatal(err) }
	defer kem.close()
	dsa, err := pqGenerate("ML-DSA-65")
	if err != nil { t.Fatal(err) }
	defer dsa.close()
	kpub, err := kem.der(false)
	if err != nil || len(kpub) != 1206 { t.Fatal("KEM public encoding", err) }
	dpub, err := dsa.der(false)
	if err != nil || len(dpub) != 1974 { t.Fatal("DSA public encoding", err) }
	kpriv, err := kem.der(true)
	if err != nil { t.Fatal(err) }
	defer clear(kpriv)
	dpriv, err := dsa.der(true)
	if err != nil { t.Fatal(err) }
	defer clear(dpriv)
	k2, err := pqImport(kpriv, "ML-KEM-768")
	if err != nil { t.Fatal(err) }
	defer k2.close()
	d2, err := pqImport(dpriv, "ML-DSA-65")
	if err != nil { t.Fatal(err) }
	defer d2.close()
	ct, secret, err := pqEncapPublic(kpub)
	if err != nil { t.Fatal(err) }
	defer clear(secret)
	opened, err := k2.dec(ct)
	if err != nil { t.Fatal(err) }
	defer clear(opened)
	if len(secret) != 32 || !bytes.Equal(secret, opened) { t.Fatal("KEM mismatch") }
	if _, err := k2.dec(ct[:len(ct)-1]); err == nil { t.Fatal("short KEM ciphertext accepted") }
	msg := []byte("quantic-pq-provider-test/v1")
	sig, err := d2.sign(msg)
	if err != nil || !pqVerifyRoot(dpub, msg, sig) { t.Fatal("signature verification", err) }
	if pqVerifyRoot(dpub, []byte("different"), sig) { t.Fatal("changed message accepted") }
	sig[0] ^= 1
	if pqVerifyRoot(dpub, msg, sig) { t.Fatal("changed signature accepted") }
	bad, err := pqImport(kpriv, "ML-DSA-65")
	if err == nil { bad.close(); t.Fatal("wrong key algorithm accepted") }
}
