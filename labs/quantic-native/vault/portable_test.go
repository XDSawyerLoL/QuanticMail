//go:build linux

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var testPassword = []byte("synthetic-only-password-2026")

func TestPortableKDFVector(t *testing.T) {
	got := hex.EncodeToString(derivePortable([]byte("password"), []byte("salt"), 2))
	if got != "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43" {
		t.Fatal(got)
	}
}
func fixturePortable(t *testing.T) (string, portableKeys, string, string) {
	t.Helper()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(dir, "vault")
	k, e := provisionSoftware(p, testPassword)
	if e != nil {
		t.Fatal(e)
	}
	s, a := portablePins(k)
	return p, k, s, a
}
func TestPortableReopenCrypto(t *testing.T) {
	p, k, s, a := fixturePortable(t)
	opened, e := openSoftware(p, testPassword, s, a)
	if e != nil {
		t.Fatal(e)
	}
	d := sha256.Sum256([]byte("synthetic"))
	sig, e := softwareSigner{opened.signing}.SignDigest(d)
	if e != nil || !ecdsa.Verify(&k.signing.PublicKey, d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("sign")
	}
	packet, e := seal(k.agreement.PublicKey(), []byte("persist"))
	if e != nil {
		t.Fatal(e)
	}
	plain, e := unseal(opened.agreement, packet)
	if e != nil || string(plain) != "persist" {
		t.Fatal("decrypt", e)
	}
}
func TestPortableWrongPasswordAndPin(t *testing.T) {
	p, _, s, a := fixturePortable(t)
	if _, e := openSoftware(p, []byte("incorrect-password-only"), s, a); e == nil {
		t.Fatal("password")
	}
	if _, e := openSoftware(p, testPassword, strings.Repeat("a", 64), a); e == nil {
		t.Fatal("pin")
	}
}
func TestPortableTamper(t *testing.T) {
	p, _, s, a := fixturePortable(t)
	raw, _ := os.ReadFile(p)
	for _, i := range []int{0, len(portableMagic), len(portableMagic) + 16, len(raw) - 1} {
		b := bytes.Clone(raw)
		b[i] ^= 1
		os.WriteFile(p, b, 0600)
		if _, e := openSoftware(p, testPassword, s, a); e == nil {
			t.Fatal("tamper", i)
		}
	}
	os.WriteFile(p, raw[:len(raw)-1], 0600)
	if _, e := openSoftware(p, testPassword, s, a); e == nil {
		t.Fatal("truncation")
	}
}
func TestPortableNoOverwriteOrCreateOnOpen(t *testing.T) {
	p, _, s, a := fixturePortable(t)
	before, _ := os.ReadFile(p)
	if _, e := provisionSoftware(p, testPassword); e == nil {
		t.Fatal("overwrite")
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(before, after) {
		t.Fatal("modified")
	}
	missing := filepath.Join(filepath.Dir(p), "missing")
	if _, e := openSoftware(missing, testPassword, s, a); e == nil {
		t.Fatal("created")
	}
	if _, e := os.Stat(missing); !os.IsNotExist(e) {
		t.Fatal(e)
	}
}
func TestPortablePrivatePermissions(t *testing.T) {
	p, _, s, a := fixturePortable(t)
	os.Chmod(p, 0644)
	if _, e := openSoftware(p, testPassword, s, a); e == nil {
		t.Fatal("public file")
	}
	os.Chmod(p, 0600)
	link := filepath.Join(filepath.Dir(p), "link")
	os.Symlink(p, link)
	if _, e := openSoftware(link, testPassword, s, a); e == nil {
		t.Fatal("symlink")
	}
	os.Chmod(filepath.Dir(p), 0755)
	if _, e := openSoftware(p, testPassword, s, a); e == nil {
		t.Fatal("public directory")
	}
}
func TestPortableSaltNonceAndPasswordBounds(t *testing.T) {
	k, e := freshPortable()
	if e != nil {
		t.Fatal(e)
	}
	a, e := encryptPortable(k, testPassword)
	if e != nil {
		t.Fatal(e)
	}
	b, e := encryptPortable(k, testPassword)
	if e != nil || bytes.Equal(a, b) {
		t.Fatal("randomness", e)
	}
	if bytes.Contains(a, k.agreement.Bytes()) || bytes.Contains(a, k.signing.D.FillBytes(make([]byte, 32))) {
		t.Fatal("raw scalar")
	}
	if _, e := encryptPortable(k, []byte("short")); e == nil {
		t.Fatal("short")
	}
}
