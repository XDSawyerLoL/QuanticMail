package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

type testSigner struct {
	k     *ecdsa.PrivateKey
	calls int
}

func (s *testSigner) Public() *ecdsa.PublicKey { return &s.k.PublicKey }
func (s *testSigner) SignDigest(d [32]byte) ([]byte, error) {
	s.calls++
	r, v, e := ecdsa.Sign(rand.Reader, s.k, d[:])
	if e != nil {
		return nil, e
	}
	return append(r.FillBytes(make([]byte, 32)), v.FillBytes(make([]byte, 32))...), nil
}
func fixture(t *testing.T) (*testSigner, *authority, time.Time) {
	t.Helper()
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	s := &testSigner{k: k}
	now := time.Now()
	a, e := issue(s.Public(), now)
	if e != nil {
		t.Fatal(e)
	}
	return s, a, now
}
func TestValidAndReplay(t *testing.T) {
	s, a, n := fixture(t)
	r, e := approveAndSign(s, a.pending, n, true)
	if e != nil || !a.verify(r, n) || a.verify(r, n) {
		t.Fatal("valid/replay failure", e)
	}
}
func TestNoApproval(t *testing.T) {
	s, a, n := fixture(t)
	if _, e := approveAndSign(s, a.pending, n, false); e == nil || s.calls != 0 {
		t.Fatal("unapproved sign")
	}
}
func TestScopeAndDomain(t *testing.T) {
	for _, f := range []func(*challenge){func(c *challenge) { c.App = "other" }, func(c *challenge) { c.Scope = "root-sign" }, func(c *challenge) { c.Domain = "production" }, func(c *challenge) { c.Nonce = "bad" }, func(c *challenge) { c.Key = "other" }} {
		s, a, n := fixture(t)
		c := a.pending
		f(&c)
		if _, e := approveAndSign(s, c, n, true); e == nil || s.calls != 0 {
			t.Fatal("invalid sign")
		}
	}
}
func TestExpiry(t *testing.T) {
	s, a, n := fixture(t)
	r, e := approveAndSign(s, a.pending, n, true)
	if e != nil {
		t.Fatal(e)
	}
	if a.verify(r, n.Add(30*time.Second)) {
		t.Fatal("expired")
	}
	if _, e = approveAndSign(s, a.pending, n.Add(30*time.Second), true); e == nil {
		t.Fatal("signed expired")
	}
}
func TestTamperedAndFreshNonce(t *testing.T) {
	s, a, n := fixture(t)
	r, e := approveAndSign(s, a.pending, n, true)
	if e != nil {
		t.Fatal(e)
	}
	other, e := issue(s.Public(), n)
	if e != nil {
		t.Fatal(e)
	}
	if other.verify(r, n) {
		t.Fatal("other nonce accepted")
	}
	r.Signature = "invalid"
	if a.verify(r, n) {
		t.Fatal("tampered accepted")
	}
}
func TestWrongKey(t *testing.T) {
	_, a, n := fixture(t)
	s, _, _ := fixture(t)
	if _, e := approveAndSign(s, a.pending, n, true); e == nil {
		t.Fatal("wrong key accepted")
	}
}
func TestClockRollback(t *testing.T) {
	s, a, n := fixture(t)
	r, e := approveAndSign(s, a.pending, n, true)
	if e != nil {
		t.Fatal(e)
	}
	if a.verify(r, n.Add(-time.Millisecond)) {
		t.Fatal("rollback accepted")
	}
}
