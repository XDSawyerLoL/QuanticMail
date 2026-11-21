package main

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

type fakeAnchor struct {
	count int
	tail  [32]byte
	fail  bool
}

func (a *fakeAnchor) check(_ string, n int, h [32]byte) error {
	if a.fail || a.count != n || a.tail != h {
		return errors.New("checkpoint mismatch")
	}
	return nil
}
func (a *fakeAnchor) advance(id string, n int, h, k [32]byte) error {
	if e := a.check(id, n, h); e != nil {
		return e
	}
	a.tail = hashRecord(h, k)
	a.count++
	return nil
}
func TestAnchorMismatchAfterUncertainCommit(t *testing.T) {
	p, s, e, app := testJournal(t)
	j, err := openReplay(p, s, e, app)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := anchorID(s, e, app)
	a := &fakeAnchor{tail: j.tail}
	if err = j.attachAnchor(a, id); err != nil {
		t.Fatal(err)
	}
	if err = j.consume(sha256.Sum256([]byte("one"))); err != nil {
		t.Fatal(err)
	}
	a.fail = true
	if j.consume(sha256.Sum256([]byte("two"))) == nil || !j.failed {
		t.Fatal("private result could be released")
	}
	j.close()
	a.fail = false
	j, err = openReplay(p, s, e, app)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	if j.attachAnchor(a, id) == nil {
		t.Fatal("divergence accepted")
	}
}
func TestAnchoredVaultFormatNoDowngrade(t *testing.T) {
	k, err := freshPortable()
	if err != nil {
		t.Fatal(err)
	}
	p := []byte("synthetic secret only 2026")
	mode := anchoredMagic + strings.Repeat("a", 64) + "\x00"
	b, err := encryptPortableMode(k, p, mode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decryptPortable(b, p); err == nil {
		t.Fatal("downgrade accepted")
	}
	if _, err = decryptPortableMode(b, p, mode); err != nil {
		t.Fatal(err)
	}
	legacy, err := encryptPortable(k, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decryptPortableMode(b, p, anchoredMagic+strings.Repeat("b", 64)+"\x00"); err == nil {
		t.Fatal("alternate authority accepted")
	}
	if _, err = decryptPortableMode(legacy, p, mode); err == nil {
		t.Fatal("legacy silently promoted")
	}
}
