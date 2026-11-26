package main

import (
	"strings"
	"testing"
)

func TestFreshQuorumExactManifest(t *testing.T) {
	q := freshQuorum{}
	a := manifestVote{Sequence: 1, Digest: strings.Repeat("a", 64), Expires: 2000}
	b := manifestVote{Sequence: 2, Digest: strings.Repeat("b", 64), Expires: 2000}
	if q.accept([]manifestVote{a, a, b, b}, 1000) == nil {
		t.Fatal("split accepted")
	}
	if q.accept([]manifestVote{a, a, a, b}, 1000) != nil {
		t.Fatal("three identical refused")
	}
	if q.accept([]manifestVote{b, b, b, a}, 2000) == nil {
		t.Fatal("expired accepted")
	}
	if q.accept([]manifestVote{b, b, b, a}, 1000) != nil {
		t.Fatal("newer rejected")
	}
	if q.accept([]manifestVote{a, a, a, b}, 1000) == nil {
		t.Fatal("rollback accepted")
	}
	c := b
	c.Digest = a.Digest
	if q.accept([]manifestVote{c, c, c, b}, 1000) == nil {
		t.Fatal("same-sequence fork accepted")
	}
}
func TestPQProfileQuorum(t *testing.T) {
	pin := strings.Repeat("c", 64)
	q := freshQuorum{pqBinding: pin}
	a := manifestVote{Sequence: 1, Digest: strings.Repeat("a", 64), Expires: 2000, ProfileSequence: 1, ProfileDigest: strings.Repeat("d", 64), PQBinding: pin}
	b := a
	b.ProfileSequence = 2
	b.ProfileDigest = strings.Repeat("e", 64)
	if q.accept([]manifestVote{a, a, b, b}, 1000) == nil {
		t.Fatal("split")
	}
	if q.accept([]manifestVote{a, a, a, b}, 1000) != nil {
		t.Fatal("matching grant refused")
	}
	if q.accept([]manifestVote{b, b, b, a}, 1000) != nil {
		t.Fatal("advance refused")
	}
	if q.accept([]manifestVote{a, a, a, b}, 1000) == nil {
		t.Fatal("rollback")
	}
	c := b
	c.PQBinding = strings.Repeat("f", 64)
	if q.accept([]manifestVote{c, c, c, b}, 1000) == nil {
		t.Fatal("wrong binding")
	}
	c = b
	c.ProfileDigest = a.ProfileDigest
	if q.accept([]manifestVote{c, c, c, b}, 1000) == nil {
		t.Fatal("fork")
	}
	c = b
	c.PQBinding = ""
	c.ProfileSequence = 0
	c.ProfileDigest = ""
	if q.accept([]manifestVote{c, c, c, b}, 1000) == nil {
		t.Fatal("classical fallback")
	}
}
