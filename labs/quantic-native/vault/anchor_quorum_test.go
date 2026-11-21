package main

import (
	"crypto/sha256"
	"strings"
	"testing"
)

func TestQuorumPinOrderAndDistinctness(t *testing.T) {
	p := []string{strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64), strings.Repeat("4", 64)}
	a, e := quorumPin(p)
	if e != nil {
		t.Fatal(e)
	}
	p[0], p[3] = p[3], p[0]
	b, e := quorumPin(p)
	if e != nil || a != b {
		t.Fatal("unstable group pin")
	}
	p[0] = p[1]
	if _, e = quorumPin(p); e == nil {
		t.Fatal("duplicate pin accepted")
	}
}
func TestQuorumThreshold(t *testing.T) {
	var q quorumAnchor
	h := sha256.Sum256([]byte("synthetic"))
	for i := range q.members {
		q.members[i] = &fakeAnchor{tail: h, fail: i == 0}
	}
	if e := q.check("test", 0, h); e != nil {
		t.Fatal(e)
	}
	q.members[1].(*fakeAnchor).fail = true
	if q.advance("test", 0, h, h) == nil {
		t.Fatal("two votes accepted")
	}
}
