package main

import (
	"strings"
	"testing"
)

func TestDualRootDigestRequired(t *testing.T) {
	q := freshQuorum{
		pqBinding: strings.Repeat("a", 64),
		dualRootPin: strings.Repeat("b", 64),
		pqAddress: "alice~" + strings.Repeat("c", 32) + "@quantic",
		pqDevice: "d-" + strings.Repeat("d", 32),
		pqKemPin: strings.Repeat("e", 64),
		pqDsaPin: strings.Repeat("f", 64),
	}
	expected, err := q.expectedDualDigest(1)
	if err != nil {
		t.Fatal(err)
	}
	// Cross-language network regression exercises the exact Python digest.
	v := manifestVote{Sequence: 1, Digest: strings.Repeat("1", 64), Expires: 2000, ProfileSequence: 1, ProfileDigest: expected, PQBinding: q.pqBinding}
	bad := v
	bad.ProfileDigest = strings.Repeat("0", 64)
	if q.accept([]manifestVote{bad, bad, bad, bad}, 1000) == nil {
		t.Fatal("matching but unpinned digest accepted")
	}
	if q.accept([]manifestVote{v, v, bad, bad}, 1000) == nil {
		t.Fatal("split accepted")
	}
	if q.accept([]manifestVote{v, v, v, bad}, 1000) != nil {
		t.Fatal("valid committed grant refused")
	}
	bad = v
	bad.ProfileSequence = 2
	if q.accept([]manifestVote{bad, bad, bad, bad}, 1000) == nil {
		t.Fatal("digest reused at newer sequence")
	}
	q.dualRootPin = strings.Repeat("9", 64)
	if q.accept([]manifestVote{v, v, v, v}, 1000) == nil {
		t.Fatal("wrong root accepted")
	}
}
