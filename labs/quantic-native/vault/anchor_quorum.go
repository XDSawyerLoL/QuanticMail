package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
)

// A fixed 3-of-4 checkpoint policy. No leader, repair, or consensus protocol.
// Assumes at most one faulty authority and independently protected state domains.
type quorumAnchor struct {
	members [4]checkpointAnchor
	pin     string
}

func quorumPin(pins []string) (string, error) {
	if len(pins) != 4 {
		return "", errors.New("four authority pins required")
	}
	pins = append([]string(nil), pins...)
	sort.Strings(pins)
	for i, p := range pins {
		if !hashRE.MatchString(p) || (i > 0 && p == pins[i-1]) {
			return "", errors.New("invalid or duplicate authority pin")
		}
	}
	return hexHash([]byte("quantic-anchor-quorum-lab/v1\x003-of-4\x00" + strings.Join(pins, ""))), nil
}
func newQuorumAnchor(path string) (*quorumAnchor, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	var configs []anchorConfig
	d := json.NewDecoder(io.LimitReader(f, 65537))
	d.DisallowUnknownFields()
	var extra any
	if d.Decode(&configs) != nil || d.Decode(&extra) != io.EOF || len(configs) != 4 {
		return nil, errors.New("invalid quorum config")
	}
	q := &quorumAnchor{}
	pins := make([]string, 4)
	urls := map[string]bool{}
	for i, c := range configs {
		if urls[c.URL] {
			return nil, errors.New("duplicate endpoint")
		}
		urls[c.URL] = true
		pins[i] = c.ServerPin
		a, e := remoteFromConfig(c)
		if e != nil {
			return nil, e
		}
		q.members[i] = a
	}
	q.pin, e = quorumPin(pins)
	if e != nil {
		return nil, e
	}
	return q, nil
}
func (q *quorumAnchor) vote(fn func(checkpointAnchor) error) error {
	// Wait for every bounded TLS request to settle. Never retry or silently lower threshold.
	results := make(chan error, 4)
	for _, a := range q.members {
		go func(a checkpointAnchor) { results <- fn(a) }(a)
	}
	n := 0
	for i := 0; i < 4; i++ {
		if <-results == nil {
			n++
		}
	}
	if n < 3 {
		return errors.New("checkpoint quorum refused")
	}
	return nil
}
func (q *quorumAnchor) check(id string, n int, h [32]byte) error {
	return q.vote(func(a checkpointAnchor) error { return a.check(id, n, h) })
}
func (q *quorumAnchor) advance(id string, n int, h, k [32]byte) error {
	return q.vote(func(a checkpointAnchor) error { return a.advance(id, n, h, k) })
}
