package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"
)

type manifestVote struct {
	ContactCommitment string `json:"contactCommitment,omitempty"`
	Sequence        int64  `json:"sequence"`
	Digest          string `json:"digest"`
	Expires         int64  `json:"expires"`
	ProfileSequence int64  `json:"profileSequence,omitempty"`
	ProfileDigest   string `json:"profileDigest,omitempty"`
	PQBinding       string `json:"pqBinding,omitempty"`
}
type freshQuorum struct {
	q               *quorumAnchor
	sequence        int64
	digest          string
	scheduled       bool
	compact         bool
	pqBinding       string
	profileSequence int64
	profileDigest   string
	dualRootPin    string
	pqAddress      string
	pqDevice       string
	pqKemPin       string
	pqDsaPin       string
	localProof *dualLocalProof
	contactID string
	contactCommitment string
}

func (a *remoteAnchor) fresh(op string, p anchorRequest, scheduled, compact bool) (manifestVote, error) {
	var v manifestVote
	b, e := json.Marshal(p)
	if e != nil {
		return v, e
	}
	prefix := "/fresh-"
	if scheduled {
		prefix = "/scheduled-"
	}
	if compact {
		prefix = "/compact-"
	}
	resp, e := a.client.Post(a.endpoint+prefix+op, "application/json", bytes.NewReader(b))
	if e != nil {
		return v, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return v, errors.New("fresh witness refused")
	}
	raw, e := io.ReadAll(io.LimitReader(resp.Body, 513))
	if e != nil || len(raw) > 512 {
		return v, errors.New("invalid vote")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var extra any
	if d.Decode(&v) != nil || d.Decode(&extra) != io.EOF {
		return v, errors.New("invalid vote")
	}
	return v, nil
}
func (q *freshQuorum) accept(votes []manifestVote, now int64) error {
	type version struct {
		sequence        int64
		digest          string
		profileSequence int64
		profileDigest   string
	}
	counts := map[version]int{}
	for _, v := range votes {
		if v.ContactCommitment!=q.contactCommitment{continue}
		if v.Sequence < 1 || !hashRE.MatchString(v.Digest) || v.Expires <= now || v.Expires > now+30000 {
			continue
		}
		if q.pqBinding != "" {
			if v.PQBinding != q.pqBinding || v.ProfileSequence < 1 || !hashRE.MatchString(v.ProfileDigest) {
				continue
			}
		} else if v.PQBinding != "" || v.ProfileSequence != 0 || v.ProfileDigest != "" {
			continue
		}
		if q.dualRootPin != "" {
			if q.localProof != nil && q.localProof.sequence != v.ProfileSequence { continue }
			expected, err := q.expectedDualDigest(v.ProfileSequence)
			if err != nil || v.ProfileDigest != expected {
				continue
			}
		}
		counts[version{v.Sequence, v.Digest, v.ProfileSequence, v.ProfileDigest}]++
	}
	for v, n := range counts {
		if n >= 3 {
			if v.sequence < q.sequence || (v.sequence == q.sequence && q.digest != "" && q.digest != v.digest) {
				return errors.New("manifest rollback or fork")
			}
			if v.profileSequence < q.profileSequence || (v.profileSequence == q.profileSequence && q.profileDigest != "" && v.profileDigest != q.profileDigest) {
				return errors.New("PQ profile rollback or fork")
			}
			q.profileSequence = v.profileSequence
			q.profileDigest = v.profileDigest
			q.sequence = v.sequence
			q.digest = v.digest
			return nil
		}
	}
	return errors.New("no three identical fresh manifest votes")
}
func (q *freshQuorum) call(op string, p anchorRequest) error {
	p.PQBinding = q.pqBinding
	p.ContactID,p.ContactCommitment=q.contactID,q.contactCommitment
	ch := make(chan manifestVote, 4)
	for _, m := range q.q.members {
		a, ok := m.(*remoteAnchor)
		if !ok {
			return errors.New("invalid witness")
		}
		go func() {
			v, e := a.fresh(op, p, q.scheduled, q.compact)
			if e != nil {
				v = manifestVote{}
			}
			ch <- v
		}()
	}
	votes := make([]manifestVote, 0, 4)
	for i := 0; i < 4; i++ {
		votes = append(votes, <-ch)
	}
	return q.accept(votes, time.Now().UnixMilli())
}
func (q *freshQuorum) check(id string, n int, h [32]byte) error {
	return q.call("check", anchorRequest{ID: id, Count: n, Tail: hex.EncodeToString(h[:])})
}
func (q *freshQuorum) advance(id string, n int, h, k [32]byte) error {
	return q.call("advance", anchorRequest{ID: id, Count: n, Tail: hex.EncodeToString(h[:]), Record: hex.EncodeToString(k[:])})
}
