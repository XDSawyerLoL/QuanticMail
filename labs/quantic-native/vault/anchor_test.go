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

func TestPrivateSignatureReservedBeforeProvider(t *testing.T) {
	for _, refused := range []int{0, 1, 2} {
		t.Run(string(rune('0'+refused)), func(t *testing.T) {
			p, s, e, app := testJournal(t)
			j, err := openReplay(p, s, e, app)
			if err != nil { t.Fatal(err) }
			defer j.close()
			id, _ := anchorID(s,e,app)
			q := &quorumAnchor{}
			var witnesses [4]*fakeAnchor
			for i := range witnesses {
				witnesses[i] = &fakeAnchor{tail:j.tail}
				q.members[i] = witnesses[i]
			}
			if err = j.attachAnchor(q,id); err != nil { t.Fatal(err) }
			for i:=0;i<refused;i++ { witnesses[i].fail=true }
			k := replayID("pq-proof-lab", []byte("synthetic"))
			calls:=0
			sign := func() ([]byte,error) {
				calls++
				if !j.seen[k] { t.Fatal("signer called before durable local commit") }
				accepted:=0
				for _,w:=range witnesses { if w.count==1 && w.tail==j.tail { accepted++ } }
				if accepted<3 { t.Fatal("signer called without durable quorum") }
				return []byte("synthetic signature"),nil
			}
			_,err=j.reservePrivateSignature(k,sign)
			if refused>=2 {
				if err==nil || calls!=0 || !j.failed { t.Fatal("provider invoked on refused quorum",err,calls) }
			} else {
				if err!=nil || calls!=1 { t.Fatal("valid authorization refused",err,calls) }
				if _,err=j.reservePrivateSignature(k,sign);err==nil||calls!=1 { t.Fatal("replayed authorization reached provider") }
			}
		})
	}
}
func TestPrivateSignatureFailureBurnsAuthorization(t *testing.T) {
	p,s,e,app:=testJournal(t)
	j,err:=openReplay(p,s,e,app)
	if err!=nil { t.Fatal(err) }
	defer j.close()
	k:=replayID("pq-proof-lab",[]byte("burn"))
	calls:=0
	sign:=func()([]byte,error){calls++;return nil,errors.New("provider failed")}
	if _,err=j.reservePrivateSignature(k,sign);err==nil||calls!=0 { t.Fatal("unanchored signing accepted") }
	id,_:=anchorID(s,e,app)
	a:=&fakeAnchor{tail:j.tail}
	if err=j.attachAnchor(a,id);err!=nil { t.Fatal(err) }
	if _,err=j.reservePrivateSignature(k,sign);err==nil||calls!=1||!j.seen[k] { t.Fatal("failed provider reservation not retained") }
	if _,err=j.reservePrivateSignature(k,sign);err==nil||calls!=1 { t.Fatal("spent challenge reused") }
}
