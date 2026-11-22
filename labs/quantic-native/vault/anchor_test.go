package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"
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

func TestAnchoredClassicalBrokerSignsOnlyAfterQuorum(t *testing.T) {
 for _,op:=range []string{"prove","enroll-proof"} {
  for _,refused:=range []bool{false,true} {
   name:=op+"/accepted";if refused{name=op+"/refused"}
   t.Run(name,func(t *testing.T){
    s,_,_:=fixture(t)
    key,err:=ecdh.P256().GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
    path,sp,ep,app:=testJournal(t)
    j,err:=openReplay(path,sp,ep,app);if err!=nil{t.Fatal(err)};defer j.close()
    id,_:=anchorID(sp,ep,app)
    q:=&quorumAnchor{}
    var ws [4]*fakeAnchor
    for i:=range ws{ws[i]=&fakeAnchor{tail:j.tail};q.members[i]=ws[i]}
    if err=j.attachAnchor(q,id);err!=nil{t.Fatal(err)}
    if refused{ws[0].fail=true;ws[1].fail=true}
    approve:=func(string)bool{return true}
    if op=="enroll-proof"{
     p:=key.PublicKey().Bytes()
     dev:=sha256.Sum256([]byte("P-256:"+b64.EncodeToString(p[1:33])+":"+b64.EncodeToString(p[33:])))
     raw,err:=json.Marshal([]any{"quantic-native-enrollment-lab-v1","alice~"+strings.Repeat("a",32)+"@quantic",strings.Repeat("b",64),1,strings.Repeat("c",64),"d-"+hex.EncodeToString(dev[:16]),publicPin(s.Public()),publicPin(key.PublicKey()),"synthetic device",strings.Repeat("d",64),time.Now().Add(20*time.Second).UnixMilli()})
     if err!=nil{t.Fatal(err)}
     body,_:=json.Marshal(request{Op:op,Enrollment:string(raw),Approved:true})
     var out bytes.Buffer
     err=serveGuarded(s,key,"test",strings.NewReader(string(body)+"\n"),&out,approve,j)
     if !refused{var r reply;if json.Unmarshal(out.Bytes(),&r)!=nil||!r.OK{t.Fatal("valid enrollment refused",out.String())}}
    }else{
     inR,inW:=io.Pipe();outR,outW:=io.Pipe();done:=make(chan error,1)
     go func(){e:=serveGuarded(s,key,"test",inR,outW,approve,j);outW.Close();inR.Close();done<-e}()
     defer inW.Close();defer outR.Close()
     enc:=json.NewEncoder(inW);dec:=json.NewDecoder(outR)
     if err=enc.Encode(request{Op:"issue"});err!=nil{t.Fatal(err)}
     var issued reply;if err=dec.Decode(&issued);err!=nil||!issued.OK||issued.Challenge==nil{t.Fatal("issue failed",err)}
     if err=enc.Encode(request{Op:op,Challenge:issued.Challenge,Approved:true});err!=nil{t.Fatal(err)}
     var r reply;readErr:=dec.Decode(&r);inW.Close();err=<-done
     if !refused&&(readErr!=nil||!r.OK||r.Proof==nil){t.Fatal("valid proof refused",readErr)}
    }
    if refused{if err==nil||s.calls!=0||!j.failed{t.Fatal("private signer reached on refused quorum",err,s.calls)}}else{
     if err!=nil||s.calls!=1||len(j.seen)!=1{t.Fatal("unexpected signer/journal result",err,s.calls)}
     for _,w:=range ws{if w.count!=1||w.tail!=j.tail{t.Fatal("witness state not committed")}}
    }
   })
  }
 }
}
