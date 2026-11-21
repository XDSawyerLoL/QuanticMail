package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
)

// A separately delivered public proof; never a source of private key material.
// One verified active sequence per process. Any new sequence requires restart
// with a new proof, and every operation still needs a fresh matching quorum.
type dualLocalProof struct { sequence int64 }
type dualProofWire struct {
	Sequence int64 `json:"sequence"`
	ClassicalRoot []byte `json:"classicalRoot"`
	PQRoot []byte `json:"pqRoot"`
	ClassicalSignature []byte `json:"classicalSignature"`
	PQSignature []byte `json:"pqSignature"`
}
func (q *freshQuorum) loadDualLocalProof(path,id string)(*dualLocalProof,error){
	if !filepath.IsAbs(path) { return nil, portableRefusal }
	if err:=checkPortableDirectory(filepath.Dir(path));err!=nil{return nil,err}
	info,e:=os.Lstat(path)
	if e!=nil||!info.Mode().IsRegular()||!privatePortableFile(info)||info.Size()>16384{return nil,portableRefusal}
	f,e:=os.Open(path);if e!=nil{return nil,e};defer f.Close()
	actual,e:=f.Stat();if e!=nil||!os.SameFile(info,actual){return nil,portableRefusal}
	raw,e:=io.ReadAll(io.LimitReader(f,16385));if e!=nil||len(raw)>16384{return nil,portableRefusal}
	var p dualProofWire
	d:=json.NewDecoder(bytes.NewReader(raw));d.DisallowUnknownFields()
	var extra any
	if d.Decode(&p)!=nil||d.Decode(&extra)!=io.EOF{return nil,portableRefusal}
	return q.verifyDualLocalProof(id,p)
}
func(q *freshQuorum)verifyDualLocalProof(id string,p dualProofWire)(*dualLocalProof,error){
	refuse:=errors.New("local dual authority proof refused")
	if !hashRE.MatchString(id)||len(p.ClassicalRoot)>256||len(p.PQRoot)!=1974||len(p.ClassicalSignature)!=64||len(p.PQSignature)!=3309||hexHash(p.PQRoot)!=q.dualRootPin{return nil,refuse}
	if _,e:=q.expectedDualDigest(p.Sequence);e!=nil{return nil,refuse}
	pub,e:=x509.ParsePKIXPublicKey(p.ClassicalRoot);if e!=nil{return nil,refuse}
	root,ok:=pub.(*ecdsa.PublicKey);if !ok||root.Curve!=elliptic.P256(){return nil,refuse}
	x,y:=root.X.FillBytes(make([]byte,32)),root.Y.FillBytes(make([]byte,32))
	fingerprint:=hexHash([]byte("P-256:"+b64.EncodeToString(x)+":"+b64.EncodeToString(y)))
	// Applies to strong 128-bit canonical addresses only. The independently
	// pinned PQ root signs the grant and checkpoint ID; classical root is
	// additionally bound by the canonical identity fingerprint.
	if q.pqAddress[len(q.pqAddress)-40:len(q.pqAddress)-8]!=fingerprint[:32]{return nil,refuse}
	canonical,e:=json.Marshal([]any{"quantic-pq-profile-lab/v1",q.pqAddress,q.pqDevice,q.pqKemPin,q.pqDsaPin,p.Sequence,true});if e!=nil{return nil,refuse}
	h:=sha256.Sum256(canonical)
	if !ecdsa.Verify(root,h[:],new(big.Int).SetBytes(p.ClassicalSignature[:32]),new(big.Int).SetBytes(p.ClassicalSignature[32:])){return nil,refuse}
	identity,_:=hex.DecodeString(id)
	message:=append([]byte("quantic-pq-dual-authority-lab/v1\x00"),identity...)
	message=append(message,canonical...)
	if !pqVerifyRoot(p.PQRoot,message,p.PQSignature){return nil,refuse}
	return &dualLocalProof{sequence:p.Sequence},nil
}
