//go:build windows && cgo && pqopenssl

package main

import (
 "crypto/ecdh"
 "crypto/ecdsa"
 "crypto/rand"
 "crypto/sha256"
 "encoding/json"
 "math/big"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

func TestWindowsNativePossessionFourKeys(t *testing.T){
 k,e:=freshPortable();if e!=nil{t.Fatal(e)}
 kem,e:=pqGenerate("ML-KEM-768");if e!=nil{t.Fatal(e)};defer kem.close()
 dsa,e:=pqGenerate("ML-DSA-65");if e!=nil{t.Fatal(e)};defer dsa.close()
 addr,dev:="alice~"+strings.Repeat("a",32)+"@quantic","d-"+strings.Repeat("b",32)
 p,e:=pqMake(kem,dsa,addr,dev);if e!=nil{t.Fatal(e)}
 s,a:=portablePins(k)
 r:=map[string]string{"address":addr,"deviceId":dev,"signingPin":s,"encryptionPin":a,"kemPin":p.kemPin,"dsaPin":p.dsaPin,"quorumPin":strings.Repeat("c",64),"controllerPublic":b64.EncodeToString(make([]byte,32))}
 ep,e:=ecdh.P256().GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
 ct,pqs,e:=pqEncapPublic(p.kemPub);if e!=nil{t.Fatal(e)};defer clear(pqs)
 now:=time.Now().UnixMilli()
 fields:=[]any{possessionDomain,addr,dev,s,a,p.kemPin,p.dsaPin,r["quorumPin"],r["controllerPublic"],strings.Repeat("d",64),strings.Repeat("e",64),now+60000,b64.EncodeToString(ep.PublicKey().Bytes()),b64.EncodeToString(ct)}
 raw,e:=json.Marshal(fields);if e!=nil{t.Fatal(e)}
 c,e:=parsePossessionChallenge(raw,r,now);if e!=nil{t.Fatal(e)}
 if _,e=parsePossessionChallenge(raw,r,now+60000);e==nil{t.Fatal("expired challenge accepted")}
 fields[1]="wrong~"+strings.Repeat("a",32)+"@quantic"
 bad,_:=json.Marshal(fields);if _,e=parsePossessionChallenge(bad,r,now);e==nil{t.Fatal("wrong identity accepted")}
 dir:=filepath.Join(t.TempDir(),"possession")
 if e=winCreatePrivateDirectory(dir);e!=nil{t.Fatal(e)}
 reserve:=func()error{return winWritePrivate(filepath.Join(dir,"enrollment-proof.used"),[]byte(hexHash(raw)))}
 proof,e:=nativePossessionProof(raw,c,k,p,reserve);if e!=nil{t.Fatal(e)}
 if proof["challengeSha256"]!=hexHash(raw){t.Fatal("challenge digest mismatch")}
 ecs,e:=ep.ECDH(k.agreement.PublicKey());if e!=nil{t.Fatal(e)};defer clear(ecs)
 transcript:=possessionTranscript(raw,ecs,pqs);defer clear(transcript)
 digest:=sha256.Sum256(transcript)
 cs,e:=decode(proof["classicalSignature"],64,64);if e!=nil{t.Fatal(e)}
 if !ecdsa.Verify(&k.signing.PublicKey,digest[:],new(big.Int).SetBytes(cs[:32]),new(big.Int).SetBytes(cs[32:])){t.Fatal("classical signature invalid")}
 ps,e:=decode(proof["pqSignature"],3309,3309);if e!=nil{t.Fatal(e)}
 if !pqVerifyRoot(p.dsaPub,transcript,ps){t.Fatal("PQ signature invalid")}
 transcript[len(transcript)-1]^=1
 if pqVerifyRoot(p.dsaPub,transcript,ps){t.Fatal("altered possession transcript accepted")}
 if _,e=nativePossessionProof(raw,c,k,p,reserve);e==nil{t.Fatal("replayed nonce accepted")}
}
