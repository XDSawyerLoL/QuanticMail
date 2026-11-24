//go:build (linux || windows) && cgo && pqopenssl

package main

import (
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/x509"
 "encoding/json"
 "sort"
 "strings"
 "testing"
 "time"
)
func credentialTestApprovals(t *testing.T,r enrollmentRequest,now time.Time)(enrollmentApprovalBundle,string){
 t.Helper()
 digest,e:=nativeEnrollmentDigest(r);if e!=nil{t.Fatal(e)}
 b:=enrollmentApprovalBundle{Format:"quantic-enrollment-approvals-lab/v1"}
 var keys []ed25519.PrivateKey
 var pins []string
 for i:=0;i<4;i++{
  pub,key,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
  der,e:=x509.MarshalPKIXPublicKey(pub);if e!=nil{t.Fatal(e)}
  pin:=hexHash(der);keys=append(keys,key);pins=append(pins,pin)
  b.Trusted=append(b.Trusted,enrollmentRosterEntry{pin,b64.EncodeToString(der)})
 }
 sort.Strings(pins);raw,_:=json.Marshal(append([]string{"quantic-enrollment-roster-lab/v1","3-of-4"},pins...));pin:=hexHash(raw)
 for i:=0;i<3;i++{
  v:=enrollmentVotePayload{"quantic-native-enrollment-vote-lab/v1",b.Trusted[i].Pin,pin,digest,hexHash([]byte{byte(i)}),now.UnixMilli(),now.UnixMilli()+900000,"approve"}
  raw,e:=nativeEnrollmentVoteTranscript(v);if e!=nil{t.Fatal(e)}
  b.Votes=append(b.Votes,enrollmentVote{v,b64.EncodeToString(ed25519.Sign(keys[i],raw))})
 }
 for _,k:=range keys{clear(k)}
 return b,pin
}
func TestNativeMailboxCredentialSeal(t *testing.T){
 pw,pqw:=[]byte("synthetic classical password 123"),[]byte("synthetic postquantum password 456")
 token:=make([]byte,32);if _,e:=rand.Read(token);e!=nil{t.Fatal(e)}
 digest:=strings.Repeat("a",64)
 raw,e:=sealNativeMailboxCredential(token,digest,pw,pqw);if e!=nil{t.Fatal(e)}
 if bytes.Contains(raw,token){t.Fatal("plaintext persisted")}
 opened,e:=openNativeMailboxCredential(raw,digest,pw,pqw);if e!=nil||!bytes.Equal(opened,token){t.Fatal("reopen failed",e)}
 if _,e=openNativeMailboxCredential(raw,digest,pw,pw);e==nil{t.Fatal("reused secret accepted")}
 if _,e=openNativeMailboxCredential(raw,digest,pqw,pw);e==nil{t.Fatal("swapped secrets accepted")}
 if _,e=openNativeMailboxCredential(raw,strings.Repeat("b",64),pw,pqw);e==nil{t.Fatal("wrong identity accepted")}
 raw[len(raw)-1]^=1
 if _,e=openNativeMailboxCredential(raw,digest,pw,pqw);e==nil{t.Fatal("tampering accepted")}
}
