//go:build (linux || windows) && cgo && pqopenssl

package main

import (
 "crypto/ecdsa"
 "crypto/ed25519"
 "crypto/elliptic"
 "crypto/rand"
 "encoding/json"
 "os"
 "strings"
 "testing"
 "time"
)

func TestNativeEnrollmentClaimInterop(t *testing.T){
 owner,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if e!=nil{t.Fatal(e)}
 root,e:=pqGenerate("ML-DSA-65");if e!=nil{t.Fatal(e)};defer root.close()
 device,e:=freshPortable();if e!=nil{t.Fatal(e)}
 j,e:=enrollmentPoint(elliptic.Marshal(elliptic.P256(),owner.X,owner.Y));if e!=nil{t.Fatal(e)}
 enc,e:=enrollmentPoint(device.agreement.PublicKey().Bytes());if e!=nil{t.Fatal(e)}
 addr:="testalice~"+enrollmentFingerprint(j)+"@quantic"
 id:="d-"+enrollmentFingerprint(enc)
 kem,e:=pqGenerate("ML-KEM-768");if e!=nil{t.Fatal(e)};defer kem.close()
 dsa,e:=pqGenerate("ML-DSA-65");if e!=nil{t.Fatal(e)};defer dsa.close()
 p,e:=pqMake(kem,dsa,addr,id);if e!=nil{t.Fatal(e)}
 claim,e:=nativeEnrollmentClaim("testalice",owner,device,p,root,time.Now());if e!=nil{t.Fatal(e)}
 if claim.Address!=addr||claim.DeviceID!=id||claim.RootPin==claim.SigningPin||
  claim.PQRootPin==claim.DsaPin||claim.MailAuthorized||claim.RemotelyEnrolled{t.Fatal("unsafe claim")}
 if _,e=nativeEnrollmentClaim("testalice",device.signing,device,p,root,time.Now());e==nil{t.Fatal("owner/device alias accepted")}
 if _,e=nativeEnrollmentClaim("testalice",owner,device,p,dsa,time.Now());e==nil{t.Fatal("PQ owner/device alias accepted")}
 if _,e=nativeEnrollmentClaim("otheruser",owner,device,p,root,time.Now());e==nil{t.Fatal("wrong identity binding accepted")}
 pw:=[]byte("synthetic-only separate owner secret")
 sealed,e:=sealEnrollmentRoots(owner,root,claim,pw);if e!=nil{t.Fatal(e)}
 if e=verifySealedEnrollmentRoots(sealed,claim,pw);e!=nil{t.Fatal(e)}
 if e=verifySealedEnrollmentRoots(sealed,claim,[]byte("synthetic incorrect owner passphrase"));e==nil{t.Fatal("wrong password accepted")}
 sealed[len(sealed)-1]^=1
 if e=verifySealedEnrollmentRoots(sealed,claim,pw);e==nil{t.Fatal("altered owner key archive accepted")}
 pub,private,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)};defer clear(private)
 request,e:=signEnrollmentRequest(claim,strings.Repeat("c",64),b64.EncodeToString(pub),owner,root);if e!=nil{t.Fatal(e)}
 raw,e:=json.Marshal(request);if e!=nil{t.Fatal(e)}
 // The optional file contains PUBLIC data exclusively, for the independent
 // Node compatibility test. The test fixture has no live authority or account.
 if dst:=os.Getenv("QUANTIC_ENROLLMENT_TEST_OUTPUT");dst!=""{
  if e=os.WriteFile(dst,raw,0600);e!=nil{t.Fatal(e)}
 }
}
