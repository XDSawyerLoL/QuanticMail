//go:build (linux || windows) && cgo && pqopenssl

package main

import (
 "bufio"
 "os/exec"
 "path/filepath"
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
 if os.Getenv("QUANTIC_ENROLLMENT_PROOF_INTEROP")=="1"{
  checkNativePossessionInterop(t,request,device,p)
 }
 // The optional file contains PUBLIC data exclusively, for the independent
 // Node compatibility test. The test fixture has no live authority or account.
 if dst:=os.Getenv("QUANTIC_ENROLLMENT_TEST_OUTPUT");dst!=""{
  if e=os.WriteFile(dst,raw,0600);e!=nil{t.Fatal(e)}
 }
}

func checkNativePossessionInterop(t *testing.T,r enrollmentRequest,k portableKeys,p *pqKeys){
 t.Helper()
 driver,err:=filepath.Abs("../../../tests/helpers/native-enrollment-possession-driver.mjs");if err!=nil{t.Fatal(err)}
 cmd:=exec.Command("node","--experimental-transform-types",driver)
 in,err:=cmd.StdinPipe();if err!=nil{t.Fatal(err)}
 out,err:=cmd.StdoutPipe();if err!=nil{t.Fatal(err)}
 cmd.Stderr=os.Stderr
 if err=cmd.Start();err!=nil{t.Fatal(err)}
 defer func(){_ = in.Close();if cmd.Process!=nil{_ = cmd.Process.Kill()}}()
 enc:=json.NewEncoder(in);reader:=bufio.NewReader(out)
 if err=enc.Encode(r);err!=nil{t.Fatal(err)}
 raw,err:=reader.ReadBytes('\n');if err!=nil{t.Fatal(err)}
 var reply struct{Challenge possessionChallenge `json:"challenge"`;OperatorPin string `json:"operatorPin"`}
 if err=json.Unmarshal(raw,&reply);err!=nil{t.Fatal(err)}
 c:=reply.Challenge
 now:=time.Now()
 if _,err=answerPossessionChallenge(c,r,strings.Repeat("d",64),k,p,now);err==nil{t.Fatal("untrusted operator accepted")}
 if _,err=answerPossessionChallenge(c,r,reply.OperatorPin,k,p,time.UnixMilli(c.Expires));err==nil{t.Fatal("expired challenge accepted")}
 bad:=c;bad.Nonce=strings.Repeat("a",64)
 if _,err=answerPossessionChallenge(bad,r,reply.OperatorPin,k,p,now);err==nil{t.Fatal("mutated nonce accepted")}
 bad=c;bad.Envelope.Ciphertext=strings.Repeat("A",64)
 if _,err=answerPossessionChallenge(bad,r,reply.OperatorPin,k,p,now);err==nil{t.Fatal("mutated ciphertext accepted")}
 proof,err:=answerPossessionChallenge(c,r,reply.OperatorPin,k,p,now);if err!=nil{t.Fatal(err)}
 if err=enc.Encode(proof);err!=nil{t.Fatal(err)}
 if err=in.Close();err!=nil{t.Fatal(err)}
 result,err:=reader.ReadBytes('\n');if err!=nil{t.Fatal(err)}
 var report struct{Status string `json:"status"`;MailAuthorized bool `json:"mailAuthorized"`;RemotelyEnrolled bool `json:"remotelyEnrolled"`}
 if err=json.Unmarshal(result,&report);err!=nil||report.Status!="device-possession-verified-pending-authority-renewal"||report.MailAuthorized||report.RemotelyEnrolled{t.Fatal("invalid authority proof result",err)}
 if err=cmd.Wait();err!=nil{t.Fatal(err)}
}
