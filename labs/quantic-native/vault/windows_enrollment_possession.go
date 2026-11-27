//go:build windows && cgo && pqopenssl

package main

import (
 "bytes"
 "encoding/json"
 "io"
 "os"
 "path/filepath"
 "regexp"
 "strings"
 "time"
)

var enrollmentDirectory=regexp.MustCompile(`^quantic-enroll-[0-9a-f]{16}$`)
func readPendingEnrollment(dir string)(enrollmentRequest,error){
 var r enrollmentRequest
 if !enrollmentDirectory.MatchString(filepath.Base(dir)){return r,portableRefusal}
 raw,e:=winReadPrivate(filepath.Join(dir,"enrollment-request.json"),50000);if e!=nil{return r,e}
 d:=json.NewDecoder(bytes.NewReader(raw));d.DisallowUnknownFields()
 if e=d.Decode(&r);e!=nil{return enrollmentRequest{},e}
 var trailing any;if e=d.Decode(&trailing);e!=io.EOF{return enrollmentRequest{},portableRefusal}
 c:=r.Claim
 if r.Format!="quantic-native-enrollment-request-lab/v1"||c.Format!="quantic-native-enrollment-claim-lab/v1"||
  c.Version!=1||!c.LabOnly||c.Status!="signed-claim-not-enrolled"||c.RemotelyEnrolled||c.MailAuthorized||
  !strongAddr.MatchString(c.Address)||!strongDevice.MatchString(c.DeviceID){return enrollmentRequest{},portableRefusal}
 for _,v:=range []string{r.QuorumPin,c.RootPin,c.PQRootPin,c.SigningPin,c.EncryptionPin,c.KemPin,c.DsaPin,c.ManifestDigest,c.ProfileDigest}{
  if !hashRE.MatchString(v){return enrollmentRequest{},portableRefusal}
 }
 pub,e:=decode(r.ControllerPublic,32,32);if e!=nil{return enrollmentRequest{},e}
 mark,e:=winReadPrivate(filepath.Join(dir,"lab-provisioned"),64)
 if e!=nil||string(mark)!=hexHash(pub){return enrollmentRequest{},portableRefusal}
 fp:=strings.Split(c.Address,"~")[1][:16]
 if filepath.Base(dir)!="quantic-enroll-"+fp{return enrollmentRequest{},portableRefusal}
 return r,nil
}
func windowsListEnrollmentCLI(args []string)error{
 if len(args)!=3{return portableRefusal}
 parent:=args[2]
 handles,e:=winLockDirectory(parent,false);if e!=nil{return e};defer winClose(handles)
 entries,e:=os.ReadDir(parent);if e!=nil||len(entries)>4096{return portableRefusal}
 type item struct{Directory string `json:"directory"`;Address string `json:"address"`}
 list:=make([]item,0,4)
 for _,entry:=range entries{
  if !entry.IsDir()||entry.Type()&os.ModeSymlink!=0||!enrollmentDirectory.MatchString(entry.Name()){continue}
  dir:=filepath.Join(parent,entry.Name());r,e:=readPendingEnrollment(dir);if e!=nil{continue}
  if len(list)>=32{return portableRefusal}
  list=append(list,item{dir,r.Claim.Address})
 }
 return json.NewEncoder(os.Stdout).Encode(struct{Status string `json:"status"`;Candidates []item `json:"candidates"`}{"pending-enrollment-candidates-only",list})
}
func windowsAnswerPossessionCLI(args []string)error{
 if len(args)!=4||!hashRE.MatchString(args[3]){return portableRefusal}
 dir,pin:=args[2],args[3]
 r,e:=readPendingEnrollment(dir);if e!=nil{return e}
 raw,e:=io.ReadAll(io.LimitReader(os.Stdin,16001));if e!=nil||len(raw)>16000{return portableRefusal}
 code:=string(raw)
 if !strings.HasPrefix(code,"QSPROOF1:"){return portableRefusal}
 encoded:=strings.TrimPrefix(code,"QSPROOF1:")
 data,e:=b64.DecodeString(encoded);if e!=nil||b64.EncodeToString(data)!=encoded{return portableRefusal}
 var c possessionChallenge
 d:=json.NewDecoder(bytes.NewReader(data));d.DisallowUnknownFields()
 if e=d.Decode(&c);e!=nil{return e};var trailing any;if e=d.Decode(&trailing);e!=io.EOF{return portableRefusal}
 // Reject untrusted challenge before asking for secrets.
 if _,e=validatePossessionChallenge(c,r,pin,time.Now());e!=nil{return e}
 if !winGUIApprove("PREUVE DE POSSESSION FICTIVE pour "+r.Claim.Address+" / operateur "+pin+". Aucun compte ne sera active. Autoriser cette preuve unique ?"){return portableRefusal}
 claim:=r.Claim
 pw,e:=winGUIPassphrase("Secret classique de l'appareil",true);if e!=nil{return e};defer clear(pw)
 k,e:=winReadClassical(filepath.Join(dir,"classical.vault"),anchoredMagic+"compact-manifest-quorum:"+r.QuorumPin+"\x00",pw,claim.SigningPin,claim.EncryptionPin)
 clear(pw);if e!=nil{return e}
 pub,e:=decode(r.ControllerPublic,32,32);if e!=nil{return e}
 binding,e:=pqBinding(claim.SigningPin,claim.EncryptionPin,hexHash(pub),r.QuorumPin,claim.Address,claim.DeviceID);if e!=nil{return e}
 pqw,e:=winGUIPassphrase("Secret post-quantique de l'appareil",true);if e!=nil{return e};defer clear(pqw)
 pq,e:=winReadPQ(filepath.Join(dir,"pq.vault"),binding,pqw,claim.Address,claim.DeviceID,claim.KemPin,claim.DsaPin)
 clear(pqw);if e!=nil{return e};defer pq.close()
 response,e:=answerPossessionChallenge(c,r,pin,k,pq,time.Now());if e!=nil{return e}
 proof,e:=json.Marshal(response);if e!=nil{return e}
 return json.NewEncoder(os.Stdout).Encode(struct{
  Status string `json:"status"`
  Code string `json:"code"`
  MailAuthorized bool `json:"mailAuthorized"`
 }{"device-proof-only-not-enrolled","QSPROOFREPLY1:"+b64.EncodeToString(proof),false})
}
