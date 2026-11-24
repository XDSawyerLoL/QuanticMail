//go:build windows && cgo && pqopenssl

package main

import (
 "io"
 "bytes"
 "crypto/ed25519"
 "crypto/x509"
 "encoding/pem"
 "encoding/binary"
 "encoding/json"
 "os"
 "path/filepath"
 "regexp"
)

// Explicit local helper for the trusted Node desktop process, not a web API.
// It accepts only designated client files inside the private vault directory.
// Same-Windows-user processes are in the trusted OS boundary.
var clientFileName=regexp.MustCompile("^(scattering[.]json|desktop[.]json|controller[.]pem|contacts[.]json|peer-[a-z0-9-]{1,48}[.]pem|draft-[a-z0-9-]{1,48}[.]json|wire-[a-z0-9-]{1,48}[.]json|receipt[.]key|receipt-[a-z0-9-]{1,48}[.]json)$")
var clientDraftName=regexp.MustCompile("^draft-[a-z0-9-]{1,48}[.]json$")
var clientWireName=regexp.MustCompile("^(wire|receipt)-[a-z0-9-]{1,48}[.]json$")
// Component custody only: not isolation from arbitrary same-user code.
func winControllerKey(dir string)(ed25519.PrivateKey,error){
 raw,e:=winReadLocalSecret(filepath.Join(dir,"controller.pem"));if e!=nil{return nil,e};defer clear(raw)
 block,rest:=pem.Decode(raw)
 if block==nil{return nil,portableRefusal};defer clear(block.Bytes)
 if block.Type!="PRIVATE KEY"||len(bytes.TrimSpace(rest))!=0{return nil,portableRefusal}
 value,e:=x509.ParsePKCS8PrivateKey(block.Bytes);if e!=nil{return nil,portableRefusal}
 key,ok:=value.(ed25519.PrivateKey);if !ok{return nil,portableRefusal}
 marker,e:=winReadPrivate(filepath.Join(dir,"lab-provisioned"),64)
 if e!=nil||string(marker)!=hexHash(key.Public().(ed25519.PublicKey)){clear(key);return nil,portableRefusal}
 return key,nil
}
func winControllerFrameSign(dir string,input []byte)([]byte,error){
 if len(input)<37||len(input)>36+32767{return nil,portableRefusal}
 seq:=binary.BigEndian.Uint32(input[32:36])
 body:=input[36:]
 if seq<1||seq>maxOps||bytes.ContainsAny(body,"\r\n"){return nil,portableRefusal}
 var q request
 dec:=json.NewDecoder(bytes.NewReader(body));dec.DisallowUnknownFields()
 var extra any
 if dec.Decode(&q)!=nil||dec.Decode(&extra)!=io.EOF{return nil,portableRefusal}
 switch q.Op{
 case "public","session-proof-lab","pq-public-lab","mail-seal-hybrid-lab","mail-open-hybrid-lab","enroll-proof","close":
 default:return nil,portableRefusal
 }
 key,e:=winControllerKey(dir);if e!=nil{return nil,e};defer clear(key)
 digest:=appDigest(input[:32],seq,body)
 return ed25519.Sign(key,digest[:]),nil
}
func winClientIO(args []string)(bool,error){
 if len(args)>1&&(args[1]=="--windows-controller-public-lab"||args[1]=="--windows-controller-sign-frame-lab"){
  if len(args)!=4||args[3]!="controller.pem"{return true,portableRefusal}
  var result []byte
  if args[1]=="--windows-controller-public-lab"{
   key,e:=winControllerKey(args[2]);if e!=nil{return true,e};defer clear(key)
   result=key.Public().(ed25519.PublicKey)
  }else{
   input,e:=io.ReadAll(io.LimitReader(os.Stdin,36+32768));if e!=nil{return true,e};defer clear(input)
   result,e=winControllerFrameSign(args[2],input);if e!=nil{return true,e}
  }
  defer clear(result)
  n,e:=os.Stdout.Write(result);if e==nil&&n!=len(result){e=io.ErrShortWrite};return true,e
 }
 if len(args)<2||(args[1]!="--windows-client-read-lab"&&args[1]!="--windows-client-write-wire-lab"&&args[1]!="--windows-client-write-draft-lab"){return false,nil}
 if len(args)!=4||!clientFileName.MatchString(args[3]){return true,portableRefusal}
 dir,name:=args[2],args[3]
 if _,_,e:=winPathParts(dir);e!=nil{return true,e}
 path:=filepath.Join(dir,name)
 if args[1]=="--windows-client-read-lab"{
  if name=="controller.pem"{return true,portableRefusal}
  var data []byte;var e error
  if clientDraftName.MatchString(name){data,e=winReadProtectedDraft(path)}else if winLocalSecretName(name){data,e=winReadLocalSecret(path)}else{data,e=winReadPrivate(path,131072)}
  if e!=nil{return true,e};defer clear(data)
  n,e:=os.Stdout.Write(data);if e==nil&&n!=len(data){e=io.ErrShortWrite};return true,e
 }
 if args[1]=="--windows-client-write-draft-lab"{
  if !clientDraftName.MatchString(name){return true,portableRefusal}
 }else if !clientWireName.MatchString(name){return true,portableRefusal}
 b,e:=io.ReadAll(io.LimitReader(os.Stdin,32769));if e!=nil{return true,e};defer clear(b)
 if len(b)<1||len(b)>32768{return true,portableRefusal}
 if clientDraftName.MatchString(name){return true,winWriteProtectedDraft(path,b)}
 return true,winWritePrivate(path,b)
}
