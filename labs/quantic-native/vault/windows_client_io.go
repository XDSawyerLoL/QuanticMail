//go:build windows && cgo && pqopenssl

package main

import (
 "io"
 "encoding/json"
 "encoding/base64"
 "bytes"
 "os"
 "path/filepath"
 "regexp"
)

// Explicit local helper for the trusted Node desktop process, not a web API.
// It accepts only designated client files inside the private vault directory.
// Same-Windows-user processes are in the trusted OS boundary.
var clientFileName=regexp.MustCompile("^(scattering[.]json|desktop[.]json|controller[.]pem|contacts[.]json|peer-[a-z0-9-]{1,48}[.]pem|draft-[a-z0-9-]{1,48}[.]json|wire-[a-z0-9-]{1,48}[.]json|receipt[.]key|receipt-[a-z0-9-]{1,48}[.]json)$")
var clientDraftName=regexp.MustCompile("^(draft)-[a-z0-9-]{1,48}[.]json$")
type clientEncryptedDraft struct {
 Format string `json:"format"`
 Nonce string `json:"nonce"`
 Ciphertext string `json:"ciphertext"`
}
func validEncryptedClientDraft(b []byte)bool{
 var d clientEncryptedDraft
 dec:=json.NewDecoder(bytes.NewReader(b));dec.DisallowUnknownFields()
 if e:=dec.Decode(&d);e!=nil||d.Format!="quantic-local-draft-v1"{return false}
 var extra any;if dec.Decode(&extra)!=io.EOF{return false}
 n,e:=base64.RawURLEncoding.DecodeString(d.Nonce);if e!=nil||len(n)!=12||base64.RawURLEncoding.EncodeToString(n)!=d.Nonce{return false}
 c,e:=base64.RawURLEncoding.DecodeString(d.Ciphertext)
 return e==nil&&len(c)>=17&&len(c)<=32768&&base64.RawURLEncoding.EncodeToString(c)==d.Ciphertext
}
var clientWireName=regexp.MustCompile("^(wire|receipt)-[a-z0-9-]{1,48}[.]json$")
func winClientIO(args []string)(bool,error){
 if len(args)<2||(args[1]!="--windows-client-read-lab"&&args[1]!="--windows-client-write-wire-lab"&&args[1]!="--windows-client-write-draft-lab"){return false,nil}
 if len(args)!=4||!clientFileName.MatchString(args[3]){return true,portableRefusal}
 dir,name:=args[2],args[3]
 if _,_,e:=winPathParts(dir);e!=nil{return true,e}
 path:=filepath.Join(dir,name)
 if args[1]=="--windows-client-read-lab"{
  data,e:=winReadPrivate(path,131072);if e!=nil{return true,e};defer clear(data)
  n,e:=os.Stdout.Write(data);if e==nil&&n!=len(data){e=io.ErrShortWrite};return true,e
 }
 draft:=args[1]=="--windows-client-write-draft-lab"
 if draft&&!clientDraftName.MatchString(name)||!draft&&!clientWireName.MatchString(name){return true,portableRefusal}
 b,e:=io.ReadAll(io.LimitReader(os.Stdin,32769));if e!=nil{return true,e};defer clear(b)
 if len(b)<1||len(b)>32768||draft&&!validEncryptedClientDraft(b){return true,portableRefusal}
 return true,winWritePrivate(path,b)
}
