//go:build windows && cgo && pqopenssl

package main

import (
 "io"
 "os"
 "path/filepath"
 "regexp"
)

// Explicit local helper for the trusted Node desktop process, not a web API.
// It accepts only designated client files inside the private vault directory.
// Same-Windows-user processes are in the trusted OS boundary.
var clientFileName=regexp.MustCompile("^(scattering[.]json|desktop[.]json|controller[.]pem|contacts[.]json|peer-[a-z0-9-]{1,48}[.]pem|draft-[a-z0-9-]{1,48}[.]json|wire-[a-z0-9-]{1,48}[.]json)$")
var clientWireName=regexp.MustCompile("^wire-[a-z0-9-]{1,48}[.]json$")
func winClientIO(args []string)(bool,error){
 if len(args)<2||(args[1]!="--windows-client-read-lab"&&args[1]!="--windows-client-write-wire-lab"){return false,nil}
 if len(args)!=4||!clientFileName.MatchString(args[3]){return true,portableRefusal}
 dir,name:=args[2],args[3]
 if _,_,e:=winPathParts(dir);e!=nil{return true,e}
 path:=filepath.Join(dir,name)
 if args[1]=="--windows-client-read-lab"{
  data,e:=winReadPrivate(path,131072);if e!=nil{return true,e};defer clear(data)
  n,e:=os.Stdout.Write(data);if e==nil&&n!=len(data){e=io.ErrShortWrite};return true,e
 }
 if !clientWireName.MatchString(name){return true,portableRefusal}
 b,e:=io.ReadAll(io.LimitReader(os.Stdin,32769));if e!=nil{return true,e};defer clear(b)
 if len(b)<1||len(b)>32768{return true,portableRefusal}
 return true,winWritePrivate(path,b)
}
