//go:build windows && cgo && pqopenssl

package main

// Read-only private identity registry: no pointer file or global mutable
// active-account state. Only fully provisioned, ACL-validated local vaults
// are shown, and no directory is created, repaired, migrated or deleted.
import (
 "encoding/json"
 "os"
 "path/filepath"
 "regexp"
 "strings"
)
var syntheticDirectoryName=regexp.MustCompile(`^quantic-test-[0-9a-f]{16}$`)
type syntheticListed struct {
 Directory string `json:"directory"`
 Address string `json:"address"`
 DeviceID string `json:"deviceId"`
 LabOnly bool `json:"labOnly"`
 RemotelyEnrolled bool `json:"remotelyEnrolled"`
}
func listSyntheticGUIVaults(parent string)([]syntheticListed,error){
 if _,_,e:=winPathParts(parent);e!=nil{return nil,e}
 handles,e:=winLockDirectory(parent,false)
 if e!=nil{return nil,e}
 defer winClose(handles)
 rows,e:=os.ReadDir(parent)
 if e!=nil||len(rows)>4096{return nil,portableRefusal}
 results:=make([]syntheticListed,0,4)
 for _,row:=range rows{
  if !syntheticDirectoryName.MatchString(row.Name()){continue}
  // Reparse points, non-private directories and incomplete generation are not
  // considered usable. The private read always validates NTFS ACLs on every
  // parent and refuses reparse/hard-link escape.
  if !row.IsDir()||row.Type()&os.ModeSymlink!=0{continue}
  path:=filepath.Join(parent,row.Name())
  p,e:=readSyntheticGUIProfile(path)
  if e!=nil{continue}
  if !strings.HasPrefix(p.Address,"alpha~"+strings.TrimPrefix(row.Name(),"quantic-test-")){continue}
  if len(results)>=32{return nil,portableRefusal}
  results=append(results,syntheticListed{Directory:path,Address:p.Address,
   DeviceID:p.DeviceID,LabOnly:true,RemotelyEnrolled:false})
 }
 return results,nil
}
func winGUIListSyntheticVaults(args []string)error{
 if len(args)!=3||args[1]!="--gui-list-synthetic-identities-lab"{return portableRefusal}
 profiles,e:=listSyntheticGUIVaults(args[2])
 if e!=nil{return e}
 return json.NewEncoder(os.Stdout).Encode(struct{
  Status string `json:"status"`
  LabOnly bool `json:"labOnly"`
  Identities []syntheticListed `json:"identities"`
 }{Status:"local-synthetic-identities-only",LabOnly:true,Identities:profiles})
}
