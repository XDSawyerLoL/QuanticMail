//go:build windows && cgo && pqopenssl

package main

import (
 "encoding/json"
 "os"
 "path/filepath"
 "regexp"
 "sort"
)

var mailLabFile = regexp.MustCompile("^(draft|wire)-([a-f0-9]{32})[.]json$")
type mailLabItem struct{
 ID string `json:"id"`
 Draft bool `json:"draft"`
 Wire bool `json:"wire"`
}
type mailLabInventory struct{
 Status string `json:"status"`
 DeliveryVerified bool `json:"deliveryVerified"`
 Items []mailLabItem `json:"items"`
}
// Read-only, native-owned inventory. The presence of a wire is NEVER evidence
// of relay ACK, delivery, a verified signature, or a readable remote message.
// No private content or filenames are returned through the UI.
func winMailLabInventory(dir string)(mailLabInventory,error){
 out:=mailLabInventory{Status:"local-files-only-unverified",Items:[]mailLabItem{}}
 hs,e:=winLockDirectory(dir,true)
 if e!=nil{return out,e}
 defer winClose(hs)
 entries,e:=os.ReadDir(dir)
 if e!=nil||len(entries)>512{return out,windowsStorageRefusal}
 pairs:=make(map[string]*mailLabItem)
 for _,entry:=range entries{
  matches:=mailLabFile.FindStringSubmatch(entry.Name())
  if len(matches)==0{continue}
  if entry.IsDir(){return out,windowsStorageRefusal}
  // Validate file handles with the same strict NTFS ACL and hardlink checks.
  path:=filepath.Join(dir,entry.Name())
  limit:=32768
  if matches[1]=="draft"{limit=16384}
  var raw []byte
  if matches[1]=="draft"{raw,e=winReadEncryptedDraft(path)}else{raw,e=winReadPrivate(path,limit)}
  if e!=nil{return out,e}
  if matches[1]=="wire"{
   var record struct{
    Format string `json:"format"`
    Version int `json:"version"`
   }
   e=json.Unmarshal(raw,&record)
   if e!=nil||record.Format!="quantic-native-mail"||record.Version!=1{
    clear(raw);return out,portableRefusal
   }
  }
  clear(raw)
  item:=pairs[matches[2]]
  if item==nil{
   if len(pairs)>=64{return out,portableRefusal}
   item=&mailLabItem{ID:matches[2]}
   pairs[matches[2]]=item
  }
  if matches[1]=="draft"{item.Draft=true}else{item.Wire=true}
 }
 keys:=make([]string,0,len(pairs))
 for key:=range pairs{keys=append(keys,key)}
 sort.Strings(keys)
 for _,key:=range keys{out.Items=append(out.Items,*pairs[key])}
 return out,nil
}
func winMailLabStatus(args []string)(bool,error){
 if len(args)<2||args[1]!="--windows-client-mail-status-lab"{return false,nil}
 if len(args)!=3{return true,portableRefusal}
 status,e:=winMailLabInventory(args[2])
 if e!=nil{return true,e}
 return true,json.NewEncoder(os.Stdout).Encode(status)
}
