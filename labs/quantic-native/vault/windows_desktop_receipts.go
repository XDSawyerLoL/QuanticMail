//go:build windows && cgo && pqopenssl

package main

import (
 "encoding/json"
 "io"
 "os"
 "path/filepath"
 "regexp"
 "strings"
 "unicode"
)

// Read only authenticated receipts of the current enrolled device. No
// acknowledgement, network access, file mutation or delivery inference.
var desktopReceiptName=regexp.MustCompile("^receipt-([a-f0-9]{32})[.]json$")
const desktopReceiptLimit=64
type desktopReceipt struct {
 ID string `json:"id"`
 Subject string `json:"subject"`
 Body string `json:"body,omitempty"`
}
func cleanReceiptSubject(s string)string{
 s=strings.Map(func(r rune)rune{if unicode.IsControl(r)||unicode.In(r,unicode.Cf){return ' '};return r},s)
 r:=[]rune(strings.TrimSpace(s));if len(r)>120{r=r[:120]}
 return string(r)
}
func readDesktopReceipt(dir,id string,r enrollmentRequest,key []byte)(desktopReceipt,string,error){
 var empty desktopReceipt
 if !documentID.MatchString(id)||len(key)!=32{return empty,"",portableRefusal}
 raw,e:=winReadPrivate(filepath.Join(dir,"receipt-"+id+".json"),24000);if e!=nil{return empty,"",e}
 var sealed nativeReceipt
 if e=exactReceiptDecode(raw,&sealed);e!=nil{return empty,"",e}
 // Reuse the existing authenticated receipt parser and AEAD binding.
 op,closeOp,e:=nativeReceiptTransport(r.Claim.Address,r.Claim.DeviceID,key)
 if e!=nil{return empty,"",e};defer closeOp()
 plain,e:=op("receipt-open",raw);if e!=nil{return empty,"",e};defer clear(plain)
 var decoded struct{
  ID string `json:"id"`
  Digest string `json:"digest"`
  Payload nativeReceiptPayload `json:"payload"`
 }
 if e=exactReceiptDecode(plain,&decoded);e!=nil{return empty,"",e}
 if decoded.ID!=sealed.ID||decoded.Digest!=sealed.Digest||len(decoded.Payload.Body)>8192||len(decoded.Payload.Subject)>1024{return empty,"",portableRefusal}
 return desktopReceipt{id,cleanReceiptSubject(decoded.Payload.Subject),decoded.Payload.Body},decoded.ID,nil
}
func executeDesktopReceipt(op,dir string,r enrollmentRequest,key []byte,req documentRequest,out io.Writer)error{
 if len(key)!=32||req.Path!=""||len(req.Paths)!=0{return portableRefusal}
 hs,e:=winLockDirectory(dir,true);if e!=nil{return e};defer winClose(hs)
 enc:=json.NewEncoder(out)
 switch op{
 case "mail-list":
  if req.ID!=""{return portableRefusal}
  entries,e:=os.ReadDir(dir);if e!=nil||len(entries)>4096{return portableRefusal}
  rows:=[]desktopReceipt{};seen:=map[string]bool{};skipped:=0;truncated:=false;examined:=0
  for _,entry:=range entries{
   match:=desktopReceiptName.FindStringSubmatch(entry.Name())
   if match==nil{continue}
   if examined>=desktopReceiptLimit{truncated=true;break};examined++
   item,messageID,e:=readDesktopReceipt(dir,match[1],r,key)
   if e!=nil||seen[messageID]{skipped++;continue}
   seen[messageID]=true;item.Body="";rows=append(rows,item)
  }
  return enc.Encode(map[string]any{"labOnly":true,"status":"mail-listed","messages":rows,"unverified":skipped,"truncated":truncated})
 case "mail-open":
  if !documentID.MatchString(req.ID){return portableRefusal}
  item,_,e:=readDesktopReceipt(dir,req.ID,r,key);if e!=nil{return e}
  return enc.Encode(map[string]any{"labOnly":true,"status":"mail-opened","message":item})
 }
 return portableRefusal
}
