//go:build windows && cgo && pqopenssl

package main

import (
 "bytes"
 "crypto/hmac"
 "crypto/rand"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "io"
 "os"
 "path/filepath"
 "regexp"
 "strings"
 "syscall"
)

const documentMax=65536
const documentRecordMax=100000
const documentLimit=32
const documentMagic="QSDOC1"
var documentID=regexp.MustCompile("^[0-9a-f]{32}$")
type documentPayload struct {
 Name string `json:"name"`
 Data []byte `json:"data"`
}
type documentEntry struct {
 ID string `json:"id"`
 Name string `json:"name"`
 Size int `json:"size"`
}
type documentRequest struct {
 Path string `json:"path"`
 ID string `json:"id"`
}
func documentNameOK(name string)bool{
 if len(name)<1||len(name)>100||filepath.Base(name)!=name{return false}
 _,_,e:=winPathParts("C:\\fixture\\"+name);return e==nil
}
func documentKey(draftKey []byte,r enrollmentRequest)([]byte,error){
 if len(draftKey)!=32{return nil,portableRefusal}
 digest,e:=nativeEnrollmentDigest(r);if e!=nil{return nil,e}
 h:=hmac.New(sha256.New,draftKey)
 h.Write([]byte("quantic-document-key/v1\x00"+digest))
 return h.Sum(nil),nil
}
func documentAAD(address,device,id string)[]byte{
 b,_:=json.Marshal([]string{"quantic-document/v1",address,device,id});return b
}
func sealDocument(key []byte,address,device,id string,p documentPayload)([]byte,error){
 if !documentID.MatchString(id)||!documentNameOK(p.Name)||len(p.Data)==0||len(p.Data)>documentMax{return nil,portableRefusal}
 g,e:=nativeReceiptCipher(key);if e!=nil{return nil,e}
 raw,e:=json.Marshal(p);if e!=nil{return nil,e};defer clear(raw)
 nonce:=make([]byte,g.NonceSize());if _,e=rand.Read(nonce);e!=nil{return nil,e}
 out:=append([]byte(documentMagic),nonce...)
 return g.Seal(out,nonce,raw,documentAAD(address,device,id)),nil
}
func openDocument(key []byte,address,device,id string,record []byte)(documentPayload,error){
 var p documentPayload
 if !documentID.MatchString(id)||len(record)>documentRecordMax||!bytes.HasPrefix(record,[]byte(documentMagic)){return p,portableRefusal}
 g,e:=nativeReceiptCipher(key);if e!=nil{return p,e}
 off:=len(documentMagic)+g.NonceSize()
 if len(record)<off+g.Overhead(){return p,portableRefusal}
 raw,e:=g.Open(nil,record[len(documentMagic):off],record[off:],documentAAD(address,device,id));if e!=nil{return p,portableRefusal};defer clear(raw)
 dec:=json.NewDecoder(bytes.NewReader(raw));dec.DisallowUnknownFields()
 var extra any
 if dec.Decode(&p)!=nil||dec.Decode(&extra)!=io.EOF||!documentNameOK(p.Name)||len(p.Data)==0||len(p.Data)>documentMax{clear(p.Data);return documentPayload{},portableRefusal}
 return p,nil
}
// Hold parent directories and source handle against ordinary replacement.
// Only canonical local NTFS paths, no reparse points, hardlinks or devices.
func readDocumentSource(path string)(documentPayload,error){
 var p documentPayload
 if !documentNameOK(filepath.Base(path)){return p,portableRefusal}
 if _,_,e:=winPathParts(path);e!=nil{return p,e}
 hs,e:=winLockDirectory(filepath.Dir(path),false);if e!=nil{return p,e};defer winClose(hs)
 ptr,e:=syscall.UTF16PtrFromString(path);if e!=nil{return p,e}
 h,e:=syscall.CreateFile(ptr,syscall.GENERIC_READ,syscall.FILE_SHARE_READ,nil,syscall.OPEN_EXISTING,0x00200000,0);if e!=nil{return p,e}
 f:=os.NewFile(uintptr(h),path);if f==nil{syscall.CloseHandle(h);return p,portableRefusal};defer f.Close()
 var info syscall.ByHandleFileInformation
 kind,e:=syscall.GetFileType(h)
 if e!=nil||kind!=syscall.FILE_TYPE_DISK||syscall.GetFileInformationByHandle(h,&info)!=nil||info.FileAttributes&(0x10|0x400)!=0||info.NumberOfLinks!=1||info.FileSizeHigh!=0||info.FileSizeLow==0||info.FileSizeLow>documentMax{return p,portableRefusal}
 raw,e:=io.ReadAll(io.LimitReader(f,documentMax+1));if e!=nil||len(raw)!=int(info.FileSizeLow){clear(raw);return p,portableRefusal}
 return documentPayload{filepath.Base(path),raw},nil
}
func documentFile(dir,id string)string{return filepath.Join(dir,"document-"+id+".qdoc")}
func documentIDs(dir string)([]string,error){
 entries,e:=os.ReadDir(dir);if e!=nil{return nil,e}
 ids:=[]string{}
 for _,x:=range entries{
  name:=x.Name()
  if !strings.HasPrefix(name,"document-")||!strings.HasSuffix(name,".qdoc"){continue}
  id:=strings.TrimSuffix(strings.TrimPrefix(name,"document-"),".qdoc")
  if !documentID.MatchString(id)||len(ids)>=documentLimit{return nil,portableRefusal}
  ids=append(ids,id)
 }
 return ids,nil
}
func readDocument(dir,id string,key []byte,r enrollmentRequest)(documentPayload,error){
 if !documentID.MatchString(id){return documentPayload{},portableRefusal}
 raw,e:=winReadPrivate(documentFile(dir,id),documentRecordMax);if e!=nil{return documentPayload{},e}
 return openDocument(key,r.Claim.Address,r.Claim.DeviceID,id,raw)
}
func addDocument(dir string,key []byte,r enrollmentRequest,p documentPayload)(documentEntry,error){
 ids,e:=documentIDs(dir);if e!=nil||len(ids)>=documentLimit{return documentEntry{},portableRefusal}
 var token [16]byte;if _,e=rand.Read(token[:]);e!=nil{return documentEntry{},e};id:=hex.EncodeToString(token[:])
 record,e:=sealDocument(key,r.Claim.Address,r.Claim.DeviceID,id,p);if e!=nil{return documentEntry{},e}
 if e=winWritePrivate(documentFile(dir,id),record);e!=nil{return documentEntry{},e}
 check,e:=readDocument(dir,id,key,r);if e!=nil{return documentEntry{},e};defer clear(check.Data)
 if check.Name!=p.Name||!bytes.Equal(check.Data,p.Data){return documentEntry{},portableRefusal}
 return documentEntry{id,p.Name,len(p.Data)},nil
}
func exportDocument(parent,id string,p documentPayload)(string,error){
 if !documentID.MatchString(id)||!documentNameOK(p.Name){return "",portableRefusal}
 // New private folder only; never overwrite or open the recovered file.
 dir:=filepath.Join(parent,"quantic-export-"+id[:16])
 if e:=winCreatePrivateDirectory(dir);e!=nil{return "",e}
 dest:=filepath.Join(dir,p.Name)
 if e:=winWritePrivate(dest,p.Data);e!=nil{return "",e}
 raw,e:=winReadPrivate(dest,documentMax);if e!=nil{return "",e};defer clear(raw)
 if !bytes.Equal(raw,p.Data){return "",portableRefusal}
 return dir,nil
}
func windowsDocumentCLI(args []string)error{
 if len(args)!=3{return portableRefusal}
 op,dir:=args[1],args[2]
 if op!="--gui-document-list-lab"&&op!="--gui-document-import-lab"&&op!="--gui-document-export-lab"{return portableRefusal}
 r,e:=readPendingEnrollment(dir);if e!=nil{return e}
 raw,e:=io.ReadAll(io.LimitReader(os.Stdin,4097));if e!=nil||len(raw)>4096{return portableRefusal}
 var req documentRequest
 if e=exactReceiptDecode(raw,&req);e!=nil{return e}
 switch op{
 case "--gui-document-list-lab":if req.Path!=""||req.ID!=""{return portableRefusal}
 case "--gui-document-import-lab":if req.Path==""||req.ID!=""{return portableRefusal}
 case "--gui-document-export-lab":if req.Path==""||!documentID.MatchString(req.ID){return portableRefusal}
 }
 if !winGUIApprove("Coffre documentaire de laboratoire. Autoriser cette operation locale ? Aucun transfert reseau."){return portableRefusal}
 pw,e:=winGUIPassphrase("Secret classique de l'appareil",true);if e!=nil{return e};defer clear(pw)
 pqw,e:=winGUIPassphrase("Secret post-quantique de l'appareil",true);if e!=nil{return e};defer clear(pqw)
 draft,e:=readLocalCustody(dir,"draft",r,pw,pqw);if e!=nil{return e};defer clear(draft)
 key,e:=documentKey(draft,r);if e!=nil{return e};defer clear(key)
 hs,e:=winLockDirectory(dir,true);if e!=nil{return e};defer winClose(hs)
 switch op{
 case "--gui-document-import-lab":
  p,e:=readDocumentSource(req.Path);if e!=nil{return e};defer clear(p.Data)
  entry,e:=addDocument(dir,key,r,p);if e!=nil{return e}
  return json.NewEncoder(os.Stdout).Encode(map[string]any{"labOnly":true,"status":"imported","document":entry})
 case "--gui-document-list-lab":
  ids,e:=documentIDs(dir);if e!=nil{return e};entries:=[]documentEntry{}
  for _,id:=range ids{
   p,e:=readDocument(dir,id,key,r);if e!=nil{return e}
   entries=append(entries,documentEntry{id,p.Name,len(p.Data)});clear(p.Data)
  }
  return json.NewEncoder(os.Stdout).Encode(map[string]any{"labOnly":true,"status":"listed","documents":entries})
 case "--gui-document-export-lab":
  p,e:=readDocument(dir,req.ID,key,r);if e!=nil{return e};defer clear(p.Data)
  if !winGUIApprove("Exporter une copie DECHIFFREE vers un dossier prive neuf ? Le coffre conserve l'original chiffre."){return portableRefusal}
  if _,e=exportDocument(req.Path,req.ID,p);e!=nil{return e}
  return json.NewEncoder(os.Stdout).Encode(map[string]any{"labOnly":true,"status":"exported"})
 }
 return portableRefusal
}
