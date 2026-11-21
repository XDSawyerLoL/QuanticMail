package main
import (
 "bytes"
 "crypto/rand"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "io"
 "os"
 "path/filepath"
)
const recoveryMax=24576
func recoveryRequest(q request)[32]byte {
 q.Recover=false
 raw,_:=json.Marshal(q);defer clear(raw)
 return sha256.Sum256(raw)
}
func recoveryPath(j *replayLog,k [32]byte)string {
 return j.f.Name()+".result-"+hex.EncodeToString(k[:])
}
func recoveryAAD(j *replayLog,k,req [32]byte)[]byte{
 return []byte("quantic-result-cache-lab/v1\x00"+j.anchorID+"\x00"+hex.EncodeToString(k[:])+hex.EncodeToString(req[:]))
}
func(p *pqKeys) saveResult(j *replayLog,k,req [32]byte,r reply)error{
 if p.recovery==nil||j.failed||!r.OK||len(j.seen)>=replayCap{return portableRefusal}
 path:=recoveryPath(j,k)
 if e:=checkPortableDirectory(filepath.Dir(path));e!=nil{return e}
 raw,e:=json.Marshal(r);if e!=nil{return e};defer clear(raw)
 if len(raw)>recoveryMax-28{return portableRefusal}
 nonce:=make([]byte,p.recovery.NonceSize());if _,e=rand.Read(nonce);e!=nil{return e}
 sealed:=p.recovery.Seal(nonce,nonce,raw,recoveryAAD(j,k,req))
 f,e:=os.OpenFile(path,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600);if e!=nil{return e}
 n,e:=f.Write(sealed);if e==nil&&n!=len(sealed){e=io.ErrShortWrite}
 if e==nil{e=f.Sync()};ce:=f.Close();if e==nil{e=ce};if e!=nil{return e}
 return syncPortableDirectory(filepath.Dir(path))
}
func(p *pqKeys) readResult(j *replayLog,k,req [32]byte)(reply,error){
 var r reply
 if p.recovery==nil||j.failed{return r,portableRefusal}
 path:=recoveryPath(j,k)
 if e:=checkPortableDirectory(filepath.Dir(path));e!=nil{return r,e}
 st,e:=os.Lstat(path);if e!=nil||!st.Mode().IsRegular()||!privatePortableFile(st)||st.Size()>recoveryMax{return r,portableRefusal}
 f,e:=os.Open(path);if e!=nil{return r,e};defer f.Close()
 actual,e:=f.Stat();if e!=nil||!os.SameFile(st,actual){return r,portableRefusal}
 data,e:=io.ReadAll(io.LimitReader(f,recoveryMax+1))
 if e!=nil||len(data)>recoveryMax||len(data)<p.recovery.NonceSize()+p.recovery.Overhead(){return r,portableRefusal}
 n:=p.recovery.NonceSize();raw,e:=p.recovery.Open(nil,data[:n],data[n:],recoveryAAD(j,k,req));if e!=nil{return r,portableRefusal};defer clear(raw)
 d:=json.NewDecoder(bytes.NewReader(raw));d.DisallowUnknownFields();var extra any
 if d.Decode(&r)!=nil||d.Decode(&extra)!=io.EOF||!r.OK{return reply{},portableRefusal}
 return r,nil
}
