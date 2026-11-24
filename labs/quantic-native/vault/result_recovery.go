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
 if p.recovery==nil||j.failed||!r.OK||len(j.seen)>replayCap{return portableRefusal}
 path:=recoveryPath(j,k)
 raw,e:=json.Marshal(r);if e!=nil{return e};defer clear(raw)
 if len(raw)>recoveryMax-28{return portableRefusal}
 nonce:=make([]byte,p.recovery.NonceSize());if _,e=rand.Read(nonce);e!=nil{return e}
 sealed:=p.recovery.Seal(nonce,nonce,raw,recoveryAAD(j,k,req))
 if j.resultWrite!=nil{return j.resultWrite(path,sealed)}
 if e:=checkPortableDirectory(filepath.Dir(path));e!=nil{return e}
 f,e:=os.OpenFile(path,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600);if e!=nil{return e}
 n,e:=f.Write(sealed);if e==nil&&n!=len(sealed){e=io.ErrShortWrite}
 if e==nil{e=f.Sync()};ce:=f.Close();if e==nil{e=ce};if e!=nil{return e}
 return syncPortableDirectory(filepath.Dir(path))
}
func(p *pqKeys) readResult(j *replayLog,k,req [32]byte)(reply,error){
 var r reply
 if p.recovery==nil||j.failed{return r,portableRefusal}
 path:=recoveryPath(j,k)
 if j.resultRead!=nil{data,e:=j.resultRead(path,recoveryMax);if e!=nil{return r,e};return p.decodeResult(j,k,req,data)}
 if e:=checkPortableDirectory(filepath.Dir(path));e!=nil{return r,e}
 st,e:=os.Lstat(path);if e!=nil||!st.Mode().IsRegular()||!privatePortableFile(st)||st.Size()>recoveryMax{return r,portableRefusal}
 f,e:=os.Open(path);if e!=nil{return r,e};defer f.Close()
 actual,e:=f.Stat();if e!=nil||!os.SameFile(st,actual){return r,portableRefusal}
 data,e:=io.ReadAll(io.LimitReader(f,recoveryMax+1))
 if e!=nil{return r,portableRefusal}
 r,e=p.decodeResult(j,k,req,data)
 if e!=nil{return reply{},e}
 // A complete authenticated file may survive a crash before its initial
 // fsync finished. Re-establish local durability before releasing it.
 if e=f.Sync();e!=nil{return reply{},e}
 if e=syncPortableDirectory(filepath.Dir(path));e!=nil{return reply{},e}
 return r,nil
}
func(p *pqKeys) decodeResult(j *replayLog,k,req [32]byte,data []byte)(reply,error){
 var r reply
 if len(data)>recoveryMax||len(data)<p.recovery.NonceSize()+p.recovery.Overhead(){return r,portableRefusal}
 n:=p.recovery.NonceSize();raw,e:=p.recovery.Open(nil,data[:n],data[n:],recoveryAAD(j,k,req));if e!=nil{return r,portableRefusal};defer clear(raw)
 d:=json.NewDecoder(bytes.NewReader(raw));d.DisallowUnknownFields();var extra any
 if d.Decode(&r)!=nil||d.Decode(&extra)!=io.EOF||!r.OK{return reply{},portableRefusal}
 return r,nil
}

// authorizedMailResult is the private-operation boundary. The caller must
// maintain the fresh, contact-bound anchor context across this call. A new
// operation consumes its journal ID before invoking the provider. Recovery
// only reads a committed encrypted result; an orphan or missing result
// cannot authorize a second operation. A crash between reservation and
// fsync of the result is deliberately unrecoverable, not silently retried.
func(p *pqKeys) authorizedMailResult(j *replayLog,k,req [32]byte,recover bool,operation func()(reply,error))(reply,error){
 if j==nil||j.anchor==nil||j.failed||p.recovery==nil{return reply{},portableRefusal}
 if recover{
  if !j.seen[k]{return reply{},portableRefusal}
  if e:=j.anchor.check(j.anchorID,len(j.seen),j.tail);e!=nil{return reply{},e}
  return p.readResult(j,k,req)
 }
 if operation==nil||j.has(k){return reply{},portableRefusal}
 if e:=j.consume(k);e!=nil{return reply{},e}
 r,e:=operation();if e!=nil{return reply{},e}
 if e=p.saveResult(j,k,req,r);e!=nil{return reply{},e}
 return r,nil
}
