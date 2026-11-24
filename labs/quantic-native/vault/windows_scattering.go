//go:build windows && cgo && pqopenssl

package main
import(
 "crypto/sha256"
 "encoding/hex"
 "io"
 "os"
 "path/filepath"
 "regexp"
 "syscall"
)
func winCreateScattering(dir string)error{
 if e:=winCreatePrivateDirectory(dir);e!=nil{return e}
 if e:=winCreateDirectoryMode(filepath.Join(dir,"queue"),2);e!=nil{return e}
 state:=filepath.Join(dir,"state")
 if e:=winCreatePrivateDirectory(state);e!=nil{return e}
 return winWritePrivate(filepath.Join(state,"active.lock"),[]byte("scattering guard\n"))
}
type scatteringGuard struct{hs []syscall.Handle; lock *os.File}
func(g *scatteringGuard)close(){g.lock.Close();winClose(g.hs)}
func winReserveScattering(dir,epoch string)(*scatteringGuard,error){
 if !hashRE.MatchString(epoch){return nil,portableRefusal}
 raw,e:=hex.DecodeString(epoch);if e!=nil{return nil,e}
 q:=filepath.Join(dir,"queue");state:=filepath.Join(dir,"state")
 hs,e:=winLockDirectory(dir,true);if e!=nil{return nil,e}
 var lock *os.File
 ok:=false;defer func(){if !ok{if lock!=nil{lock.Close()};winClose(hs)}}()
 qh,e:=winLockDirectoryMode(q,2);if e!=nil{return nil,e};hs=append(hs,qh...)
 sh,e:=winLockDirectory(state,true);if e!=nil{return nil,e};hs=append(hs,sh...)
 var lh []syscall.Handle
 lock,lh,e=winOpenPrivateMode(filepath.Join(state,"active.lock"),2);if e!=nil{return nil,e};hs=append(hs,lh...)
 entries,e:=os.ReadDir(q);if e!=nil||len(entries)!=0{return nil,portableRefusal}
 marker:=sha256.Sum256(raw)
 if e=winWritePrivate(filepath.Join(state,"used-"+hex.EncodeToString(marker[:])),[]byte("epoch consumed\n"));e!=nil{return nil,e}
 ok=true;return &scatteringGuard{hs,lock},nil
}
// Each lane owns an exclusive queue guard, but all lanes share the
// durable CREATE_NEW epoch ledger. A failed reservation consumes the epoch
// rather than risking reuse. Hold both private directory trees open.
var winScatteringLane=regexp.MustCompile("^lane-[a-z0-9]{1,24}$")
func winReserveScatteringOverlap(root,lane,epoch string)(*scatteringGuard,error){
 if filepath.Dir(lane)!=root||!winScatteringLane.MatchString(filepath.Base(lane))||!hashRE.MatchString(epoch){return nil,portableRefusal}
 raw,e:=hex.DecodeString(epoch);if e!=nil{return nil,e};defer clear(raw)
 state:=filepath.Join(root,"state")
 hs,e:=winLockDirectory(state,true);if e!=nil{return nil,e}
 ok:=false;defer func(){if !ok{winClose(hs)}}()
 marker:=sha256.Sum256(raw)
 if e=winWritePrivate(filepath.Join(state,"used-"+hex.EncodeToString(marker[:])),[]byte("overlap epoch consumed\n"));e!=nil{return nil,e}
 g,e:=winReserveScattering(lane,epoch);if e!=nil{return nil,e}
 g.hs=append(g.hs,hs...);ok=true;return g,nil
}
func winScatteringCLI(args []string)(bool,error){
 if len(args)<2{return false,nil}
 switch args[1]{
 case "--windows-scattering-create-lab":
  if len(args)!=3{return true,portableRefusal}
  return true,winCreateScattering(args[2])
 case "--windows-scattering-config-lab":
  if len(args)!=3{return true,portableRefusal}
  b,e:=io.ReadAll(io.LimitReader(os.Stdin,16385));if e!=nil{return true,e};defer clear(b)
  if len(b)<1||len(b)>16384{return true,portableRefusal}
  return true,winWritePrivate(filepath.Join(args[2],"scattering.json"),b)
 case "--windows-scattering-overlap-guard-lab":
  if len(args)!=4{return true,portableRefusal}
  var b [64]byte
  if _,e:=io.ReadFull(os.Stdin,b[:]);e!=nil{return true,e}
  g,e:=winReserveScatteringOverlap(args[2],args[3],string(b[:]));clear(b[:]);if e!=nil{return true,e};defer g.close()
  if _,e=os.Stdout.WriteString("READY\n");e!=nil{return true,e}
  var end [1]byte
  n,e:=os.Stdin.Read(end[:]);if n!=0||e!=io.EOF{return true,portableRefusal}
  return true,nil
 case "--windows-scattering-guard-lab":
  if len(args)!=3{return true,portableRefusal}
  var b [64]byte
  if _,e:=io.ReadFull(os.Stdin,b[:]);e!=nil{return true,e}
  g,e:=winReserveScattering(args[2],string(b[:]));clear(b[:]);if e!=nil{return true,e};defer g.close()
  if _,e=os.Stdout.WriteString("READY\n");e!=nil{return true,e}
  var end [1]byte
  n,e:=os.Stdin.Read(end[:]);if n!=0||e!=io.EOF{return true,portableRefusal}
  return true,nil
 }
 return false,nil
}
