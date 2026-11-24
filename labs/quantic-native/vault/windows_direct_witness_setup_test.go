//go:build windows && cgo && pqopenssl

package main

import(
 "bytes"
 stdcontext "context"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)
func TestWindowsDirectWitnessPairing(t *testing.T){
 root:=t.TempDir()
 dir:=filepath.Join(root,"witness")
 card,e:=winCreateDirectWitness(dir,"127.0.0.1",31001,31002);if e!=nil{t.Fatal(e)}
 if _,e=winCreateDirectWitness(dir,"127.0.0.1",31001,31002);e==nil{t.Fatal("identity overwritten")}
 c,priv,e:=winLoadDirectWitness(dir);if e!=nil{t.Fatal(e)}
 defer clear(priv.Signing);defer clear(priv.KEM)
 if c!=card{t.Fatal("card changed")}
 p:=directWitnessPairing{"quantic-witness-pairing/v1",directWitnessCardPin(c),strings.Repeat("a",64),strings.Repeat("b",64),strings.Repeat("c",64),strings.Repeat("d",64),strings.Repeat("e",64),bytes.Repeat([]byte{1},32),bytes.Repeat([]byte{2},32)}
 cap,e:=sealDirectWitnessPair(c,p);if e!=nil{t.Fatal(e)}
 other,e:=winCreateDirectWitness(filepath.Join(root,"other"),"127.0.0.2",31003,31004);if e!=nil{t.Fatal(e)}
 if _,e=openDirectWitnessPair(other,priv,cap);e==nil{t.Fatal("other recipient accepted")}
 damaged:=cap;damaged.Data=bytes.Clone(cap.Data);damaged.Data[0]^=1
 if _,e=openDirectWitnessPair(c,priv,damaged);e==nil{t.Fatal("tamper accepted")}
 raw,e:=json.Marshal(cap);if e!=nil{t.Fatal(e)}
 pin:=hexHash(raw)
 if e=winEnrollDirectWitness(dir,strings.Repeat("f",64),raw,func()bool{return true});e==nil{t.Fatal("bad pairing pin accepted")}
 if e=winEnrollDirectWitness(dir,pin,raw,func()bool{return false});e==nil{t.Fatal("pairing without consent")}
 if e=winEnrollDirectWitness(dir,pin,raw,func()bool{return true});e!=nil{t.Fatal(e)}
 if e=winEnrollDirectWitness(dir,pin,raw,func()bool{return true});e==nil{t.Fatal("re-enrollment accepted")}
 encrypted,e:=winReadPrivate(filepath.Join(dir,"witness-pair.dpapi"),16384);if e!=nil{t.Fatal(e)}
 if json.Valid(encrypted){t.Fatal("pairing stored as plaintext JSON")}
 s:=winDirectWitnessStore{filepath.Join(dir,"lease.log"),p.LeaseID,p.Sign,p.Enc,p.LeaseID}
 h,e:=replayBinding(p.Sign,p.Enc,p.LeaseID);if e!=nil{t.Fatal(e)}
 tail:=replayIDHeader(h)
 if e=s.check(p.LeaseID,0,tail);e!=nil{t.Fatal(e)}
 record:=[32]byte{7}
 if e=s.advance(p.LeaseID,0,tail,record);e!=nil{t.Fatal(e)}
 if e=s.check(p.LeaseID,0,tail);e==nil{t.Fatal("stale checkpoint accepted")}
 if e=s.check(p.LeaseID,1,hashRecord(tail,record));e!=nil{t.Fatal(e)}
 if e=os.Remove(s.path);e!=nil{t.Fatal(e)}
 if e=winServeDirectWitness(stdcontext.Background(),dir);e==nil{t.Fatal("missing journal recreated")}
}
