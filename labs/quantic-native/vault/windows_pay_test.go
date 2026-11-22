//go:build windows && cgo && pqopenssl

package main
import("testing";"path/filepath";"strings";"crypto/ecdsa";"crypto/sha256";"math/big";"time")
func TestWindowsPayLab(t *testing.T){
 dir:=filepath.Join(t.TempDir(),"pay-only");pw:=[]byte("synthetic payment lab storage password")
 r,e:=provisionPayLab(dir,pw);if e!=nil{t.Fatal(e)}
 if _,e=provisionPayLab(dir,pw);e==nil{t.Fatal("overwritten")}
 raw,e:=winReadPrivate(filepath.Join(dir,"pay.vault"),50000);if e!=nil{t.Fatal(e)}
 s,d:=r["signingPin"],r["pqPin"]
 for _,bad:=range [][]byte{[]byte("synthetic wrong pay lab password"),pw}{
  pin:=s;if string(bad)==string(pw){pin=strings.Repeat("f",64)}
  if _,e=openPayLabKeys(raw,bad,pin,d);e==nil{t.Fatal("invalid unlock")}
 }
 cfg:=[]byte("{\"simulationOnly\":true}")
 if e=writePayQuorumConfig(dir,strings.Repeat("a",64),cfg);e==nil{t.Fatal("configuration pin mismatch")}
 if e=writePayQuorumConfig(dir,hexHash(cfg),cfg);e!=nil{t.Fatal("configuration refused",e)}
 if e=writePayQuorumConfig(dir,hexHash(cfg),cfg);e==nil{t.Fatal("configuration overwritten")}
 k,e:=openPayLabKeys(raw,pw,s,d);if e!=nil{t.Fatal(e)};defer k.close()
 n:=time.Now().UnixMilli();i:=payLabIntent{"demo-shop",250,strings.Repeat("a",64),n,n+120000}
 if _,e=signPayLab(k,i,n,false);e==nil{t.Fatal("no consent")}
 proof,e:=signPayLab(k,i,n,true);if e!=nil||proof.RealPaymentAuthorized{t.Fatal(e)}
 stored,e:=commitPayLabProof(dir,proof);if e!=nil||len(stored)==0{t.Fatal("receipt",e)}
 if _,e=commitPayLabProof(dir,proof);e==nil{t.Fatal("duplicate receipt accepted")}
 persisted,e:=winReadPrivate(filepath.Join(dir,"pay-receipt-"+i.Nonce+".json"),32768);if e!=nil||string(persisted)!=string(stored){t.Fatal("receipt changed")}
 history,e:=readPayLabHistory(dir);if e!=nil||len(history)!=1||history[0].Intent.Nonce!=i.Nonce{t.Fatal("history inventory",e)}
 b:=payLabTranscript(i,s,d);sum:=sha256.Sum256(b)
 cl,e:=decode(proof.Classical,64,64);if e!=nil{t.Fatal(e)}
 pq,e:=decode(proof.PQ,3309,3309);if e!=nil{t.Fatal(e)}
 if !ecdsa.Verify(&k.classical.PublicKey,sum[:],new(big.Int).SetBytes(cl[:32]),new(big.Int).SetBytes(cl[32:]))||!pqVerifyRoot(k.pqPublic,b,pq){t.Fatal("invalid signatures")}
 i.Cents++;if pqVerifyRoot(k.pqPublic,payLabTranscript(i,s,d),pq){t.Fatal("amount substitution")}
 i.Payee="real-bank";if _,e=signPayLab(k,i,n,true);e==nil{t.Fatal("real payee")}
 i.Payee="demo-shop";if _,e=signPayLab(k,i,n+120000,true);e==nil{t.Fatal("expired")}
 raw[len(raw)-1]^=1;if _,e=openPayLabKeys(raw,pw,s,d);e==nil{t.Fatal("tampering")}
}

func TestWindowsAnchoredPayLab(t *testing.T){
 for _,refused:=range []int{0,1,2}{
  t.Run(string(rune('0'+refused)),func(t *testing.T){
   dir:=filepath.Join(t.TempDir(),"anchored-pay");pw:=[]byte("synthetic anchored financial vault password")
   pin:=strings.Repeat("a",64)
   info,e:=provisionPayLabMode(dir,pw,pin);if e!=nil{t.Fatal(e)}
   s,d,id:=info["signingPin"],info["pqPin"],info["anchorId"]
   raw,e:=winReadPrivate(filepath.Join(dir,"pay.vault"),50000);if e!=nil{t.Fatal(e)}
   if bad,e:=openPayLabKeys(raw,pw,s,d);e==nil{bad.close();t.Fatal("legacy downgrade")}
   if bad,e:=openPayLabKeysMode(raw,pw,s,d,payMode(strings.Repeat("b",64)));e==nil{bad.close();t.Fatal("quorum substitution")}
   k,e:=openPayLabKeysMode(raw,pw,s,d,payMode(pin));if e!=nil{t.Fatal(e)};defer k.close()
   path:=filepath.Join(dir,"pay-journal.log");j,e:=winOpenReplay(path,s,d,pin);if e!=nil{t.Fatal(e)}
   q:=&quorumAnchor{};var ws [4]*fakeAnchor
   for index:=range ws{ws[index]=&fakeAnchor{tail:j.tail};q.members[index]=ws[index]}
   if e=j.attachAnchor(q,id);e!=nil{j.close();t.Fatal(e)}
   for index:=0;index<refused;index++{ws[index].fail=true}
   n:=time.Now().UnixMilli();clock:=func()int64{return n}
   intent:=payLabIntent{"demo-shop",250,strings.Repeat("c",64),n,n+120000}
   if _,e=authorizeAnchoredPay(j,k,intent,clock,false);e==nil||len(j.seen)!=0{j.close();t.Fatal("consent bypass")}
   proof,e:=authorizeAnchoredPay(j,k,intent,clock,true)
   if refused==2{
    defer j.close()
    if e==nil||proof.PQ!=""||proof.Classical!=""||!j.failed{t.Fatal("refused quorum released proof")}
    return
   }
   if e!=nil||proof.RealPaymentAuthorized||len(j.seen)!=2{j.close();t.Fatal("valid anchored proof",e)}
   b:=payLabTranscript(intent,s,d);sum:=sha256.Sum256(b)
   cl,e:=decode(proof.Classical,64,64);if e!=nil{j.close();t.Fatal(e)}
   pq,e:=decode(proof.PQ,3309,3309);if e!=nil{j.close();t.Fatal(e)}
   if !ecdsa.Verify(&k.classical.PublicKey,sum[:],new(big.Int).SetBytes(cl[:32]),new(big.Int).SetBytes(cl[32:]))||!pqVerifyRoot(k.pqPublic,b,pq){j.close();t.Fatal("invalid native hybrid proof")}
   for index,w:=range ws{if index>=refused&&(w.count!=2||w.tail!=j.tail){j.close();t.Fatal("reservation not anchored")}}
   j.close();j,e=winOpenReplay(path,s,d,pin);if e!=nil{t.Fatal(e)};defer j.close()
   if e=j.attachAnchor(q,id);e!=nil{t.Fatal(e)}
   intent.Cents++
   if _,e=authorizeAnchoredPay(j,k,intent,clock,true);e==nil||len(j.seen)!=2{t.Fatal("nonce reuse after reopen")}
  })
 }
}
