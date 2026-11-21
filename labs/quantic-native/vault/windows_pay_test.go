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
