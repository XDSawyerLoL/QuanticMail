//go:build windows && cgo && pqopenssl

package main
import("testing";"crypto/ed25519";"crypto/rand";"crypto/x509";"encoding/json";"encoding/hex";"sort";"path/filepath";"strings";"crypto/ecdsa";"crypto/sha256";"math/big";"time")
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

func TestNativeFinancialPermitVerification(t *testing.T){
 type authority struct{ pub nativePermitMember; cl ed25519.PrivateKey; pq pqKey }
 var keys []authority
 for n:=0;n<16;n++{
  public,priv,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
  der,e:=x509.MarshalPKIXPublicKey(public);if e!=nil{t.Fatal(e)}
  pq,e:=pqGenerate("ML-DSA-65");if e!=nil{t.Fatal(e)};defer pq.close()
  dp,e:=pq.der(false);if e!=nil{t.Fatal(e)}
  keys=append(keys,authority{nativePermitMember{hexHash(der),hexHash(dp),b64.EncodeToString(der),b64.EncodeToString(dp)},priv,pq})
 }
 sort.Slice(keys,func(i,j int)bool{return keys[i].pub.Pin<keys[j].pub.Pin})
 pins:=make([][2]string,0,16);members:=make([]nativePermitMember,0,16)
 for _,k:=range keys{pins=append(pins,[2]string{k.pub.Pin,k.pub.PQPin});members=append(members,k.pub)}
 shard,payer:="demo-east","demo-alice"
 policy:=permitHash([]any{"quantic-native-pay-policy/lab/v1",shard,payer,pins})
 quorum:=strings.Repeat("a",64)
 dir:=filepath.Join(t.TempDir(),"certified-pay");pw:=[]byte("synthetic certified financial vault password")
 info,e:=provisionPayLabPolicy(dir,pw,quorum,policy);if e!=nil{t.Fatal(e)}
 s,d:=info["signingPin"],info["pqPin"]
 raw,e:=winReadPrivate(filepath.Join(dir,"pay.vault"),50000);if e!=nil{t.Fatal(e)}
 if k,e:=openPayLabKeysMode(raw,pw,s,d,payMode(quorum));e==nil{k.close();t.Fatal("certified downgrade")}
 if k,e:=openPayLabKeys(raw,pw,s,d);e==nil{k.close();t.Fatal("legacy downgrade")}
 k,e:=openPayLabKeysMode(raw,pw,s,d,certifiedPayMode(quorum,policy));if e!=nil{t.Fatal(e)};defer k.close()
 now:=time.Now().UnixMilli();intent:=payLabIntent{"demo-shop",200,strings.Repeat("f",64),now,now+120000}
 network,root:=strings.Repeat("b",64),strings.Repeat("c",64)
 digest:=hexHash(payLabTranscript(intent,s,d))
 yes,no:=true,false
 p:=nativePermit{Policy:policy,Network:network,Shard:shard,Payer:payer,Root:root,IntentDigest:digest,Height:1,Available:900,Authorities:members,SimulationOnly:&yes,RealPaymentAuthorized:&no}
 domain:=permitHash([]any{"quantic-native-permit-round/lab/v1",network,shard,payer})
 scope:=permitHash([]any{"quantic-pay-committee-round/v3",domain,2,root,pins,16,11,true,nil,true})
 value:=permitHash([]any{"quantic-native-pay-permit/lab/v1",policy,network,shard,payer,1,root,900,digest,true})
 zero:=0
 makeQC:=func(phase,sc,v string)nativePermitQC{
  q:=nativePermitQC{Scope:sc,Value:v,Round:&zero}
  for _,key:=range keys[:11]{msg,_:=json.Marshal([]any{"quantic-pay-round-vote/v1",sc,phase,0,v,key.pub.Pin,key.pub.PQPin});sig,e:=key.pq.sign(msg);if e!=nil{t.Fatal(e)};q.Votes=append(q.Votes,nativePermitVote{key.pub.Pin,key.pub.PQPin,b64.EncodeToString(ed25519.Sign(key.cl,msg)),b64.EncodeToString(sig)})}
  return q
 }
 p.Certificate.Prepared=makeQC("prepare",scope,value);p.Certificate.Commit=makeQC("commit",scope,value)
 pack:=func(p nativePermit)[]byte{b,e:=json.Marshal(p);if e!=nil{t.Fatal(e)};return b}
 if e=verifyNativePayPermit(pack(p),policy,s,d,intent,now);e!=nil{t.Fatal("valid certificate refused",e)}
 changed:=intent;changed.Cents++
 if verifyNativePayPermit(pack(p),policy,s,d,changed,now)==nil{t.Fatal("amount substitution")}
 if verifyNativePayPermit(pack(p),policy,s,d,intent,intent.Expires)==nil{t.Fatal("expired permit")}
 if verifyNativePayPermit(pack(p),strings.Repeat("e",64),s,d,intent,now)==nil{t.Fatal("policy substitution")}
 bad:=p;bad.Available=199;if verifyNativePayPermit(pack(bad),policy,s,d,intent,now)==nil{t.Fatal("insufficient balance")}
 bad=p;bad.Certificate.Commit.Votes=bad.Certificate.Commit.Votes[:10];if verifyNativePayPermit(pack(bad),policy,s,d,intent,now)==nil{t.Fatal("short quorum")}
 bad=p;bad.Certificate.Commit.Votes=append([]nativePermitVote(nil),p.Certificate.Commit.Votes...);bad.Certificate.Commit.Votes[0]=bad.Certificate.Commit.Votes[1];if verifyNativePayPermit(pack(bad),policy,s,d,intent,now)==nil{t.Fatal("duplicate vote")}
 bad=p;bad.Certificate.Prepared.Votes=append([]nativePermitVote(nil),p.Certificate.Prepared.Votes...);bad.Certificate.Prepared.Votes[0].PQSignature=strings.Repeat("A",4412);if verifyNativePayPermit(pack(bad),policy,s,d,intent,now)==nil{t.Fatal("forged PQ vote")}
 // A reserved permit commits to the exact escrowed transfer identifier,
 // not a historical, potentially already-spent available balance.
 transferBytes,_:=json.Marshal([]any{"quantic-shard-transfer/v1",network,payer,intent.Payee,intent.Cents,intent.Nonce})
 reservationId:=permitHash([]any{"quantic-shard-id/v1",hex.EncodeToString(transferBytes)})
 reservedPolicy:=permitHash([]any{"quantic-native-pay-reserved-policy/lab/v1",shard,payer,pins})
 reservedNetwork:=permitHash([]any{"quantic-native-reserved-permit-round/lab/v1",network,shard,payer})
 reservedScope:=permitHash([]any{"quantic-pay-committee-round/v3",reservedNetwork,2,root,pins,16,11,true,nil,true})
 reservedValue:=permitHash([]any{"quantic-native-pay-reserved-permit/lab/v1",reservedPolicy,network,shard,payer,1,root,200,reservationId,digest,true})
 p.Policy=reservedPolicy;p.ReservationId=reservationId;p.Available=200
 p.Certificate.Prepared=makeQC("prepare",reservedScope,reservedValue)
 p.Certificate.Commit=makeQC("commit",reservedScope,reservedValue)
 if e=verifyNativePayPermit(pack(p),reservedPolicy,s,d,intent,now);e!=nil{t.Fatal("valid reserved permit refused",e)}
 if verifyNativePayPermit(pack(p),policy,s,d,intent,now)==nil{t.Fatal("reserved/plain policy mix accepted")}
 bad=p;bad.ReservationId=strings.Repeat("d",64)
 if verifyNativePayPermit(pack(bad),reservedPolicy,s,d,intent,now)==nil{t.Fatal("reservation substituted")}
 bad=p;bad.Available=201
 if verifyNativePayPermit(pack(bad),reservedPolicy,s,d,intent,now)==nil{t.Fatal("incorrect reserved amount")}
 bad=p;bad.Certificate.Commit.Votes=bad.Certificate.Commit.Votes[:10]
 if verifyNativePayPermit(pack(bad),reservedPolicy,s,d,intent,now)==nil{t.Fatal("reserved quorum missing")}
}
