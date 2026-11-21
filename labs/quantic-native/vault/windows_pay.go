//go:build windows && cgo && pqopenssl

package main

// Dedicated fictional payment keys; never open the messaging identity vault.
// Same private NTFS custody and password-derived AEAD as the native vault.
// An authorization is only a synthetic proof, not a settlement or payment credential.
import (
 "crypto/ecdh"
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/sha256"
 "encoding/json"
 "fmt"
 "os"
 "io"
 "path/filepath"
 "strconv"
 "strings"
 "bytes"
 "time"
)

const payMagic = "QV-PAY-SIMULATION-LAB-V1\x00"

type payLabKeys struct{ classical *ecdsa.PrivateKey; pq pqKey; pqPublic []byte }
func (k *payLabKeys) close(){k.pq.close();k.classical.D.SetInt64(0)}
func (k *payLabKeys) pins()(string,string){return publicPin(&k.classical.PublicKey),hexHash(k.pqPublic)}

func sealPayLabKeys(k *payLabKeys,pw []byte)([]byte,error){
 if !validPortablePassword(pw){return nil,portableRefusal}
 scalar:=k.classical.D.FillBytes(make([]byte,32));defer clear(scalar)
 der,e:=k.pq.der(true);if e!=nil{return nil,e};defer clear(der)
 plain,e:=json.Marshal([][]byte{scalar,der});if e!=nil{return nil,e};defer clear(plain)
 salt,iv:=make([]byte,16),make([]byte,12)
 if _,e=rand.Read(salt);e!=nil{return nil,e}
 if _,e=rand.Read(iv);e!=nil{return nil,e}
 a,e:=portableAEAD(pw,salt);if e!=nil{return nil,e}
 header:=append(append([]byte(payMagic),salt...),iv...)
 return a.Seal(header,iv,plain,header),nil
}

func openPayLabKeys(raw,pw []byte,signPin,pqPin string)(*payLabKeys,error){
 h:=len(payMagic)
 if !validPortablePassword(pw)||!hashRE.MatchString(signPin)||!hashRE.MatchString(pqPin)||len(raw)<h+44||len(raw)>50000||string(raw[:h])!=payMagic{return nil,portableRefusal}
 a,e:=portableAEAD(pw,raw[h:h+16]);if e!=nil{return nil,e}
 plain,e:=a.Open(nil,raw[h+16:h+28],raw[h+28:],raw[:h+28]);if e!=nil{return nil,portableRefusal};defer clear(plain)
 var parts [][]byte
 e=json.Unmarshal(plain,&parts)
 for _,p:=range parts{defer clear(p)}
 if e!=nil||len(parts)!=2||len(parts[0])!=32{return nil,portableRefusal}
 // The standard parser validates the P-256 scalar.
 priv,e:=parsePayScalar(parts[0]);if e!=nil{return nil,e}
 pq,e:=pqImport(parts[1],"ML-DSA-65");if e!=nil{priv.D.SetInt64(0);return nil,e}
 dp,e:=pq.der(false);if e!=nil{pq.close();priv.D.SetInt64(0);return nil,e}
 k:=&payLabKeys{priv,pq,dp};s,d:=k.pins()
 if s!=signPin||d!=pqPin{k.close();return nil,portableRefusal}
 return k,nil
}

func parsePayScalar(raw []byte)(*ecdsa.PrivateKey,error){
 k,e:=ecdh.P256().NewPrivateKey(raw);if e!=nil{return nil,e}
 x,y:=elliptic.Unmarshal(elliptic.P256(),k.PublicKey().Bytes());if x==nil{return nil,portableRefusal}
 return ecdsaFromBytes(raw,x,y)
}

func provisionPayLab(dir string,pw []byte)(map[string]string,error){
 if !validPortablePassword(pw){return nil,portableRefusal}
 if _,_,e:=winPathParts(filepath.Join(dir,"pay.vault"));e!=nil{return nil,e}
 if _,_,e:=winPathParts(filepath.Join(dir,"pay-receipt-"+strings.Repeat("a",64)+".json"));e!=nil{return nil,e}
 priv,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if e!=nil{return nil,e}
 pq,e:=pqGenerate("ML-DSA-65");if e!=nil{priv.D.SetInt64(0);return nil,e}
 dp,e:=pq.der(false);if e!=nil{pq.close();priv.D.SetInt64(0);return nil,e}
 k:=&payLabKeys{priv,pq,dp};defer k.close()
 raw,e:=sealPayLabKeys(k,pw);if e!=nil{return nil,e}
 if e=winCreatePrivateDirectory(dir);e!=nil{return nil,e}
 if e=winWritePrivate(filepath.Join(dir,"pay.vault"),raw);e!=nil{return nil,e}
 s,d:=k.pins()
 return map[string]string{"mode":"fictional-pay-lab","signingPin":s,"pqPin":d,"status":"stored-not-enrolled"},nil
}

type payLabIntent struct{ Payee string; Cents int; Nonce string; Issued,Expires int64 }
func (i payLabIntent) valid(now int64)bool{
 return (i.Payee=="demo-shop"||i.Payee=="demo-person")&&i.Cents>=1&&i.Cents<=10000&&hashRE.MatchString(i.Nonce)&&i.Issued>=0&&i.Expires>i.Issued&&i.Expires-i.Issued==120000&&now>=i.Issued&&now<i.Expires
}
func payLabTranscript(i payLabIntent,s,d string)[]byte{
 b,_:=json.Marshal([]any{"quantic-pay-native-simulation/v1",s,d,i.Payee,i.Cents,"EUR",i.Nonce,i.Issued,i.Expires,false})
 return b
}
type payLabProof struct{
 Intent payLabIntent `json:"intent"`
 SigningPin string `json:"signingPin"`
 PQPin string `json:"pqPin"`
 Classical string `json:"classicalSignature"`
 PQ string `json:"pqSignature"`
 ClassicalPublic string `json:"classicalPublic"`
 PQPublic string `json:"pqPublic"`
 RealPaymentAuthorized bool `json:"realPaymentAuthorized"`
}
func signPayLab(k *payLabKeys,i payLabIntent,now int64,approved bool)(payLabProof,error){
 if !approved||!i.valid(now){return payLabProof{},portableRefusal}
 s,d:=k.pins();b:=payLabTranscript(i,s,d);sum:=sha256.Sum256(b)
 sig,e:=(softwareSigner{k.classical}).SignDigest(sum);if e!=nil{return payLabProof{},e}
 pq,e:=k.pq.sign(b);if e!=nil{return payLabProof{},e}
 return payLabProof{i,s,d,b64.EncodeToString(sig),b64.EncodeToString(pq),b64.EncodeToString(elliptic.Marshal(elliptic.P256(),k.classical.X,k.classical.Y)),b64.EncodeToString(k.pqPublic),false},nil
}

// Exclusive durable receipt per synthetic nonce. A partial write or duplicate
// fails closed. This is not an externally anchored rollback-proof ledger.
func commitPayLabProof(dir string,proof payLabProof)([]byte,error){
 if proof.RealPaymentAuthorized||!hashRE.MatchString(proof.Intent.Nonce){return nil,portableRefusal}
 path:=filepath.Join(dir,"pay-receipt-"+proof.Intent.Nonce+".json")
 raw,e:=json.Marshal(proof);if e!=nil{return nil,e}
 if e=winWritePrivate(path,raw);e!=nil{return nil,e}
 got,e:=winReadPrivate(path,32768);if e!=nil||!bytes.Equal(got,raw){return nil,portableRefusal}
 return raw,nil
}
// Read only bounded public proof records via the same private Windows handles.
// The caller verifies every hybrid signature and compares the entire set to
// independently retained witnesses before requesting another signature.
func readPayLabHistory(dir string)([]payLabProof,error){
 hs,e:=winLockDirectory(dir,true);if e!=nil{return nil,e};defer winClose(hs)
 f,e:=os.Open(dir);if e!=nil{return nil,e};defer f.Close()
 entries,e:=f.Readdirnames(103);if e!=nil&&e!=io.EOF{return nil,e}
 if len(entries)>102{return nil,portableRefusal}
 result:=make([]payLabProof,0);vault:=false
 for _,name:=range entries{
  if name=="pay.vault"{vault=true;continue}
  if name=="pay-quorum.json"{continue}
  if !strings.HasPrefix(name,"pay-receipt-")||!strings.HasSuffix(name,".json"){return nil,portableRefusal}
  nonce:=strings.TrimSuffix(strings.TrimPrefix(name,"pay-receipt-"),".json")
  if !hashRE.MatchString(nonce)||len(result)>=100{return nil,portableRefusal}
  raw,e:=winReadPrivate(filepath.Join(dir,name),32768);if e!=nil{return nil,e}
  var proof payLabProof
  if e=json.Unmarshal(raw,&proof);e!=nil||proof.RealPaymentAuthorized||proof.Intent.Nonce!=nonce{return nil,portableRefusal}
  exact,e:=json.Marshal(proof);if e!=nil||!bytes.Equal(exact,raw){return nil,portableRefusal}
  result=append(result,proof)
 }
 if !vault{return nil,portableRefusal}
 return result,nil
}
func writePayQuorumConfig(dir,pin string,raw []byte)error{
 if !hashRE.MatchString(pin)||len(raw)<1||len(raw)>32768||hexHash(raw)!=pin||!json.Valid(raw){return portableRefusal}
 history,e:=readPayLabHistory(dir);if e!=nil||len(history)!=0{return portableRefusal}
 vault,e:=winReadPrivate(filepath.Join(dir,"pay.vault"),50000);if e!=nil{return e};defer clear(vault)
 if !bytes.HasPrefix(vault,[]byte(payMagic)){return portableRefusal}
 return winWritePrivate(filepath.Join(dir,"pay-quorum.json"),raw)
}
func windowsPayCLI(args []string)(bool,error){
 if len(args)<2{return false,nil}
 if args[1]=="--configure-windows-pay-quorum-lab"{
  if len(args)!=4||!hashRE.MatchString(args[3]){return true,portableRefusal}
  raw,e:=io.ReadAll(io.LimitReader(os.Stdin,32769));if e!=nil{return true,e};defer clear(raw)
  if !winApprove("Import NEW fictional Pay quorum configuration, SHA256 "+args[3]+". No overwrite or real account."){return true,portableRefusal}
  return true,writePayQuorumConfig(args[2],args[3],raw)
 }
 if args[1]=="--read-windows-pay-quorum-lab"{
  if len(args)!=4||!hashRE.MatchString(args[3]){return true,portableRefusal}
  raw,e:=winReadPrivate(filepath.Join(args[2],"pay-quorum.json"),32768);if e!=nil{return true,e};defer clear(raw)
  if hexHash(raw)!=args[3]{return true,portableRefusal}
  _,e=os.Stdout.Write(raw);return true,e
 }
 if args[1]=="--read-windows-pay-history-lab"{
  if len(args)!=3{return true,portableRefusal}
  proofs,e:=readPayLabHistory(args[2]);if e!=nil{return true,e}
  return true,json.NewEncoder(os.Stdout).Encode(proofs)
 }
 if args[1]=="--provision-windows-pay-lab"{
  if len(args)!=3||!winApprove("Create separate FICTIONAL Pay lab keys. No real payment."){return true,portableRefusal}
  pw,e:=winConfirmSecret("New independent Pay laboratory passphrase: ");if e!=nil{return true,e};defer clear(pw)
  result,e:=provisionPayLab(args[2],pw);if e!=nil{return true,e}
  return true,json.NewEncoder(os.Stdout).Encode(result)
 }
 if args[1]!="--sign-windows-pay-lab"{return false,nil}
 // Only a locally displayed synthetic recipient and exact amount; no arbitrary signing.
 if len(args)!=9{return true,portableRefusal}
 dir,s,d:=args[2],args[3],args[4]
 cents,e:=strconv.Atoi(args[6]);if e!=nil||strconv.Itoa(cents)!=args[6]{return true,portableRefusal}
 issued,e:=strconv.ParseInt(args[8],10,64);if e!=nil||issued<0||issued>time.Now().UnixMilli(){return true,portableRefusal}
 i:=payLabIntent{args[5],cents,args[7],issued,issued+120000}
 if !i.valid(time.Now().UnixMilli())||!hashRE.MatchString(s)||!hashRE.MatchString(d){return true,portableRefusal}
 hs,e:=winLockDirectory(dir,true);if e!=nil{return true,e};defer winClose(hs)
 raw,e:=winReadPrivate(filepath.Join(dir,"pay.vault"),50000);if e!=nil{return true,e}
 pw,e:=winConsoleLine("Pay laboratory passphrase: ",true);if e!=nil{return true,e};defer clear(pw)
 k,e:=openPayLabKeys(raw,pw,s,d);clear(pw);if e!=nil{return true,e};defer k.close()
 approved:=winApprove(fmt.Sprintf("SIMULATION ONLY: %d.%02d fictional EUR to %s; request %s. No money moves.",i.Cents/100,i.Cents%100,i.Payee,i.Nonce))
 proof,e:=signPayLab(k,i,time.Now().UnixMilli(),approved);if e!=nil{return true,e}
 // Release only after exclusive write and exact readback.
 receipt,e:=commitPayLabProof(dir,proof);if e!=nil{return true,e}
 _,e=os.Stdout.Write(append(receipt,'\n'))
 return true,e
}
