//go:build windows && cgo && pqopenssl

package main

// Dedicated fictional payment keys; never open the messaging identity vault.
// Same private NTFS custody and password-derived AEAD as the native vault.
// An authorization is only a synthetic proof, not a settlement or payment credential.
import (
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/sha256"
 "encoding/json"
 "fmt"
 "os"
 "path/filepath"
 "strconv"
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

func provisionPayLab(dir string,pw []byte)(map[string]string,error){
 if !validPortablePassword(pw){return nil,portableRefusal}
 if _,_,e:=winPathParts(filepath.Join(dir,"pay.vault"));e!=nil{return nil,e}
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

func windowsPayCLI(args []string)(bool,error){
 if len(args)<2{return false,nil}
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
 // Dedicated domain proof only, no replay/settlement claim.
 return true,json.NewEncoder(os.Stdout).Encode(proof)
}
