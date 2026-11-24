//go:build windows && cgo && pqopenssl

package main
import(
 "encoding/json"
 "encoding/hex"
 "path/filepath"
 "testing"
 "time"
 "bytes"
)
func TestWindowsDirectLocalVault(t *testing.T){
 root:=t.TempDir()
 dirs:=[]string{filepath.Join(root,"a"),filepath.Join(root,"b")}
 ids:=make([]directIdentity,2)
 pins:=make([]string,2)
 pass:=[]byte("Synthetic direct classical passphrase only")
 pqpass:=[]byte("Different synthetic PQ passphrase only")
 for i,d:=range dirs{
  alias:=[]string{"alice","bobby"}[i]
  id,e:=winProvisionDirect(d,alias,pass,pqpass);if e!=nil{t.Fatal(e)}
  ids[i]=id
  if _,e=winProvisionDirect(d,alias,pass,pqpass);e==nil{t.Fatal("overwrote identity")}
  if _,e=winReadClassical(filepath.Join(d,"classical.vault"),anchoredMagic+"compact-manifest-quorum:"+id.LocalPin+"\x00",pass,id.SigningPin,id.EncryptionPin);e==nil{t.Fatal("legacy quorum domain opened direct key")}
 }
 for i,d:=range dirs{
  other:=ids[1-i]
  c:=fixtureContact(t,map[string]string{"address":other.Address,"deviceId":other.Device,"signing":other.Signing,"encryption":other.Encryption,"kemPublic":other.KemPublic,"dsaPublic":other.DsaPublic})
  c.Expires=time.Now().Add(time.Hour).UnixMilli()
  raw,e:=json.Marshal([]senderContact{c});if e!=nil{t.Fatal(e)}
  pins[i]=hexHash(raw)
  if e=winDirectImport(d,pins[i],raw);e!=nil{t.Fatal(e)}
  if e=winDirectImport(d,pins[i],raw);e==nil{t.Fatal("contact overwritten")}
 }
 c:=pqContext{ClientMessageID:"qs-direct-test-0001",From:ids[0].Address,FromDeviceID:ids[0].Device,To:ids[1].Address,ToDeviceID:ids[1].Device}
 plain:=[]byte("{\"subject\":\"Direct local test\",\"body\":\"No external service\"}")
 raw,e:=json.Marshal(directDraft{c,plain});if e!=nil{t.Fatal(e)}
 draft:="draft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json"
 if e=winWriteEncryptedDraft(filepath.Join(dirs[0],draft),raw);e!=nil{t.Fatal(e)}
 prompt:=func(s string,_ bool)([]byte,error){if s=="Phrase secrete classique"{return bytes.Clone(pass),nil};return bytes.Clone(pqpass),nil}
 approve:=func(string)bool{return true}
 no:=func(string)bool{return false}
 seal:=directOperation{"seal",draft,pins[0],false}
 if _,e=winDirectMail(dirs[0],seal,prompt,no);e==nil{t.Fatal("no consent")}
 r,e:=winDirectMail(dirs[0],seal,prompt,approve);if e!=nil||r.HybridEnvelope==nil||r.SenderAuth==nil{t.Fatal("seal",e)}
 if _,e=winDirectMail(dirs[0],seal,prompt,approve);e==nil{t.Fatal("duplicate encryption")}
 seal.Recover=true
 rec,e:=winDirectMail(dirs[0],seal,prompt,approve);if e!=nil{t.Fatal(e)}
 a,_:=json.Marshal(r);b,_:=json.Marshal(rec);if !bytes.Equal(a,b){t.Fatal("result changed on reopen")}
 w:=directWire{"quantic-native-mail",1,c,*r.HybridEnvelope,*r.SenderAuth}
 wire,e:=json.Marshal(w);if e!=nil{t.Fatal(e)}
 name:="wire-in-"+hex.EncodeToString(make([]byte,20))+".json"
 if e=winWritePrivate(filepath.Join(dirs[1],name),wire);e!=nil{t.Fatal(e)}
 open:=directOperation{"open",name,pins[1],false}
 got,e:=winDirectMail(dirs[1],open,prompt,approve);if e!=nil||got.Message==nil{t.Fatal("open",e)}
 decrypted,e:=b64.DecodeString(*got.Message);if e!=nil||!bytes.Equal(decrypted,plain){t.Fatal("message changed")}
 if _,e=winDirectMail(dirs[1],open,prompt,approve);e==nil{t.Fatal("duplicate open")}
 open.Recover=true
 got,e=winDirectMail(dirs[1],open,prompt,approve);if e!=nil||got.Message==nil{t.Fatal("recover",e)}
 open.ContactPin=hex.EncodeToString(make([]byte,32))
 if _,e=winDirectMail(dirs[1],open,prompt,approve);e==nil{t.Fatal("wrong trust pin")}
 if _,e=winReadDirectIdentity(filepath.Join(root,"missing"));e==nil{t.Fatal("invalid identity")}
}
