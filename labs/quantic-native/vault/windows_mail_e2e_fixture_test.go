//go:build windows && cgo && pqopenssl

package main

// This file is linked ONLY into go test -c, never Vault-PQ-lab.exe.
// Fixed synthetic passphrases and no quorum integration: this tests the
// actual Windows vault persistence, cryptographic envelope and contact checks.
import (
 "bytes"
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/x509"
 "encoding/json"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

type windowsMailFixtureWire struct {
 Format string `json:"format"`
 Version int `json:"version"`
 Context pqContext `json:"context"`
 Envelope pqEnvelope `json:"envelope"`
 Auth senderAuth `json:"senderAuth"`
}
type windowsMailFixtureDraft struct {
 Context pqContext `json:"context"`
 Payload json.RawMessage `json:"payload"`
}
func fixtureReport(t *testing.T,v any){
 t.Helper()
 b,e:=json.Marshal(v);if e!=nil{t.Fatal(e)}
 fmt.Println("QS_FIXTURE:"+string(b))
}
func fixturePassword(role string)([]byte,[]byte){
 return []byte("SYNTHETIC classical fixture "+role+" ONLY"),[]byte("SYNTHETIC post-quantum fixture "+role+" ONLY")
}
func fixtureAddress(role string)string{
 if role=="alice"{return "alice~"+strings.Repeat("a",32)+"@quantic"}
 return "bobby~"+strings.Repeat("b",32)+"@quantic"
}
func fixtureSPKI(t *testing.T,point string)[]byte{
 t.Helper()
 b,e:=b64.DecodeString(point);if e!=nil{t.Fatal(e)}
 x,y:=elliptic.Unmarshal(elliptic.P256(),b);if x==nil||y==nil{t.Fatal("invalid fixture point")}
 der,e:=x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{Curve:elliptic.P256(),X:x,Y:y});if e!=nil{t.Fatal(e)}
 return der
}
func fixtureContact(t *testing.T,m map[string]string) senderContact{
 t.Helper()
 kem,e:=b64.DecodeString(m["kemPublic"]);if e!=nil{t.Fatal(e)}
 dsa,e:=b64.DecodeString(m["dsaPublic"]);if e!=nil{t.Fatal(e)}
 return senderContact{Address:m["address"],Device:m["deviceId"],ClassicalRoot:fixtureSPKI(t,m["signing"]),PQRoot:dsa,Encryption:fixtureSPKI(t,m["encryption"]),KEM:kem,Expires:time.Now().Add(time.Hour).UnixMilli()}
}
func fixtureLoad(t *testing.T,dir,role,quorum string)(portableKeys,*pqKeys,*senderTrust){
 t.Helper()
 raw,e:=winReadPrivate(filepath.Join(dir,"fixture-public.json"),16384);if e!=nil{t.Fatal(e)}
 var m map[string]string
 if json.Unmarshal(raw,&m)!=nil||m["address"]!=fixtureAddress(role){t.Fatal("fixture identity mismatch")}
 pub,e:=appPublic(m["controllerPublic"]);if e!=nil{t.Fatal(e)}
 pw,pqw:=fixturePassword(role);defer clear(pw);defer clear(pqw)
 k,e:=winReadClassical(filepath.Join(dir,"classical.vault"),anchoredMagic+"compact-manifest-quorum:"+quorum+"\x00",pw,m["signingPin"],m["encryptionPin"]);if e!=nil{t.Fatal(e)}
 bind,e:=pqBinding(m["signingPin"],m["encryptionPin"],hexHash(pub),quorum,m["address"],m["deviceId"]);if e!=nil{t.Fatal(e)}
 p,e:=winReadPQ(filepath.Join(dir,"pq.vault"),bind,pqw,m["address"],m["deviceId"],m["kemPin"],m["dsaPin"]);if e!=nil{t.Fatal(e)}
 raw,e=winReadPrivate(filepath.Join(dir,"contacts.json"),131072);if e!=nil{p.close();t.Fatal(e)}
 trust,e:=parseSenderTrust(raw);if e!=nil{p.close();t.Fatal(e)}
 return k,p,trust
}
func TestWindowsMailE2EFixture(t *testing.T){
 stage,root:=os.Getenv("QS_MAIL_E2E_STAGE"),os.Getenv("QS_MAIL_E2E_ROOT")
 if stage==""{t.Skip("only run by synthetic installed integration harness")}
 if !filepath.IsAbs(root)||!strings.HasPrefix(filepath.Base(root),"qs-mail-e2e-"){t.Fatal("synthetic temporary root required")}
 quorum:=strings.Repeat("a",64)
 a,b:=filepath.Join(root,"alice"),filepath.Join(root,"bob")
 switch stage{
 case "init":
  maps:=make([]map[string]string,2)
  for i,role:=range []string{"alice","bob"}{
   pw,pqw:=fixturePassword(role)
   dir:=[]string{a,b}[i]
   m,e:=winProvisionAutoController(dir,quorum,fixtureAddress(role),pw,pqw)
   clear(pw);clear(pqw);if e!=nil{t.Fatal(e)}
   raw,e:=json.Marshal(m);if e!=nil{t.Fatal(e)}
   if e=winWritePrivate(filepath.Join(dir,"fixture-public.json"),raw);e!=nil{t.Fatal(e)}
   maps[i]=m
  }
  if maps[0]["deviceId"]==maps[1]["deviceId"]||maps[0]["kemPin"]==maps[1]["kemPin"]{t.Fatal("not independent")}
  for i,dir:=range []string{a,b}{
   raw,e:=json.Marshal([]senderContact{fixtureContact(t,maps[1-i])});if e!=nil{t.Fatal(e)}
   if e=winWritePrivate(filepath.Join(dir,"contacts.json"),raw);e!=nil{t.Fatal(e)}
  }
  fixtureReport(t,maps)
 case "seal":
  k,p,trust:=fixtureLoad(t,a,"alice",quorum);defer p.close()
  name:=os.Getenv("QS_MAIL_E2E_DRAFT")
  if !clientDraftName.MatchString(name){t.Fatal("fixture draft name")}
  raw,e:=winReadEncryptedDraft(filepath.Join(a,name));if e!=nil{t.Fatal(e)};defer clear(raw)
  var d windowsMailFixtureDraft
  if json.Unmarshal(raw,&d)!=nil{t.Fatal("draft")}
  peer,ok:=trust.contacts[senderKey(d.Context.To,d.Context.ToDeviceID)]
  if !ok||peer.Expires<=time.Now().UnixMilli(){t.Fatal("untrusted recipient")}
  env,auth,e:=p.sealOutgoing(softwareSigner{k.signing},d.Context,peer,d.Payload);if e!=nil{t.Fatal(e)}
  fixtureReport(t,windowsMailFixtureWire{"quantic-native-mail",1,d.Context,env,auth})
 case "open":
  k,p,trust:=fixtureLoad(t,b,"bob",quorum);defer p.close()
  raw,e:=io.ReadAll(io.LimitReader(os.Stdin,32769));if e!=nil||len(raw)>32768{t.Fatal("wire input")}
  var w windowsMailFixtureWire
  dec:=json.NewDecoder(bytes.NewReader(raw));dec.DisallowUnknownFields()
  if dec.Decode(&w)!=nil||w.Format!="quantic-native-mail"||w.Version!=1{t.Fatal("wire shape")}
  if !trust.verify(w.Context,w.Envelope,&w.Auth,time.Now().UnixMilli()){t.Fatal("sender authentication")}
  payload,e:=p.open(k.agreement,w.Context,w.Envelope);if e!=nil{t.Fatal(e)};defer clear(payload)
  if !json.Valid(payload){t.Fatal("payload")}
  fixtureReport(t,json.RawMessage(payload))
 default:
  t.Fatal("unknown synthetic stage")
 }
}
