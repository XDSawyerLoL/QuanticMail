//go:build windows && cgo && pqopenssl

package main

import (
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "encoding/json"
 "strings"
 "testing"
 "time"
)
func TestSyntheticContactCardSignedButNeverAuthorized(t *testing.T){
 pub,private,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
 p:=sampleSyntheticProfile()
 p.ControllerPublic=base64.RawURLEncoding.EncodeToString(pub)
 now:=time.Now().Unix()
 code,fp,e:=newSyntheticCard(p,private,now)
 if e!=nil{t.Fatal(e)}
 if !strings.HasPrefix(code,syntheticCardPrefix)||len(fp)!=24{t.Fatal("invalid card")}
 result,e:=verifySyntheticCard(code,"",now)
 if e!=nil{t.Fatal(e)}
 if result.MailAuthorized||result.IndependentlyVerified||!result.LabOnly||
  result.Status!="contact-candidate-not-trusted"||result.Address!=p.Address||result.Fingerprint!=fp{
  t.Fatal("synthetic card elevated to trusted contact")
 }
 if _,e=verifySyntheticCard(code,p.Address,now);e==nil{t.Fatal("self pairing allowed")}
 if _,e=verifySyntheticCard(code,"",now+24*3600);e==nil{t.Fatal("expired card accepted")}
 if _,e=verifySyntheticCard(code,"",now-301);e==nil{t.Fatal("future card accepted")}
 if _,e=verifySyntheticCard(code+"X","",now);e==nil{t.Fatal("appended bytes accepted")}
 raw,e:=base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code,syntheticCardPrefix));if e!=nil{t.Fatal(e)}
 var card syntheticCard
 if e=json.Unmarshal(raw,&card);e!=nil{t.Fatal(e)}
 card.Payload.KemPin=strings.Repeat("f",64)
 edited,_:=json.Marshal(card)
 if _,e=verifySyntheticCard(syntheticCardPrefix+base64.RawURLEncoding.EncodeToString(edited),"",now);e==nil{
  t.Fatal("tampered signed PQ key accepted")
 }
 card.Payload.KemPin=p.KemPin
 card.Payload.IndependentlyVerified=true
 edited,_=json.Marshal(card)
 if _,e=verifySyntheticCard(syntheticCardPrefix+base64.RawURLEncoding.EncodeToString(edited),"",now);e==nil{
  t.Fatal("claim of independent authority accepted")
 }
}
func TestNativeSyntheticRegistryAndContactCommandsFailClosed(t *testing.T){
 for _,args:=range [][]string{
  {"Vault.exe"},
  {"Vault.exe","--gui-share-synthetic-contact-card-lab"},
  {"Vault.exe","--gui-add-synthetic-contact-candidate-lab"},
  {"Vault.exe","--gui-share-synthetic-contact-card-lab","C:\\Temp","more"},
  {"Vault.exe","--gui-list-synthetic-identities-lab","C:\\Temp","extra"},
  {"Vault.exe","--unknown","C:\\Temp"},
 }{
  if e:=winGUIContactCard(args);e==nil{t.Fatalf("invalid contact command accepted %v",args)}
 }
 if e:=winGUIListSyntheticVaults([]string{"Vault.exe","--gui-list-synthetic-identities-lab","\\\\server\\share"});e==nil{
  t.Fatal("uncanonical remote registry accepted")
 }
 if !syntheticDirectoryName.MatchString("quantic-test-0123456789abcdef")||
  syntheticDirectoryName.MatchString("quantic-test-0123456789abcdef\\..")||
  syntheticDirectoryName.MatchString("quantic-test-0123456789abcdef.json"){
  t.Fatal("unexpected registry naming policy")
 }
}
