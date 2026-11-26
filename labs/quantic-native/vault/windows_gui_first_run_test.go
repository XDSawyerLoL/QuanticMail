//go:build windows && cgo && pqopenssl

package main

import (
 "encoding/base64"
 "strings"
 "testing"
)

func sampleSyntheticProfile()syntheticProfile{
 return syntheticProfile{
  Version:1,LabOnly:true,Address:"alpha~"+strings.Repeat("a",32)+"@quantic",
  DeviceID:"d-"+strings.Repeat("b",32),
  QuorumPin:strings.Repeat("1",64),ControllerPublic:base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x",32))),
  SigningPin:strings.Repeat("2",64),EncryptionPin:strings.Repeat("3",64),
  KemPin:strings.Repeat("4",64),DsaPin:strings.Repeat("5",64),
 }
}
func TestSyntheticFirstRunMetadataNeverBecomesEnrollment(t *testing.T){
 p:=sampleSyntheticProfile()
 if e:=validateSyntheticProfile(p);e!=nil{t.Fatal(e)}
 for _,alter:=range []func(*syntheticProfile){
  func(p *syntheticProfile){p.Version=2},
  func(p *syntheticProfile){p.LabOnly=false},
  func(p *syntheticProfile){p.RemotelyEnrolled=true},
  func(p *syntheticProfile){p.IndependentQuorum=true},
  func(p *syntheticProfile){p.QuorumPin="0"},
  func(p *syntheticProfile){p.Address="../invalid"},
  func(p *syntheticProfile){p.DeviceID="d-traversal"},
  func(p *syntheticProfile){p.ControllerPublic="bad"},
 }{
  q:=p;alter(&q)
  if validateSyntheticProfile(q)==nil{t.Fatal("unsafe profile accepted")}
 }
}
func TestSyntheticGUICommandsRejectUnexpectedArgumentsWithoutDialogs(t *testing.T){
 for _,args:=range [][]string{
  {"Vault-PQ-lab.exe"},
  {"Vault-PQ-lab.exe","--gui-create-synthetic-identity-lab"},
  {"Vault-PQ-lab.exe","--gui-open-synthetic-identity-lab"},
  {"Vault-PQ-lab.exe","--gui-create-synthetic-identity-lab","C:\\Temp","extra"},
  {"Vault-PQ-lab.exe","--gui-open-synthetic-identity-lab","C:\\Temp","extra"},
  {"Vault-PQ-lab.exe","--unknown","C:\\Temp"},
 }{
  if winGUIFirstRun(args)==nil{t.Fatal("untrusted command accepted")}
 }
}
