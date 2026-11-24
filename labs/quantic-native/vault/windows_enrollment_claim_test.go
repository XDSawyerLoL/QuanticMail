//go:build windows && cgo && pqopenssl

package main

import (
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestWindowsEnrollmentClaimPrivatePersistence(t *testing.T){
 parent:=t.TempDir()
 pw:=[]byte("synthetic device classical password")
 pq:=[]byte("synthetic device postquantum password")
 root:=[]byte("synthetic independent owner password")
 pin:=strings.Repeat("c",64)
 if _,_,e:=prepareWindowsEnrollmentVault(parent,"testalice",pin,pw,pw,root);e==nil{t.Fatal("password reuse accepted")}
 if _,_,e:=prepareWindowsEnrollmentVault(parent,"../unsafe",pin,pw,pq,root);e==nil{t.Fatal("path escape accepted")}
 c,dir,e:=prepareWindowsEnrollmentVault(parent,"testalice",pin,pw,pq,root);if e!=nil{t.Fatal(e)}
 if filepath.Dir(dir)!=parent||c.MailAuthorized||c.RemotelyEnrolled||c.RootPin==c.SigningPin||c.PQRootPin==c.DsaPin{t.Fatal("wrong custody or status")}
 b,e:=winReadPrivate(filepath.Join(dir,"enrollment-request.json"),50000);if e!=nil{t.Fatal(e)}
 var r enrollmentRequest
 if e=json.Unmarshal(b,&r);e!=nil||r.Claim.Address!=c.Address||r.QuorumPin!=pin||r.OwnerP256Signature==""||r.OwnerMLDSASignature==""{t.Fatal("invalid persisted claim",e)}
 sealed,e:=winReadPrivate(filepath.Join(dir,"owner-roots.vault"),50000);if e!=nil{t.Fatal(e)}
 if e=verifySealedEnrollmentRoots(sealed,c,root);e!=nil{t.Fatal(e)}
 if e=verifySealedEnrollmentRoots(sealed,c,pw);e==nil{t.Fatal("device password opened owner keys")}
 for _,name:=range []string{"contacts.json","desktop.json","quorum.json","synthetic-profile.json","scattering.json"}{
  if _,e=os.Stat(filepath.Join(dir,name));!os.IsNotExist(e){t.Fatalf("unexpected implicit activation: %s",name)}
 }
 if _,e:=readSyntheticGUIProfile(dir);e==nil{t.Fatal("claim confused with former synthetic profile")}
 pending,e:=readPendingEnrollment(dir)
 if e!=nil||pending.Claim.Address!=c.Address||pending.Claim.DeviceID!=c.DeviceID{t.Fatal("pending identity discovery failed",e)}
 if _,e=readPendingEnrollment(parent);e==nil{t.Fatal("non-candidate directory accepted")}
 if e=windowsAnswerPossessionCLI([]string{"Vault.exe","--gui-answer-enrollment-possession-lab",dir,"untrusted"});e==nil{t.Fatal("bad operator pin accepted")}
 if e=windowsListEnrollmentCLI([]string{"Vault.exe","--gui-list-enrollment-candidates-lab",parent,"extra"});e==nil{t.Fatal("extra argument accepted")}

 if e=windowsPrepareEnrollmentCLI([]string{"Vault.exe","--gui-prepare-enrollment-claim-lab",parent,"testalice"});e==nil{t.Fatal("missing anchor accepted")}
}
