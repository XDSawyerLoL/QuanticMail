//go:build windows && cgo && pqopenssl

package main

import (
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
 "bytes"
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
 for _,name:=range []string{"controller.pem","receipt.key"}{if _,e=os.Stat(filepath.Join(dir,name));!os.IsNotExist(e){t.Fatal("plaintext secret exists",name)}}
 controller,e:=readEnrollmentController(dir,r,pw,pq);if e!=nil{t.Fatal(e)};clear(controller)
 if _,e=readEnrollmentController(dir,r,pq,pw);e==nil{t.Fatal("wrong secrets opened controller")}
 key,e:=readLocalCustody(dir,"receipt",r,pw,pq);if e!=nil{t.Fatal(e)};defer clear(key)
 op,closeOp,e:=nativeReceiptTransport(c.Address,c.DeviceID,key);if e!=nil{t.Fatal(e)}
 sealedReceipt,e:=op("receipt-seal",[]byte(`{"id":"01234567-89ab-4cde-8fab-0123456789ab","digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","payload":{"subject":"synthetic","body":"private receipt example"}}`));if e!=nil||bytes.Contains(sealedReceipt,[]byte("private receipt example")){t.Fatal("receipt not sealed",e)}
 openedReceipt,e:=op("receipt-open",sealedReceipt);if e!=nil||!bytes.Contains(openedReceipt,[]byte("private receipt example")){t.Fatal("receipt not opened",e)}
 var altered nativeReceipt;if e=json.Unmarshal(sealedReceipt,&altered);e!=nil{t.Fatal(e)};altered.Digest=strings.Repeat("b",64);tampered,_:=json.Marshal(altered)
 if _,e=op("receipt-open",tampered);e==nil{t.Fatal("altered receipt accepted")}
 closeOp();if _,e=op("receipt-open",sealedReceipt);e==nil{t.Fatal("closed session reused")}
 draftKey,e:=readLocalCustody(dir,"draft",r,pw,pq);if e!=nil{t.Fatal(e)};defer clear(draftKey)
 if bytes.Equal(draftKey,key){t.Fatal("draft and receipt keys reused")}
 if _,e=readLocalCustody(dir,"draft",r,pq,pw);e==nil{t.Fatal("wrong secrets")}
 name:="draft-a1478dbe30034bb58fda0123456789ab.json"
 draft:=nativeDraft{Context:pqContext{ClientMessageID:"qs-a1478dbe-3003-4bb5-8fda-0123456789ab",From:c.Address,FromDeviceID:c.DeviceID,To:"testpeer~"+strings.Repeat("a",32)+"@quantic",ToDeviceID:"d-"+strings.Repeat("b",32)},Payload:nativeReceiptPayload{Subject:"Synthetic",Body:"private draft example"}}
 enc,e:=sealNativeDraft(draftKey,name,c.Address,c.DeviceID,draft);if e!=nil{t.Fatal(e)}
 rawDraft,e:=json.Marshal(enc);if e!=nil||bytes.Contains(rawDraft,[]byte(draft.Payload.Body))||bytes.Contains(rawDraft,[]byte(draft.Context.To)){t.Fatal("plaintext draft")}
 actual,e:=openNativeDraft(draftKey,name,c.Address,c.DeviceID,enc);if e!=nil||actual!=draft{t.Fatal("reopen draft",e)}
 if _,e=openNativeDraft(key,name,c.Address,c.DeviceID,enc);e==nil{t.Fatal("receipt key opens draft")}
 if _,e=openNativeDraft(draftKey,"draft-"+strings.Repeat("b",32)+".json",c.Address,c.DeviceID,enc);e==nil{t.Fatal("renamed draft opens")}
 if _,e=openNativeDraft(draftKey,name,draft.Context.To,c.DeviceID,enc);e==nil{t.Fatal("foreign account opens")}
 corrupt:=enc;ct,e:=decode(enc.Ciphertext,17,8208);if e!=nil{t.Fatal(e)};ct[0]^=1;corrupt.Ciphertext=b64.EncodeToString(ct)
 if _,e=openNativeDraft(draftKey,name,c.Address,c.DeviceID,corrupt);e==nil{t.Fatal("altered draft opens")}
 dOp,dClose,e:=nativeDraftTransport(c.Address,c.DeviceID,draftKey);if e!=nil{t.Fatal(e)}
 req,_:=json.Marshal(map[string]any{"file":name,"record":enc})
 decoded,e:=dOp("draft-open",req);if e!=nil||!bytes.Contains(decoded,[]byte(draft.Payload.Body)){t.Fatal("broker draft open",e)}
 dClose();if _,e=dOp("draft-open",req);e==nil{t.Fatal("closed draft session reused")}
 legacy,_:=json.Marshal(draft)
 if e=winImportLabFile(dir,name,hexHash(legacy),legacy);e==nil{t.Fatal("legacy import bypass")}
 now:=time.Now()
 approvals,roster:=credentialTestApprovals(t,r,now)
 bad:=approvals;bad.Votes=bad.Votes[:2]
 if _,_,e=prepareWindowsMailboxCredential(dir,bad,roster,pw,pq,now);e==nil{t.Fatal("two votes accepted")}
 bad=approvals;bad.Votes=append([]enrollmentVote{},approvals.Votes...);bad.Votes[2]=bad.Votes[0]
 if _,_,e=prepareWindowsMailboxCredential(dir,bad,roster,pw,pq,now);e==nil{t.Fatal("duplicate vote accepted")}
 if _,_,e=prepareWindowsMailboxCredential(dir,approvals,strings.Repeat("d",64),pw,pq,now);e==nil{t.Fatal("untrusted roster accepted")}
 if _,_,e=prepareWindowsMailboxCredential(dir,approvals,roster,pw,pq,now.Add(16*time.Minute));e==nil{t.Fatal("expired approvals accepted")}
 if _,_,e=prepareWindowsMailboxCredential(dir,approvals,roster,pw,pw,now);e==nil{t.Fatal("wrong PQ secret accepted")}
 if _,e=os.Stat(filepath.Join(dir,"mailbox-token.vault"));!os.IsNotExist(e){t.Fatal("failed proof wrote credential")}
 proof,digest,e:=prepareWindowsMailboxCredential(dir,approvals,roster,pw,pq,now);if e!=nil{t.Fatal(e)}
 raw,e:=winReadPrivate(filepath.Join(dir,"mailbox-token.vault"),1024);if e!=nil{t.Fatal(e)}
 token,e:=openNativeMailboxCredential(raw,digest,pw,pq);if e!=nil{t.Fatal(e)};defer clear(token)
 if proof.TokenHash!=hexHash([]byte(b64.EncodeToString(token)))||bytes.Contains(raw,token){t.Fatal("bad token proof or cleartext")}
 proof2,digest2,e:=prepareWindowsMailboxCredential(dir,approvals,roster,pw,pq,now)
 if e!=nil||proof2!=proof||digest2!=digest{t.Fatal("re-export changed credential",e)}
 raw2,e:=winReadPrivate(filepath.Join(dir,"mailbox-token.vault"),1024)
 if e!=nil||!bytes.Equal(raw,raw2){t.Fatal("credential unexpectedly replaced",e)}

}
