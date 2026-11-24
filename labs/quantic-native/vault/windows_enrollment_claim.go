//go:build windows && cgo && pqopenssl

package main

import (
 "crypto/ecdsa"
 "crypto/ed25519"
 "crypto/elliptic"
 "crypto/rand"
 "encoding/json"
 "os"
 "path/filepath"
 "time"
)

// New enrollment candidate only. The quorum anchor must come from an
// independent authenticated operator. No enrollment or legacy migration.
func prepareWindowsEnrollmentVault(parent,handle,quorum string,devicePW,pqPW,ownerPW []byte)(enrollmentClaim,string,error){
 var empty enrollmentClaim
 if !enrollmentHandle.MatchString(handle)||!hashRE.MatchString(quorum)||
  !validPortablePassword(devicePW)||!validPortablePassword(pqPW)||!validPortablePassword(ownerPW)||
  equalSecret(devicePW,pqPW)||equalSecret(devicePW,ownerPW)||equalSecret(pqPW,ownerPW){
  return empty,"",portableRefusal
 }
 handles,e:=winLockDirectory(parent,false);if e!=nil{return empty,"",e};defer winClose(handles)
 owner,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if e!=nil{return empty,"",e}
 ownerPoint,e:=enrollmentPoint(elliptic.Marshal(elliptic.P256(),owner.X,owner.Y));if e!=nil{return empty,"",e}
 addr:=handle+"~"+enrollmentFingerprint(ownerPoint)+"@quantic"
 dir:=filepath.Join(parent,"quantic-enroll-"+enrollmentFingerprint(ownerPoint)[:16])
 if _,_,e=winPathParts(filepath.Join(dir,"journal.log.result-"+"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));e!=nil{return empty,"",e}
 device,e:=freshPortable();if e!=nil{return empty,"",e}
 enc,e:=enrollmentPoint(device.agreement.PublicKey().Bytes());if e!=nil{return empty,"",e}
 id:="d-"+enrollmentFingerprint(enc)
 kem,e:=pqGenerate("ML-KEM-768");if e!=nil{return empty,"",e};defer kem.close()
 dsa,e:=pqGenerate("ML-DSA-65");if e!=nil{return empty,"",e};defer dsa.close()
 pq,e:=pqMake(kem,dsa,addr,id);if e!=nil{return empty,"",e}
 rootPQ,e:=pqGenerate("ML-DSA-65");if e!=nil{return empty,"",e};defer rootPQ.close()
 claim,e:=nativeEnrollmentClaim(handle,owner,device,pq,rootPQ,time.Now());if e!=nil{return empty,"",e}
 pub,controller,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{return empty,"",e};defer clear(controller)
 request,e:=signEnrollmentRequest(claim,quorum,b64.EncodeToString(pub),owner,rootPQ)
 if e!=nil{return empty,"",e}
 ownerSealed,e:=sealEnrollmentRoots(owner,rootPQ,claim,ownerPW)
 if e!=nil{return empty,"",e};defer clear(ownerSealed)
 appPin:=hexHash(pub)
 binding,e:=pqBinding(claim.SigningPin,claim.EncryptionPin,appPin,quorum,addr,id);if e!=nil{return empty,"",e}
 magic:=anchoredMagic+"compact-manifest-quorum:"+quorum+"\x00"
 if e=winCreatePrivateDirectory(dir);e!=nil{return empty,"",e}
 if e=winWriteClassical(filepath.Join(dir,"classical.vault"),magic,devicePW,device);e!=nil{return empty,"",e}
 if e=winWritePQ(filepath.Join(dir,"pq.vault"),binding,pqPW,pq);e!=nil{return empty,"",e}
 if e=winWritePrivate(filepath.Join(dir,"owner-roots.vault"),ownerSealed);e!=nil{return empty,"",e}
 if e=winInitReplay(filepath.Join(dir,"journal.log"),claim.SigningPin,claim.EncryptionPin,appPin);e!=nil{return empty,"",e}
 var receipt [32]byte
 if _,e=rand.Read(receipt[:]);e!=nil{return empty,"",e};defer clear(receipt[:])
 if e=writeLocalCustody(dir,"receipt",request,receipt[:],devicePW,pqPW);e!=nil{return empty,"",e}
 seed:=controller.Seed();defer clear(seed)
 if e=writeLocalCustody(dir,"controller",request,seed,devicePW,pqPW);e!=nil{return empty,"",e}
 verified,e:=readEnrollmentController(dir,request,devicePW,pqPW);if e!=nil{return empty,"",e};clear(verified)
 receiptCheck,e:=readLocalCustody(dir,"receipt",request,devicePW,pqPW);if e!=nil{return empty,"",e};defer clear(receiptCheck)
 if !equalSecret(receiptCheck,receipt[:]){return empty,"",portableRefusal}
 reopened,e:=winReadClassical(filepath.Join(dir,"classical.vault"),magic,devicePW,claim.SigningPin,claim.EncryptionPin)
 if e!=nil||reopened.signing==nil{return empty,"",portableRefusal}
 reopenedPQ,e:=winReadPQ(filepath.Join(dir,"pq.vault"),binding,pqPW,addr,id,claim.KemPin,claim.DsaPin)
 if e!=nil{return empty,"",e};reopenedPQ.close()
 rootBytes,e:=winReadPrivate(filepath.Join(dir,"owner-roots.vault"),50000)
 if e!=nil{return empty,"",e};defer clear(rootBytes)
 if e=verifySealedEnrollmentRoots(rootBytes,claim,ownerPW);e!=nil{return empty,"",e}
 raw,e:=json.Marshal(request);if e!=nil{return empty,"",e}
 if e=winWritePrivate(filepath.Join(dir,"enrollment-request.json"),raw);e!=nil{return empty,"",e}
 if e=winWritePrivate(filepath.Join(dir,"lab-provisioned"),[]byte(appPin));e!=nil{return empty,"",e}
 return claim,dir,nil
}
func windowsPrepareEnrollmentCLI(args []string)error{
 if len(args)!=5||args[1]!="--gui-prepare-enrollment-claim-lab"||
  !enrollmentHandle.MatchString(args[3])||!hashRE.MatchString(args[4]){return portableRefusal}
 if _,_,e:=winPathParts(args[2]);e!=nil{return e}
 if !winGUIApprove("NOUVELLE IDENTITE FICTIVE. L'empreinte de quorum doit venir d'un operateur independant. Aucun compte distant ne sera cree. Continuer ?"){return portableRefusal}
 pw,e:=guiNewPassword("Secret de l'appareil classique");if e!=nil{return e};defer clear(pw)
 pqw,e:=guiNewPassword("Secret de l'appareil post-quantique");if e!=nil{return e};defer clear(pqw)
 ownerPW,e:=guiNewPassword("Secret distinct de sauvegarde des racines proprietaires");if e!=nil{return e};defer clear(ownerPW)
 c,dir,e:=prepareWindowsEnrollmentVault(args[2],args[3],args[4],pw,pqw,ownerPW)
 if e!=nil{return e}
 request,e:=winReadPrivate(filepath.Join(dir,"enrollment-request.json"),50000)
 if e!=nil{return e}
 return json.NewEncoder(os.Stdout).Encode(struct{
  Status string `json:"status"`
  Directory string `json:"directory"`
  Address string `json:"address"`
  Code string `json:"code"`
  LabOnly bool `json:"labOnly"`
  RemotelyEnrolled bool `json:"remotelyEnrolled"`
 }{"signed-claim-not-enrolled",dir,c.Address,"QSENROLL1:"+b64.EncodeToString(request),true,false})
}
