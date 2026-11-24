//go:build windows && cgo && pqopenssl

package main

import (
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/json"
 "io"
 "os"
 "path/filepath"
 "strings"
 "time"
)
func prepareWindowsMailboxCredential(dir string,b enrollmentApprovalBundle,pin string,pw,pqw []byte,now time.Time)(enrollmentCredential,string,error){
 var empty enrollmentCredential
 r,e:=readPendingEnrollment(dir);if e!=nil{return empty,"",e}
 digest,e:=checkEnrollmentApprovals(r,b,pin,now);if e!=nil{return empty,"",e}
 c:=r.Claim
 if _,e=winReadClassical(filepath.Join(dir,"classical.vault"),anchoredMagic+"compact-manifest-quorum:"+r.QuorumPin+"\x00",pw,c.SigningPin,c.EncryptionPin);e!=nil{return empty,"",e}
 pub,e:=decode(r.ControllerPublic,32,32);if e!=nil{return empty,"",e}
 binding,e:=pqBinding(c.SigningPin,c.EncryptionPin,hexHash(pub),r.QuorumPin,c.Address,c.DeviceID);if e!=nil{return empty,"",e}
 pq,e:=winReadPQ(filepath.Join(dir,"pq.vault"),binding,pqw,c.Address,c.DeviceID,c.KemPin,c.DsaPin);if e!=nil{return empty,"",e};pq.close()
 key,e:=readEnrollmentController(dir,r,pw,pqw);if e!=nil{return empty,"",e};defer clear(key)
 if !bytes.Equal(key.Public().(ed25519.PublicKey),pub){return empty,"",portableRefusal}
 path:=filepath.Join(dir,"mailbox-token.vault")
 raw,e:=winReadPrivate(path,1024)
 if e!=nil{
  // Exclusive creation. If read was refused (rather than missing), this
  // still cannot overwrite or repair a pre-existing file.
  token:=make([]byte,32);defer clear(token)
  if _,e=rand.Read(token);e!=nil{return empty,"",e}
  sealed,e:=sealNativeMailboxCredential(token,digest,pw,pqw);if e!=nil{return empty,"",e};defer clear(sealed)
  if e=winWritePrivate(path,sealed);e!=nil{return empty,"",e}
  raw,e=winReadPrivate(path,1024);if e!=nil{return empty,"",e}
 }
 defer clear(raw)
 token,e:=openNativeMailboxCredential(raw,digest,pw,pqw);if e!=nil{return empty,"",e};defer clear(token)
 // Do not return a proof after the approval window has expired.
 if _,e=checkEnrollmentApprovals(r,b,pin,time.Now());e!=nil{return empty,"",e}
 proof,e:=nativeMailboxCredentialProof(token,digest,key)
 return proof,digest,e
}
func windowsMailboxCredentialCLI(args []string)error{
 if len(args)!=4||args[1]!="--gui-prepare-mailbox-credential-lab"||!hashRE.MatchString(args[3]){return portableRefusal}
 dir,pin:=args[2],args[3]
 r,e:=readPendingEnrollment(dir);if e!=nil{return e}
 raw,e:=io.ReadAll(io.LimitReader(os.Stdin,20001));if e!=nil||len(raw)>20000{return portableRefusal}
 code:=string(raw);if !strings.HasPrefix(code,"QSAPPROVAL1:"){return portableRefusal}
 encoded:=strings.TrimPrefix(code,"QSAPPROVAL1:")
 data,e:=b64.DecodeString(encoded);if e!=nil||b64.EncodeToString(data)!=encoded{return portableRefusal}
 var bundle enrollmentApprovalBundle
 d:=json.NewDecoder(bytes.NewReader(data));d.DisallowUnknownFields()
 if e=d.Decode(&bundle);e!=nil{return e};var trailing any;if e=d.Decode(&trailing);e!=io.EOF{return portableRefusal}
 if _,e=checkEnrollmentApprovals(r,bundle,pin,time.Now());e!=nil{return e}
 if !winGUIApprove("Trois approbations de laboratoire verifiees pour "+r.Claim.Address+". Creer ou retrouver le jeton chiffre local, sans activation distante ?"){return portableRefusal}
 pw,e:=winGUIPassphrase("Secret classique de l'appareil",true);if e!=nil{return e};defer clear(pw)
 pqw,e:=winGUIPassphrase("Secret post-quantique de l'appareil",true);if e!=nil{return e};defer clear(pqw)
 proof,digest,e:=prepareWindowsMailboxCredential(dir,bundle,pin,pw,pqw,time.Now());if e!=nil{return e}
 transport,e:=prepareWindowsTransportRequests(dir,bundle,pin,proof,digest,pw,pqw,time.Now());if e!=nil{return e}
 csr,e:=json.Marshal(transport);if e!=nil{return e}
 public,e:=json.Marshal(proof);if e!=nil{return e}
 return json.NewEncoder(os.Stdout).Encode(struct{
  Status string `json:"status"`
  Code string `json:"code"`
  TransportCode string `json:"transportCode"`
  RequestDigest string `json:"requestDigest"`
  MailAuthorized bool `json:"mailAuthorized"`
 }{"mailbox-credential-sealed-not-activated","QSCRED1:"+b64.EncodeToString(public),"QSTLS1:"+b64.EncodeToString(csr),digest,false})
}
