//go:build windows && cgo && pqopenssl

package main

import(
 "crypto/elliptic"
 "crypto/ed25519"
 "crypto/x509"
 "encoding/pem"
 "crypto/rand"
 "encoding/json"
 "os"
 "path/filepath"
)

// Explicit isolated native provision command. No web keys, TPM or network.
// Existing directories/identities cannot be overwritten; partial directories
// are retained and must never be reused as successfully provisioned.
func winProvisionVault(dir,app,quorum,addr string,pw,pqPassword []byte)(map[string]string,error){
 return winProvisionVaultLocal(dir,app,quorum,addr,pw,pqPassword,nil)
}
func winProvisionAutoController(dir,quorum,addr string,pw,pqPassword []byte)(map[string]string,error){
 pub,key,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{return nil,e};defer clear(key)
 der,e:=x509.MarshalPKCS8PrivateKey(key);if e!=nil{return nil,e};defer clear(der)
 data:=pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:der});defer clear(data)
 result,e:=winProvisionVaultLocal(dir,b64.EncodeToString(pub),quorum,addr,pw,pqPassword,data)
 if e!=nil{return nil,e}
 result["controllerPublic"]=b64.EncodeToString(pub)
 return result,nil
}
func winProvisionVaultLocal(dir,app,quorum,addr string,pw,pqPassword,controller []byte)(map[string]string,error){
 if !hashRE.MatchString(quorum)||!strongAddr.MatchString(addr)||!validPortablePassword(pw)||!validPortablePassword(pqPassword)||equalSecret(pw,pqPassword){return nil,portableRefusal}
 pub,e:=appPublic(app);if e!=nil{return nil,e}
 if _,_,e=winPathParts(dir);e!=nil{return nil,e}
 // Also check the longest recovery file name before creating anything.
 if _,_,e=winPathParts(filepath.Join(dir,"journal.log.result-"+"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));e!=nil{return nil,e}
 k,e:=freshPortable();if e!=nil{return nil,e}
 s,a:=portablePins(k);point:=k.agreement.PublicKey().Bytes()
 device:="d-"+hexHash([]byte("P-256:"+b64.EncodeToString(point[1:33])+":"+b64.EncodeToString(point[33:])))[:32]
 binding,e:=pqBinding(s,a,hexHash(pub),quorum,addr,device);if e!=nil{return nil,e}
 kem,e:=pqGenerate("ML-KEM-768");if e!=nil{return nil,e};defer kem.close()
 dsa,e:=pqGenerate("ML-DSA-65");if e!=nil{return nil,e};defer dsa.close()
 p,e:=pqMake(kem,dsa,addr,device);if e!=nil{return nil,e}
 if e=winCreatePrivateDirectory(dir);e!=nil{return nil,e}
 if e=winWriteClassical(filepath.Join(dir,"classical.vault"),anchoredMagic+"compact-manifest-quorum:"+quorum+"\x00",pw,k);e!=nil{return nil,e}
 if e=winWritePQ(filepath.Join(dir,"pq.vault"),binding,pqPassword,p);e!=nil{return nil,e}
 if e=winInitReplay(filepath.Join(dir,"journal.log"),s,a,hexHash(pub));e!=nil{return nil,e}
 var receipt [32]byte;if _,e=rand.Read(receipt[:]);e!=nil{return nil,e};defer clear(receipt[:])
 if e=winWritePrivate(filepath.Join(dir,"receipt.key"),receipt[:]);e!=nil{return nil,e}
 if len(controller)>0{if e=winWritePrivate(filepath.Join(dir,"controller.pem"),controller);e!=nil{return nil,e}}
 if e=winWritePrivate(filepath.Join(dir,"lab-provisioned"),[]byte(hexHash(pub)));e!=nil{return nil,e}
 return map[string]string{"backend":"windows-software-pq-storage-lab","address":addr,"deviceId":device,"signingPin":s,"encryptionPin":a,"kemPin":p.kemPin,"dsaPin":p.dsaPin,"signing":b64.EncodeToString(elliptic.Marshal(elliptic.P256(),k.signing.X,k.signing.Y)),"encryption":b64.EncodeToString(point),"kemPublic":b64.EncodeToString(p.kemPub),"dsaPublic":b64.EncodeToString(p.dsaPub),"status":"local-provision-only-not-enrolled"},nil
}
func windowsVaultCLI(args []string)(bool,error){
 if handled,e:=winMigrationIO(args);handled{return true,e}
 if handled,e:=windowsPayCLI(args);handled{return true,e}
 if len(args)>1&&args[1]=="--windows-import-lab-file"{return true,winImportCLI(args)}
 if handled,e:=winScatteringCLI(args);handled{return true,e}
 if handled,e:=winMailLabStatus(args);handled{return true,e}
 if handled,e:=winClientIO(args);handled{return true,e}
 if len(args)>1&&(args[1]=="--broker-windows-pq-quorum-lab"||args[1]=="--broker-windows-pq-quorum-gui-lab"){return true,winBroker(args)}
 if len(args)>1&&args[1]=="--provision-windows-controller-lab"{
  if len(args)!=5||!hashRE.MatchString(args[3])||!strongAddr.MatchString(args[4]){return true,portableRefusal}
  if !winApprove("Create NEW synthetic Windows vault and local controller; no real account enrollment."){return true,portableRefusal}
  pw,e:=winConfirmSecret("New classical laboratory passphrase: ");if e!=nil{return true,e};defer clear(pw)
  pq,e:=winConfirmSecret("Different post-quantum laboratory passphrase: ");if e!=nil{return true,e};defer clear(pq)
  result,e:=winProvisionAutoController(args[2],args[3],args[4],pw,pq)
  if e!=nil{return true,e}
  return true,json.NewEncoder(os.Stdout).Encode(result)
 }
 if len(args)<2||args[1]!="--provision-windows-pq-storage-lab"{return false,nil}
 if len(args)!=6||!hashRE.MatchString(args[4])||!strongAddr.MatchString(args[5]){return true,portableRefusal}
 if _,e:=appPublic(args[3]);e!=nil{return true,e}
 if !winApprove("Create a NEW synthetic Windows vault; no existing account will be migrated."){return true,portableRefusal}
 pw,e:=winConfirmSecret("New classical laboratory passphrase: ");if e!=nil{return true,e};defer clear(pw)
 pq,e:=winConfirmSecret("Different post-quantum laboratory passphrase: ");if e!=nil{return true,e};defer clear(pq)
 result,e:=winProvisionVault(args[2],args[3],args[4],args[5],pw,pq)
 if e!=nil{return true,e}
 return true,json.NewEncoder(os.Stdout).Encode(result)
}
