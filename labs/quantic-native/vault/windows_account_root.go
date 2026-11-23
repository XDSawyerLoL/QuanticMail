//go:build windows && cgo && pqopenssl

package main

import (
 "bytes"
 "crypto/rand"
 "encoding/json"
 "os"
 "path/filepath"
)

// Synthetic account-root custody is distinct from the existing *device*
// ML-DSA sidecar. Software-encrypted PKCS#8 is recoverable with the passphrase:
// this is NOT non-exportable hardware custody or protection from a compromised
// process. Real account enrollment, revocation and cutover remain disabled.
const winPQRootDomain="quantic-windows-account-pq-root-lab/v1\x00"

func winPQRootBinding(app,quorum,addr,device,sign,enc,kem,dsa string)(string,error){
 pub,e:=appPublic(app);if e!=nil{return "",e}
 if !strongAddr.MatchString(addr)||!strongDevice.MatchString(device){return "",portableRefusal}
 for _,pin:=range []string{quorum,sign,enc,kem,dsa}{
  if !hashRE.MatchString(pin){return "",portableRefusal}
 }
 return winPQRootDomain+hexHash(pub)+"\x00"+quorum+"\x00"+addr+"\x00"+device+"\x00"+
  sign+"\x00"+enc+"\x00"+kem+"\x00"+dsa+"\x00",nil
}
func winPQRootLabDirectory(dir,app string)error{
 pub,e:=appPublic(app);if e!=nil{return e}
 marker,e:=winReadPrivate(filepath.Join(dir,"lab-provisioned"),64)
 if e!=nil{return e};defer clear(marker)
 if !bytes.Equal(marker,[]byte(hexHash(pub))){return portableRefusal}
 // Refuse root creation in arbitrary new directories, or in a partially
 // provisioned vault missing either its classical or device PQ sidecar.
 for _,name:=range []string{"classical.vault","pq.vault","journal.log"}{
  raw,e:=winReadPrivate(filepath.Join(dir,name),50000)
  if e!=nil{return e}
  clear(raw)
 }
 return nil
}
func winSealAccountRoot(key pqKey,binding string,pw []byte)([]byte,error){
 if !validPortablePassword(pw)||len(binding)<100{return nil,portableRefusal}
 der,e:=key.der(true);if e!=nil{return nil,e};defer clear(der)
 salt,nonce:=make([]byte,16),make([]byte,12)
 if _,e=rand.Read(salt);e!=nil{return nil,e}
 if _,e=rand.Read(nonce);e!=nil{return nil,e}
 g,e:=portableAEAD(pw,salt);if e!=nil{return nil,e}
 header:=make([]byte,0,len(binding)+28)
 header=append(header,[]byte(binding)...)
 header=append(header,salt...)
 header=append(header,nonce...)
 return g.Seal(header,nonce,der,header),nil
}
func winOpenAccountRoot(path,binding string,pw []byte,expectedRootPin string)(pqKey,[]byte,error){
 if !validPortablePassword(pw)||!hashRE.MatchString(expectedRootPin)||len(binding)<100{
  return pqKey{},nil,portableRefusal
 }
 raw,e:=winReadPrivate(path,16384);if e!=nil{return pqKey{},nil,e}
 defer clear(raw)
 h:=len(binding)
 if len(raw)<=h+16+12+16||!bytes.Equal(raw[:h],[]byte(binding)){
  return pqKey{},nil,portableRefusal
 }
 g,e:=portableAEAD(pw,raw[h:h+16]);if e!=nil{return pqKey{},nil,e}
 der,e:=g.Open(nil,raw[h+16:h+28],raw[h+28:],raw[:h+28])
 if e!=nil{return pqKey{},nil,portableRefusal}
 defer clear(der)
 key,e:=pqImport(der,"ML-DSA-65");if e!=nil{return pqKey{},nil,e}
 public,e:=key.der(false)
 if e!=nil{key.close();return pqKey{},nil,e}
 if len(public)!=1974||hexHash(public)!=expectedRootPin{
  key.close();clear(public);return pqKey{},nil,portableRefusal
 }
 return key,public,nil
}
func winProveAccountRoot(key pqKey,public []byte,binding string)error{
 challenge:=make([]byte,32)
 if _,e:=rand.Read(challenge);e!=nil{return e}
 message:=append([]byte("quantic-account-root-proof-lab/v1\x00"+binding),challenge...)
 defer clear(message)
 signature,e:=key.sign(message);if e!=nil{return e}
 defer clear(signature)
 if !pqVerifyRoot(public,message,signature){return portableRefusal}
 return nil
}
func winVerifyAccountRoot(dir,app,binding,expectedRootPin string,pw []byte)(map[string]any,error){
 if e:=winPQRootLabDirectory(dir,app);e!=nil{return nil,e}
 key,public,e:=winOpenAccountRoot(filepath.Join(dir,"account-root.pq.vault"),binding,pw,expectedRootPin)
 if e!=nil{return nil,e}
 defer key.close();defer clear(public)
 if e=winProveAccountRoot(key,public,binding);e!=nil{return nil,e}
 return map[string]any{
  "kind":"synthetic-windows-account-pq-root",
  "rootPin":expectedRootPin,
  "rootPossessionVerified":true,
  "rootFileReopened":true,
  "softwareEncryptedPrivateKey":true,
  "hardwareNonExportable":false,
  "nativeAccountEnrolled":false,
  "realIdentityMigrationAuthorized":false,
  "legacyKeyDeletionAuthorized":false,
 },nil
}
func winCreateAccountRoot(dir,app,binding string,pw []byte)(map[string]any,error){
 if e:=winPQRootLabDirectory(dir,app);e!=nil{return nil,e}
 if !validPortablePassword(pw){return nil,portableRefusal}
 root,e:=pqGenerate("ML-DSA-65");if e!=nil{return nil,e}
 defer root.close()
 public,e:=root.der(false);if e!=nil{return nil,e};defer clear(public)
 if len(public)!=1974{return nil,portableRefusal}
 expected:=hexHash(public)
 encrypted,e:=winSealAccountRoot(root,binding,pw);if e!=nil{return nil,e}
 defer clear(encrypted)
 // The NTFS primitive creates exclusively and never overwrites any existing
 // root. Failed verification leaves the file for explicit operator recovery.
 if e=winWritePrivate(filepath.Join(dir,"account-root.pq.vault"),encrypted);e!=nil{return nil,e}
 report,e:=winVerifyAccountRoot(dir,app,binding,expected,pw)
 if e!=nil{return nil,e}
 report["rootPublic"]=b64.EncodeToString(public)
 report["rootProvisioned"]=true
 return report,nil
}
func winAccountRootCLI(args []string)(bool,error){
 if len(args)<2{return false,nil}
 provision:=args[1]=="--provision-windows-account-root-lab"
 verify:=args[1]=="--verify-windows-account-root-lab"
 if !provision&&!verify{return false,nil}
 if provision&&len(args)!=11||verify&&len(args)!=12{return true,portableRefusal}
 // args: dir app quorum address device classical-sign classical-enc
 //       device-MLKEM device-MLDSA [externally pinned account-root]
 dir,app,quorum,addr,device:=args[2],args[3],args[4],args[5],args[6]
 binding,e:=winPQRootBinding(app,quorum,addr,device,args[7],args[8],args[9],args[10])
 if e!=nil{return true,e}
 if e=winPQRootLabDirectory(dir,app);e!=nil{return true,e}
 expected:=""
 if verify{
  expected=args[11]
  if !hashRE.MatchString(expected){return true,portableRefusal}
 }
 action:="Create an independent, synthetic ML-DSA account root (no real identity, no auto enrollment)."
 if verify{action="Verify previously provisioned ML-DSA account root against an INDEPENDENT pinned fingerprint."}
 if !winApprove(action){return true,portableRefusal}
 var pw []byte
 if provision{pw,e=winConfirmSecret("New separate account-root passphrase: ")}
 if verify{pw,e=winConsoleLine("Account-root passphrase (local only): ",true)}
 if e!=nil{return true,e};defer clear(pw)
 var report map[string]any
 if provision{report,e=winCreateAccountRoot(dir,app,binding,pw)}
 if verify{report,e=winVerifyAccountRoot(dir,app,binding,expected,pw)}
 if e!=nil{return true,e}
 return true,json.NewEncoder(os.Stdout).Encode(report)
}
