//go:build windows && cgo && pqopenssl

package main

import(
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "testing"
)

const syntheticRootPassword="synthetic unique laboratory account root passphrase only"
func TestWindowsAccountRootDurabilityAndRefusal(t *testing.T){
 pub,_,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
 app:=b64.EncodeToString(pub)
 quorum,addr:=strings.Repeat("a",64),"alice~"+strings.Repeat("b",32)+"@quantic"
 dir:=filepath.Join(t.TempDir(),"native-pq")
 res,e:=winProvisionVault(dir,app,quorum,addr,
  []byte("synthetic legacy classical passphrase only"),
  []byte("different synthetic device PQ passphrase"))
 if e!=nil{t.Fatal(e)}
 binding,e:=winPQRootBinding(app,quorum,addr,res["deviceId"],res["signingPin"],res["encryptionPin"],res["kemPin"],res["dsaPin"])
 if e!=nil{t.Fatal(e)}
 root,e:=winCreateAccountRoot(dir,app,binding,[]byte(syntheticRootPassword))
 if e!=nil{t.Fatal(e)}
 if root["rootPossessionVerified"]!=true||root["nativeAccountEnrolled"]!=false||
    root["realIdentityMigrationAuthorized"]!=false||root["hardwareNonExportable"]!=false{
  t.Fatal("unsafe or missing root report")
 }
 rootPin:=root["rootPin"].(string)
 if rootPin==res["dsaPin"]{t.Fatal("account root reused device signer")}
 if _,e=winCreateAccountRoot(dir,app,binding,[]byte(syntheticRootPassword));e==nil{
  t.Fatal("account root overwrite accepted")
 }
 if _,e=winVerifyAccountRoot(dir,app,binding,rootPin,[]byte(syntheticRootPassword));e!=nil{t.Fatal(e)}
 if _,e=winVerifyAccountRoot(dir,app,binding,strings.Repeat("0",64),[]byte(syntheticRootPassword));e==nil{t.Fatal("root substitution accepted")}
 if _,e=winVerifyAccountRoot(dir,app,binding,rootPin,[]byte("wrong synthetic passphrase"));e==nil{t.Fatal("wrong password accepted")}
 if _,e=winVerifyAccountRoot(dir,app,binding+"mismatch",rootPin,[]byte(syntheticRootPassword));e==nil{t.Fatal("wrong identity context accepted")}
 if _,e=winVerifyAccountRoot(dir,app,binding,rootPin,[]byte(syntheticRootPassword));e!=nil{t.Fatal(e)}

 // Independent OS process: no parent key handle or decrypted private key is
 // inherited. The passphrase in this test-only child environment is synthetic.
 cmd:=exec.Command(os.Args[0],"-test.run=^TestWindowsAccountRootSeparateProcess$")
 cmd.Env=append(os.Environ(),
  "QV_TEST_SYNTHETIC_ROOT_CHILD=1",
  "QV_TEST_SYNTHETIC_ROOT_DIR="+dir,
  "QV_TEST_SYNTHETIC_ROOT_APP="+app,
  "QV_TEST_SYNTHETIC_ROOT_BINDING_B64="+base64.RawURLEncoding.EncodeToString([]byte(binding)),
  "QV_TEST_SYNTHETIC_ROOT_PIN="+rootPin)
 output,e:=cmd.CombinedOutput()
 if e!=nil{t.Fatalf("separate-process reopen failed: %v: %s",e,output)}

 f:=filepath.Join(dir,"account-root.pq.vault")
 original,e:=winReadPrivate(f,16384);if e!=nil{t.Fatal(e)}
 if bytes.Contains(original,[]byte(syntheticRootPassword)){t.Fatal("plaintext passphrase in sidecar")}
 // Simulate a fully valid alternate ML-DSA private key sealed under exactly
 // the same lab password and AAD: only the independent root pin stops it.
 alternate,e:=pqGenerate("ML-DSA-65");if e!=nil{t.Fatal(e)}
 substituted,e:=winSealAccountRoot(alternate,binding,[]byte(syntheticRootPassword))
 alternate.close()
 if e!=nil{t.Fatal(e)}
 if e=os.WriteFile(f,substituted,0600);e!=nil{t.Fatal(e)}
 clear(substituted)
 if _,e=winVerifyAccountRoot(dir,app,binding,rootPin,[]byte(syntheticRootPassword));e==nil{
  t.Fatal("valid but unpinned replacement account root accepted")
 }
 if e=os.WriteFile(f,original,0600);e!=nil{t.Fatal(e)}
 if _,e=winVerifyAccountRoot(dir,app,binding,rootPin,[]byte(syntheticRootPassword));e!=nil{t.Fatal("original not recoverable",e)}
 original[len(original)-1]^=1
 if e=os.WriteFile(f,original,0600);e!=nil{t.Fatal(e)}
 if _,e=winVerifyAccountRoot(dir,app,binding,rootPin,[]byte(syntheticRootPassword));e==nil{
  t.Fatal("ciphertext modification accepted")
 }
 clear(original)
}
func TestWindowsAccountRootSeparateProcess(t *testing.T){
 if os.Getenv("QV_TEST_SYNTHETIC_ROOT_CHILD")!="1"{return}
 dir,app:=os.Getenv("QV_TEST_SYNTHETIC_ROOT_DIR"),os.Getenv("QV_TEST_SYNTHETIC_ROOT_APP")
 encoded,pin:=os.Getenv("QV_TEST_SYNTHETIC_ROOT_BINDING_B64"),os.Getenv("QV_TEST_SYNTHETIC_ROOT_PIN")
 raw,e:=base64.RawURLEncoding.DecodeString(encoded);if e!=nil{t.Fatal(e)}
 binding:=string(raw);defer clear(raw)
 if _,e:=winVerifyAccountRoot(dir,app,binding,pin,[]byte(syntheticRootPassword));e!=nil{t.Fatal(e)}
}
func TestWindowsAccountRootRequiresExistingLabAndBinding(t *testing.T){
 pub,_,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
 app:=b64.EncodeToString(pub)
 if _,e=winPQRootBinding(app,"bad","x","x","x","x","x","x");e==nil{t.Fatal("binding was not validated")}
 if _,e=winCreateAccountRoot(filepath.Join(t.TempDir(),"missing"),app,strings.Repeat("a",200),[]byte(syntheticRootPassword));e==nil{t.Fatal("no existing vault accepted")}
 if _,e=winCreateAccountRoot(t.TempDir(),app,strings.Repeat("b",200),[]byte(syntheticRootPassword));e==nil{t.Fatal("unenrolled directory accepted")}
}
