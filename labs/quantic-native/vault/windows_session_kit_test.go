//go:build windows && cgo && pqopenssl

package main
import(
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/x509"
 "crypto/x509/pkix"
 "encoding/base64"
 "encoding/json"
 "encoding/pem"
 "math/big"
 "path/filepath"
 "strings"
 "testing"
 "time"
)
func TestWindowsSessionKitImport(t *testing.T){
 k,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if e!=nil{t.Fatal(e)}
 now:=time.Now()
 c:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"Synthetic session kit"},NotBefore:now.Add(-time.Hour),NotAfter:now.Add(time.Hour),BasicConstraintsValid:true,IsCA:true,KeyUsage:x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature}
 cert,e:=x509.CreateCertificate(rand.Reader,c,c,&k.PublicKey,k);if e!=nil{t.Fatal(e)}
 der,e:=x509.MarshalPKCS8PrivateKey(k);if e!=nil{t.Fatal(e)};defer clear(der)
 certPEM:=pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:cert})
 keyPEM:=pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:der});defer clear(keyPEM)
 identity:=map[string]string{"address":"alice~"+strings.Repeat("a",32)+"@quantic","deviceId":"d-"+strings.Repeat("b",32),"signingPin":strings.Repeat("a",64),"encryptionPin":strings.Repeat("b",64),"kemPin":strings.Repeat("c",64),"dsaPin":strings.Repeat("d",64),"quorumPin":strings.Repeat("e",64),"controllerPublic":strings.Repeat("a",43)}
 cfg:=sessionKitConfig{Format:"quantic-native-session-config-lab/v1",LabOnly:true,ClientPin:hexHash(cert),Expected:identity,TLSFiles:map[string]string{"ca":"peer-id-ca.pem","cert":"peer-id-cert.pem","key":"peer-id-key.pem"},EnrollmentReceipts:[]json.RawMessage{json.RawMessage("{}"),json.RawMessage("{}"),json.RawMessage("{}")}}
 rawCfg,_:=json.Marshal(cfg)
 kit:=windowsMailKit{Format:"quantic-windows-session-kit-lab/v1",Address:identity["address"],DeviceID:identity["deviceId"],Files:map[string]string{}}
 for n,b:=range map[string][]byte{"session.json":rawCfg,"peer-id-ca.pem":certPEM,"peer-id-cert.pem":certPEM,"peer-id-key.pem":keyPEM}{kit.Files[n]=base64.RawURLEncoding.EncodeToString(b)}
 raw,_:=json.Marshal(kit)
 files,e:=decodeSessionKit(raw,identity);if e!=nil{t.Fatal(e)};defer clearMailKit(files)
 cfg.EnrollmentReceipts=[]json.RawMessage{}
 initial,_:=json.Marshal(cfg)
 kit.Files["session.json"]=base64.RawURLEncoding.EncodeToString(initial)
 initialRaw,_:=json.Marshal(kit)
 initialFiles,e:=decodeSessionKit(initialRaw,identity);if e!=nil{t.Fatal("initial enrollment kit rejected",e)};clearMailKit(initialFiles)
 cfg.EnrollmentReceipts=nil
 invalid,_:=json.Marshal(cfg)
 kit.Files["session.json"]=base64.RawURLEncoding.EncodeToString(invalid)
 invalidRaw,_:=json.Marshal(kit)
 if _,e=decodeSessionKit(invalidRaw,identity);e==nil{t.Fatal("missing enrollment receipt list accepted")}
 kit.Files["session.json"]=base64.RawURLEncoding.EncodeToString(rawCfg)
 // Scope and private key mismatch rejected before writes.
 other:=map[string]string{};for n,v:=range identity{other[n]=v};other["kemPin"]=strings.Repeat("0",64)
 if _,e=decodeSessionKit(raw,other);e==nil{t.Fatal("wrong key pin accepted")}
 kit.Files["peer-id-key.pem"]=kit.Files["peer-id-ca.pem"];bad,_:=json.Marshal(kit)
 if _,e=decodeSessionKit(bad,identity);e==nil{t.Fatal("wrong TLS private key accepted")}
 dir:=filepath.Join(t.TempDir(),"session-kit-vault");if e=winCreatePrivateDirectory(dir);e!=nil{t.Fatal(e)}
 if e=winWritePrivate(filepath.Join(dir,"lab-provisioned"),[]byte(strings.Repeat("a",64)));e!=nil{t.Fatal(e)}
 if e=writeSessionKit(dir,files);e!=nil{t.Fatal(e)}
 if e=writeSessionKit(dir,files);e!=nil{t.Fatal("identical resume failed",e)}
 marker,e:=winReadPrivate(filepath.Join(dir,sessionApprovalName),4096);if e!=nil{t.Fatal(e)}
 var hashes map[string]string;if json.Unmarshal(marker,&hashes)!=nil||len(hashes)!=4||hashes["session.json"]!=hexHash(rawCfg){t.Fatal("incorrect approval marker")}
 files["session.json"]=[]byte("{}")
 if e=writeSessionKit(dir,files);e==nil{t.Fatal("overwrite accepted")}
 if got,e:=winReadPrivate(filepath.Join(dir,"session.json"),65536);e!=nil||hexHash(got)!=hexHash(rawCfg){t.Fatal("approved config changed")}
}
