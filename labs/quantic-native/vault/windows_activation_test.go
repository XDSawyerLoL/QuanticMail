//go:build windows && cgo && pqopenssl

package main

import (
 "bytes"
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/x509"
 "crypto/x509/pkix"
 "encoding/json"
 "encoding/pem"
 "fmt"
 "math/big"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)
func TestWindowsActivationPrivateImport(t *testing.T){
 now:=time.Now()
 pw,pqw,owner:=[]byte("activation synthetic classical password"),[]byte("activation synthetic postquantum password"),[]byte("activation synthetic owner password")
 anchors:=[]activationAnchor{};pins:=[]string{}
 for i:=0;i<4;i++{pin:=hexHash([]byte(fmt.Sprintf("anchor-%d",i)));pins=append(pins,pin);anchors=append(anchors,activationAnchor{fmt.Sprintf("https://127.0.0.1:%d",40101+i),pin})}
 quorum,e:=quorumPin(pins);if e!=nil{t.Fatal(e)}
 _,dir,e:=prepareWindowsEnrollmentVault(t.TempDir(),"testactivation",quorum,pw,pqw,owner);if e!=nil{t.Fatal(e)}
 r,e:=readPendingEnrollment(dir);if e!=nil{t.Fatal(e)}
 approvals,roster:=credentialTestApprovals(t,r,now)
 proof,digest,e:=prepareWindowsMailboxCredential(dir,approvals,roster,pw,pqw,now);if e!=nil{t.Fatal(e)}
 k,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if e!=nil{t.Fatal(e)}
 cert:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"Synthetic activation CA"},NotBefore:now.Add(-time.Hour),NotAfter:now.Add(time.Hour),IsCA:true,BasicConstraintsValid:true,KeyUsage:x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature,ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
 der,e:=x509.CreateCertificate(rand.Reader,cert,cert,&k.PublicKey,k);if e!=nil{t.Fatal(e)}
 key,e:=x509.MarshalPKCS8PrivateKey(k);if e!=nil{t.Fatal(e)}
 certPEM:=pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der})
 tls:=activationTLS{certPEM,certPEM,pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:key})}
 cps:=[]activationCheckpoint{}
 for i,a:=range approvals.Trusted{cps=append(cps,activationCheckpoint{fmt.Sprintf("https://127.0.0.1:%d/native-checkpoint",40201+i),a.Pin,a.PublicKey,hexHash([]byte(fmt.Sprintf("checkpoint-%d",i)))})}
 peer,e:=freshPortable();if e!=nil{t.Fatal(e)}
 sk,e:=x509.MarshalPKIXPublicKey(&peer.signing.PublicKey);if e!=nil{t.Fatal(e)}
 ek,e:=x509.MarshalPKIXPublicKey(peer.agreement.PublicKey());if e!=nil{t.Fatal(e)}
 kem,e:=pqGenerate("ML-KEM-768");if e!=nil{t.Fatal(e)};defer kem.close()
 dsa,e:=pqGenerate("ML-DSA-65");if e!=nil{t.Fatal(e)};defer dsa.close()
 kd,e:=kem.der(false);if e!=nil{t.Fatal(e)};dd,e:=dsa.der(false);if e!=nil{t.Fatal(e)}
 contacts:=[]senderContact{{Address:"testpeer~"+strings.Repeat("a",32)+"@quantic",Device:"d-"+strings.Repeat("b",32),ClassicalRoot:sk,PQRoot:dd,Encryption:ek,KEM:kd,Expires:now.Add(time.Hour).UnixMilli()}}
 b:=windowsActivationBundle{"quantic-native-windows-activation-lab/v1",true,digest,roster,approvals,proof,"http://127.0.0.1:45001/",anchors,cps,tls,tls,contacts}
 raw,e:=json.Marshal(b);if e!=nil{t.Fatal(e)}
 if _,e=parseWindowsActivation(raw,strings.Repeat("e",64));e==nil{t.Fatal("wrong package pin accepted")}
 if _,e=parseWindowsActivation(raw,hexHash(raw));e!=nil{t.Fatal(e)}
 binary:=filepath.Join(filepath.Dir(dir),"Vault-PQ-lab.exe");pin:=strings.Repeat("f",64)
 bad:=b;bad.Endpoint="https://example.invalid/"
 if e=importWindowsActivation(dir,binary,pin,bad,pw,pqw,now);e==nil{t.Fatal("remote transport accepted")}
 bad=b;bad.Credential.TokenHash=strings.Repeat("a",64)
 if e=importWindowsActivation(dir,binary,pin,bad,pw,pqw,now);e==nil{t.Fatal("wrong credential accepted")}
 if _,e=os.Stat(filepath.Join(dir,"desktop.json"));!os.IsNotExist(e){t.Fatal("failed import configured desktop")}
 if e=importWindowsActivation(dir,binary,pin,b,pw,pqw,now);e!=nil{t.Fatal(e)}
 saved,e:=winReadPrivate(filepath.Join(dir,"desktop.json"),131072);if e!=nil{t.Fatal(e)}
 var config map[string]any;if e=json.Unmarshal(saved,&config);e!=nil{t.Fatal(e)}
 scope:=config["windowsScattering"].(map[string]any)
 if scope["credentialMode"]!="vault-sealed-v1"||scope["token"]!=nil{t.Fatal("unsealed credential")}
 if e=importWindowsActivation(dir,binary,pin,b,pw,pqw,now);e!=nil{t.Fatal("exact resume failed",e)}
 bad=b;bad.Endpoint="http://127.0.0.1:45002/"
 if e=importWindowsActivation(dir,binary,pin,bad,pw,pqw,now);e==nil{t.Fatal("configuration overwrite accepted")}
 again,e:=winReadPrivate(filepath.Join(dir,"desktop.json"),131072);if e!=nil||!bytes.Equal(saved,again){t.Fatal("configuration changed",e)}
}
