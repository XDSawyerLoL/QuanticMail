//go:build windows && cgo && pqopenssl

package main

import (
 "bytes"
 "crypto/ecdsa"
 "crypto/ed25519"
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
 certPEM:=pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der})
 ca,e:=x509.ParseCertificate(der);if e!=nil{t.Fatal(e)}
 requests,e:=prepareWindowsTransportRequests(dir,approvals,roster,proof,digest,pw,pqw,now);if e!=nil{t.Fatal(e)}
 pub,e:=decode(r.ControllerPublic,32,32);if e!=nil{t.Fatal(e)}
 tr,e:=nativeTransportTranscript(requests);if e!=nil{t.Fatal(e)}
 sig,e:=decode(requests.Signature,64,64);if e!=nil||!ed25519.Verify(ed25519.PublicKey(pub),tr,sig){t.Fatal("unsigned request")}
 issue:=func(code,role string,serial int64)activationTLS{
  t.Helper()
  raw,e:=decode(code,1,4096);if e!=nil{t.Fatal(e)}
  csr,e:=x509.ParseCertificateRequest(raw);if e!=nil||csr.CheckSignature()!=nil||csr.Subject.CommonName!=transportSubject(digest,role){t.Fatal("wrong CSR",e)}
  leaf:=&x509.Certificate{SerialNumber:big.NewInt(serial),Subject:csr.Subject,NotBefore:now.Add(-time.Minute),NotAfter:now.Add(time.Hour),KeyUsage:x509.KeyUsageDigitalSignature,ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},BasicConstraintsValid:true}
  b,e:=x509.CreateCertificate(rand.Reader,leaf,ca,csr.PublicKey,k);if e!=nil{t.Fatal(e)}
  return activationTLS{certPEM,pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:b})}
 }
 anchorTLS:=issue(requests.AnchorCSR,"anchor",2);checkpointTLS:=issue(requests.CheckpointCSR,"checkpoint",3)
 repeat,e:=prepareWindowsTransportRequests(dir,approvals,roster,proof,digest,pw,pqw,time.Now());if e!=nil{t.Fatal(e)}
 for _,p:=range [][2]string{{requests.AnchorCSR,repeat.AnchorCSR},{requests.CheckpointCSR,repeat.CheckpointCSR}}{
  a,_:=b64.DecodeString(p[0]);b,_:=b64.DecodeString(p[1]);x,e:=x509.ParseCertificateRequest(a);if e!=nil{t.Fatal(e)};y,e:=x509.ParseCertificateRequest(b);if e!=nil||!bytes.Equal(x.RawSubjectPublicKeyInfo,y.RawSubjectPublicKeyInfo){t.Fatal("private key rotated")}
 }
 cps:=[]activationCheckpoint{}
 for i,a:=range approvals.Trusted{cps=append(cps,activationCheckpoint{fmt.Sprintf("https://127.0.0.1:%d/native-checkpoint",40201+i),a.Pin,a.PublicKey,hexHash([]byte(fmt.Sprintf("checkpoint-%d",i)))})}
 peer,e:=freshPortable();if e!=nil{t.Fatal(e)}
 sk,e:=x509.MarshalPKIXPublicKey(&peer.signing.PublicKey);if e!=nil{t.Fatal(e)}
 ek,e:=x509.MarshalPKIXPublicKey(peer.agreement.PublicKey());if e!=nil{t.Fatal(e)}
 kem,e:=pqGenerate("ML-KEM-768");if e!=nil{t.Fatal(e)};defer kem.close()
 dsa,e:=pqGenerate("ML-DSA-65");if e!=nil{t.Fatal(e)};defer dsa.close()
 kd,e:=kem.der(false);if e!=nil{t.Fatal(e)};dd,e:=dsa.der(false);if e!=nil{t.Fatal(e)}
 pt:=peer.agreement.PublicKey().Bytes()
 peerID:="d-"+hexHash([]byte("P-256:"+b64.EncodeToString(pt[1:33])+":"+b64.EncodeToString(pt[33:])))[:32]
 contacts:=[]senderContact{{Address:"testpeer~"+strings.Repeat("a",32)+"@quantic",Device:peerID,ClassicalRoot:sk,PQRoot:dd,Encryption:ek,KEM:kd,Expires:now.Add(time.Hour).UnixMilli()}}
 b:=windowsActivationBundle{"quantic-native-windows-activation-lab/v2",true,digest,roster,approvals,proof,"http://127.0.0.1:45001/",anchors,cps,anchorTLS,checkpointTLS,contacts}
 raw,e:=json.Marshal(b);if e!=nil{t.Fatal(e)}
 if _,e=parseWindowsActivation(raw,strings.Repeat("e",64));e==nil{t.Fatal("wrong package pin accepted")}
 if _,e=parseWindowsActivation(raw,hexHash(raw));e!=nil{t.Fatal(e)}
 // Legacy/private-key injection cannot be parsed.
 var injected map[string]any;if e=json.Unmarshal(raw,&injected);e!=nil{t.Fatal(e)}
 injected["anchorTls"].(map[string]any)["key"]="AAAA"
 injectedBytes,_:=json.Marshal(injected)
 if _,e=parseWindowsActivation(injectedBytes,hexHash(injectedBytes));e==nil{t.Fatal("imported private key accepted")}
 binary:=filepath.Join(filepath.Dir(dir),"Vault-PQ-lab.exe");pin:=strings.Repeat("f",64)
 bad:=b;bad.Endpoint="https://example.invalid/"
 if e=importWindowsActivation(dir,binary,pin,bad,pw,pqw,now);e==nil{t.Fatal("remote transport accepted")}
 bad=b;bad.AnchorTLS=checkpointTLS
 if e=importWindowsActivation(dir,binary,pin,bad,pw,pqw,now);e==nil{t.Fatal("substituted transport certificate accepted")}
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
