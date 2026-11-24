//go:build windows && cgo && pqopenssl

package main

import(
 "bytes"
 "encoding/json"
 "io"
 "os"
 "path/filepath"
 "strings"
)

// Configuration files are provisioned out of band into the same protected
// directory; relative paths, alternate streams, reparse points and broad
// ACLs are refused. No direct unvalidated filesystem read for TLS keys.
func winLoadQuorum(dir string)(*quorumAnchor,error){
 raw,e:=winReadPrivate(filepath.Join(dir,"quorum.json"),65536)
 if e!=nil{return nil,e}
 return parseQuorumAnchor(bytes.NewReader(raw),func(c anchorConfig)(*remoteAnchor,error){
  return remoteFromConfigReader(c,func(path string)([]byte,error){
   if filepath.Dir(path)!=dir{return nil,windowsStorageRefusal}
   return winReadPrivate(path,65536)
  })
 })
}

func winAttachPQ(j *replayLog,q *quorumAnchor,p *pqKeys,rootPin,id string)error{
 if q==nil||p==nil||!hashRE.MatchString(rootPin)||!hashRE.MatchString(id){return portableRefusal}
 a:=&freshQuorum{q:q,scheduled:true,compact:true,dualRootPin:rootPin,pqAddress:p.address,pqDevice:p.device,pqKemPin:p.kemPin,pqDsaPin:p.dsaPin}
 a.pqBinding=hexHash([]byte("quantic-pq-key-binding-lab/v1\x00"+p.address+"\x00"+p.device+"\x00"+p.kemPin+p.dsaPin))
 proof,e:=a.fetchDualLocalProof(id,len(j.seen),j.tail)
 if e!=nil{return e}
 a.localProof=proof
 return j.attachAnchor(a,id)
}

// Only the explicitly selected Windows PQ lab broker is enabled. The
// existing Linux/legacy commands have no new fallback or guard removal.
func winBroker(args []string)error{
 // Only the dedicated native GUI command opts into Windows Credential UI.
 // Legacy command remains console-only, without environment/CLI secret fallback.
 enrolled:=len(args)==12&&args[1]=="--broker-windows-pq-enrolled-mail-gui-lab"
 if len(args)!=11&&!enrolled{return portableRefusal}
 gui:=args[1]=="--broker-windows-pq-gui-lab"||enrolled
 if !gui&&args[1]!="--broker-windows-pq-quorum-lab"{return portableRefusal}
 if gui&&!enrolled&&len(args)!=11{return portableRefusal}
 approve:=winApprove
 secret:=winConsoleLine
 if gui{approve=winGUIApprove;secret=winGUIPassphrase}
 dir,app,s,a,addr,device,kem,dsa,root:=args[2],args[3],args[4],args[5],args[6],args[7],args[8],args[9],args[10]
 for _,pin:=range []string{s,a,kem,dsa,root}{if !hashRE.MatchString(pin){return portableRefusal}}
 if !strongAddr.MatchString(addr)||!strongDevice.MatchString(device){return portableRefusal}
 pub,e:=appPublic(app);if e!=nil{return e}
 hs,e:=winLockDirectory(dir,true);if e!=nil{return e};defer winClose(hs)
 var q *quorumAnchor
 var quorumPinValue string
 var enrollment enrollmentRequest
 if enrolled{
  enrollment,e=readPendingEnrollment(dir);if e!=nil{return e};quorumPinValue=enrollment.QuorumPin
 }else{q,e=winLoadQuorum(dir);if e!=nil{return e};quorumPinValue=q.pin}
 if !approve("Open Windows PQ LAB vault "+addr+" / "+device){return portableRefusal}
 pw,e:=secret("Classical laboratory passphrase: ",true);if e!=nil{return e}
 defer clear(pw)
 k,e:=winReadClassical(filepath.Join(dir,"classical.vault"),anchoredMagic+"compact-manifest-quorum:"+quorumPinValue+"\x00",pw,s,a);if !enrolled{clear(pw)};if e!=nil{return e}
 point:=k.agreement.PublicKey().Bytes()
 if device!="d-"+hexHash([]byte("P-256:"+b64.EncodeToString(point[1:33])+":"+b64.EncodeToString(point[33:])))[:32]{return portableRefusal}
 binding,e:=pqBinding(s,a,hexHash(pub),quorumPinValue,addr,device);if e!=nil{return e}
 pqw,e:=secret("Post-quantum laboratory passphrase: ",true);if e!=nil{return e};defer clear(pqw)
 p,e:=winReadPQ(filepath.Join(dir,"pq.vault"),binding,pqw,addr,device,kem,dsa);if !enrolled{clear(pqw)};if e!=nil{return e};defer p.close()
 var transport mailboxTransport
 var checkpointTransport mailboxTransport
 if enrolled{
  request:=enrollment
  claim:=request.Claim
  if request.QuorumPin!=quorumPinValue||request.ControllerPublic!=app||claim.Address!=addr||claim.DeviceID!=device||claim.SigningPin!=s||claim.EncryptionPin!=a||claim.KemPin!=kem||claim.DsaPin!=dsa||claim.PQRootPin!=root{return portableRefusal}
  digest,e:=nativeEnrollmentDigest(request);if e!=nil{return e}
  raw,e:=winReadPrivate(filepath.Join(dir,"mailbox-token.vault"),1024);if e!=nil{return e}
  token,e:=openNativeMailboxCredential(raw,digest,pw,pqw);clear(raw);if e!=nil{return e};defer clear(token)
  storageSecret,e:=transportSecret(pw,pqw);clear(pw);clear(pqw);if e!=nil{return e};defer clear(storageSecret)
  q,e=winLoadSealedQuorum(dir,digest,storageSecret);if e!=nil||q.pin!=quorumPinValue{return portableRefusal}
  contactRaw,e:=winReadPrivate(filepath.Join(dir,"contacts.json"),131072);if e!=nil{return e}
  contacts,e:=parseSenderTrust(contactRaw);if e!=nil{return e}
  var closeCheckpoints func()
  checkpointTransport,closeCheckpoints,e=winCheckpointTransport(dir,digest,addr,device,storageSecret,contacts);clear(storageSecret);if e!=nil{return e};defer closeCheckpoints()
  var closeTransport func()
  transport,closeTransport,e=newMailboxTransport(args[11],addr,device,token);clear(token);if e!=nil{return e};defer closeTransport()
  mail:=transport
  transport=func(op string,body json.RawMessage)(json.RawMessage,error){if op=="checkpoint"{return checkpointTransport(op,body)};return mail(op,body)}
 }
 raw,e:=winReadPrivate(filepath.Join(dir,"contacts.json"),131072);if e!=nil{return e}
 senders,e:=parseSenderTrust(raw);if e!=nil{return e}
 j,e:=winOpenReplay(filepath.Join(dir,"journal.log"),s,a,hexHash(pub));if e!=nil{return e};defer j.close()
 id,e:=anchorID(s,a,hexHash(pub));if e!=nil{return e}
 if e=winAttachPQ(j,q,p,root,id);e!=nil{return e}
 return authenticateFrames(pub,os.Stdin,os.Stdout,func(in io.Reader,out io.Writer)error{
  return serveGuardedPQTransport(softwareSigner{k.signing},k.agreement,"windows-software-pq-quorum-lab",in,out,func(detail string)bool{
   // Existing operation details include only constrained identifiers and hashes.
   if strings.ContainsAny(detail,"\r\n\x00"){return false}
   return approve(detail)
  },j,p,transport,senders)
 })
}
