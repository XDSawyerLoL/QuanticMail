//go:build windows && cgo && pqopenssl

package main

import(
 "bytes"
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
 // dir app sign enc address device kem dsa independently pinned PQ root
 if len(args)!=11{return portableRefusal}
 gui:=args[1]=="--broker-windows-pq-quorum-gui-lab"
 promptSecret:=winConsoleLine
 approve:=winApprove
 if gui{promptSecret=winGUISecret;approve=winGUIApprove}
 dir,app,s,a,addr,device,kem,dsa,root:=args[2],args[3],args[4],args[5],args[6],args[7],args[8],args[9],args[10]
 for _,pin:=range []string{s,a,kem,dsa,root}{if !hashRE.MatchString(pin){return portableRefusal}}
 if !strongAddr.MatchString(addr)||!strongDevice.MatchString(device){return portableRefusal}
 pub,e:=appPublic(app);if e!=nil{return e}
 hs,e:=winLockDirectory(dir,true);if e!=nil{return e};defer winClose(hs)
 q,e:=winLoadQuorum(dir);if e!=nil{return e}
 if !approve("Open Windows PQ LAB vault "+addr+" / "+device){return portableRefusal}
 pw,e:=promptSecret("Classical laboratory passphrase: ",true);if e!=nil{return e}
 defer clear(pw)
 k,e:=winReadClassical(filepath.Join(dir,"classical.vault"),anchoredMagic+"compact-manifest-quorum:"+q.pin+"\x00",pw,s,a);clear(pw);if e!=nil{return e}
 point:=k.agreement.PublicKey().Bytes()
 if device!="d-"+hexHash([]byte("P-256:"+b64.EncodeToString(point[1:33])+":"+b64.EncodeToString(point[33:])))[:32]{return portableRefusal}
 binding,e:=pqBinding(s,a,hexHash(pub),q.pin,addr,device);if e!=nil{return e}
 pqw,e:=promptSecret("Post-quantum laboratory passphrase: ",true);if e!=nil{return e};defer clear(pqw)
 p,e:=winReadPQ(filepath.Join(dir,"pq.vault"),binding,pqw,addr,device,kem,dsa);clear(pqw);if e!=nil{return e};defer p.close()
 raw,e:=winReadPrivate(filepath.Join(dir,"contacts.json"),131072);if e!=nil{return e}
 senders,e:=parseSenderTrust(raw);if e!=nil{return e}
 j,e:=winOpenReplay(filepath.Join(dir,"journal.log"),s,a,hexHash(pub));if e!=nil{return e};defer j.close()
 id,e:=anchorID(s,a,hexHash(pub));if e!=nil{return e}
 if e=winAttachPQ(j,q,p,root,id);e!=nil{return e}
 return authenticateFrames(pub,os.Stdin,os.Stdout,func(in io.Reader,out io.Writer)error{
  return serveGuardedPQ(softwareSigner{k.signing},k.agreement,"windows-software-pq-quorum-lab",in,out,func(detail string)bool{
   // Existing operation details include only constrained identifiers and hashes.
   if strings.ContainsAny(detail,"\r\n\x00"){return false}
   return approve(detail)
  },j,p,senders)
 })
}
