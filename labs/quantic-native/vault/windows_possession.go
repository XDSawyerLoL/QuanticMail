//go:build windows && cgo && pqopenssl

package main

import (
 "bytes"
 "crypto/ecdsa"
 "crypto/hmac"
 "crypto/rand"
 "crypto/sha256"
 "encoding/json"
 "io"
 "os"
 "path/filepath"
 "time"
)

const possessionDomain="quantic-native-enrollment-possession-lab/v1"
type possessionChallenge struct{
 fields [11]string
 expires int64
 ephemeral,kem string
}
func parsePossessionChallenge(raw []byte,r map[string]string,now int64)(possessionChallenge,error){
 var c possessionChallenge
 var a []json.RawMessage
 if len(raw)<1||len(raw)>4096||json.Unmarshal(raw,&a)!=nil||len(a)!=14{return c,portableRefusal}
 for i:=0;i<11;i++{if json.Unmarshal(a[i],&c.fields[i])!=nil{return c,portableRefusal}}
 if json.Unmarshal(a[11],&c.expires)!=nil||json.Unmarshal(a[12],&c.ephemeral)!=nil||json.Unmarshal(a[13],&c.kem)!=nil{return c,portableRefusal}
 f:=c.fields
 if f[0]!=possessionDomain||c.expires<=now||c.expires-now>180000||!hashRE.MatchString(f[9])||!hashRE.MatchString(f[10]){return c,portableRefusal}
 for i,n:=range []string{"address","deviceId","signingPin","encryptionPin","kemPin","dsaPin","quorumPin","controllerPublic"}{if f[i+1]!=r[n]{return c,portableRefusal}}
 if _,e:=public(c.ephemeral);e!=nil{return c,e}
 if _,e:=decode(c.kem,1088,1088);e!=nil{return c,e}
 v:=make([]any,0,14);for _,s:=range f{v=append(v,s)};v=append(v,c.expires,c.ephemeral,c.kem)
 canonical,e:=json.Marshal(v);if e!=nil||!bytes.Equal(canonical,raw){return c,portableRefusal}
 return c,nil
}
func possessionMAC(key,data []byte)[]byte{m:=hmac.New(sha256.New,key);m.Write(data);return m.Sum(nil)}
func possessionTranscript(raw,ec,pq []byte)[]byte{
 combined:=append(append([]byte(nil),ec...),pq...);defer clear(combined)
 key:=possessionMAC([]byte(possessionDomain),combined);defer clear(key)
 proof:=possessionMAC(key,raw);defer clear(proof)
 t:=append([]byte(possessionDomain+"\x00"),raw...);t=append(t,0);return append(t,proof...)
}
func nativePossessionProof(raw []byte,c possessionChallenge,k portableKeys,p *pqKeys,reserve func()error)(map[string]string,error){
 ep,e:=public(c.ephemeral);if e!=nil{return nil,e}
 ct,e:=decode(c.kem,1088,1088);if e!=nil{return nil,e}
 ec,e:=k.agreement.ECDH(ep);if e!=nil{return nil,e};defer clear(ec)
 pq,e:=p.kem.dec(ct);if e!=nil{return nil,e};defer clear(pq)
 if len(ec)!=32||len(pq)!=32{return nil,portableRefusal}
 transcript:=possessionTranscript(raw,ec,pq);defer clear(transcript)
 if e=reserve();e!=nil{return nil,e}
 digest:=sha256.Sum256(transcript)
 r,s,e:=ecdsa.Sign(rand.Reader,k.signing,digest[:]);if e!=nil{return nil,e}
 cs:=make([]byte,64);r.FillBytes(cs[:32]);s.FillBytes(cs[32:])
 ps,e:=p.dsa.sign(transcript);if e!=nil||len(ps)!=3309{return nil,portableRefusal}
 return map[string]string{"status":"native-possession-lab-proof","challengeSha256":hexHash(raw),"classicalSignature":b64.EncodeToString(cs),"pqSignature":b64.EncodeToString(ps)},nil
}
// Isolated pre-enrollment operation, not a general signing endpoint or
// substitute for the existing quorum-guarded mail broker.
func winPossessionProofGUI(args []string)error{
 if len(args)!=4||!hashRE.MatchString(args[3]){return portableRefusal}
 dir,pin:=args[2],args[3]
 raw,e:=io.ReadAll(io.LimitReader(os.Stdin,4097));if e!=nil{return e}
 if hexHash(raw)!=pin{return portableRefusal}
 hs,e:=winLockDirectory(dir,true);if e!=nil{return e};defer winClose(hs)
 r,e:=winGUIReadIdentity(dir);if e!=nil{return e}
 c,e:=parsePossessionChallenge(raw,r,time.Now().UnixMilli());if e!=nil{return e}
 marker:=filepath.Join(dir,"enrollment-proof-"+c.fields[10]+".used")
 if _,e=os.Lstat(marker);!os.IsNotExist(e){return portableRefusal}
 if !winGUIApproveText("Prouver la possession des quatre cles du coffre de TEST "+r["address"]+" ? Candidat SHA256 "+c.fields[9]+" . Aucune inscription distante."){return portableRefusal}
 pub,e:=appPublic(r["controllerPublic"]);if e!=nil{return e}
 pw,e:=winGUISecret("Phrase secrete classique du coffre de test.");if e!=nil{return e};defer clear(pw)
 k,e:=winReadClassical(filepath.Join(dir,"classical.vault"),anchoredMagic+"compact-manifest-quorum:"+r["quorumPin"]+"\x00",pw,r["signingPin"],r["encryptionPin"]);clear(pw);if e!=nil{return e}
 binding,e:=pqBinding(r["signingPin"],r["encryptionPin"],hexHash(pub),r["quorumPin"],r["address"],r["deviceId"]);if e!=nil{return e}
 pqw,e:=winGUISecret("Phrase secrete post-quantique du coffre de test.");if e!=nil{return e};defer clear(pqw)
 p,e:=winReadPQ(filepath.Join(dir,"pq.vault"),binding,pqw,r["address"],r["deviceId"],r["kemPin"],r["dsaPin"]);clear(pqw);if e!=nil{return e};defer p.close()
 proof,e:=nativePossessionProof(raw,c,k,p,func()error{
  now:=time.Now().UnixMilli();if now>=c.expires||c.expires-now>180000{return portableRefusal}
  // Exclusive durable local reservation; no assertion of rollback
  // resistance against the already trusted Windows account.
  return winWritePrivate(marker,[]byte(pin))
 });if e!=nil{return e}
 return json.NewEncoder(os.Stdout).Encode(proof)
}
