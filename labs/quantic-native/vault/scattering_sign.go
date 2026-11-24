package main

import (
 "bytes"
 "crypto/ecdsa"
 "crypto/sha256"
 "crypto/sha512"
 "crypto/x509"
 "encoding/asn1"
 "encoding/hex"
 "encoding/json"
 "io"
 "math/big"
 "regexp"
 "time"
)

const scatteringSignDomain = "quantic-mux-hybrid/lab/v1"
var scatteringHex = regexp.MustCompile("^[0-9a-f]{96}$")
var scatteringZero = string(bytes.Repeat([]byte{'0'},96))
type scatteringHelloBody struct { Nonce string `json:"nonce"`; EC string `json:"ec"`; KEM string `json:"kem"` }
type scatteringResponseBody struct { Nonce string `json:"nonce"`; EC string `json:"ec"`; Ciphertext string `json:"ciphertext"` }
type scatteringSignature struct { Classical string `json:"classical"`; PQ string `json:"pq"` }
type scatteringHello struct { Body scatteringHelloBody `json:"body"`; Sig scatteringSignature `json:"sig"` }
type scatteringEvidence struct { Hello scatteringHello `json:"hello"`; Response scatteringResponseBody `json:"responseBody"` }
type scatteringSignRequest struct { Address string `json:"address"`; Device string `json:"deviceId"`; Raw string `json:"raw"`; Evidence *scatteringEvidence `json:"evidence,omitempty"`; Renewal bool `json:"renewal,omitempty"` }
func scatteringDecode(raw []byte,v any)bool{
 d:=json.NewDecoder(bytes.NewReader(raw));d.DisallowUnknownFields()
 var extra any
 return d.Decode(v)==nil&&d.Decode(&extra)==io.EOF
}
func scatteringPin(raw []byte)string{h:=sha512.Sum384(raw);return hex.EncodeToString(h[:])}
func scatteringEC(raw string)bool{b,e:=decode(raw,91,91);if e!=nil{return false};p,e:=senderPublic(b);if e!=nil{return false};canonical,e:=x509.MarshalPKIXPublicKey(p);return e==nil&&bytes.Equal(b,canonical)}
func scatteringKEM(raw string)bool{
 b,e:=decode(raw,1206,1206);if e!=nil{return false}
 var spki struct{Algorithm struct{OID asn1.ObjectIdentifier}; Key asn1.BitString}
 rest,e:=asn1.Unmarshal(b,&spki)
 if e!=nil||len(rest)!=0||!spki.Algorithm.OID.Equal(asn1.ObjectIdentifier{2,16,840,1,101,3,4,4,2})||spki.Key.BitLength!=1184*8{return false}
 canonical,e:=asn1.Marshal(spki);return e==nil&&bytes.Equal(b,canonical)
}
func scatteringHelloValid(b scatteringHelloBody)bool{_,e:=decode(b.Nonce,32,32);return e==nil&&scatteringEC(b.EC)&&scatteringKEM(b.KEM)}
func scatteringResponseValid(b scatteringResponseBody)bool{_,e:=decode(b.Nonce,32,32);_,f:=decode(b.Ciphertext,1088,1088);return e==nil&&f==nil&&scatteringEC(b.EC)}
func scatteringVerify(c senderContact,raw []byte,s scatteringSignature)bool{
 key,e:=senderPublic(c.ClassicalRoot);if e!=nil{return false}
 a,e:=decode(s.Classical,64,64);if e!=nil{return false};b,e:=decode(s.PQ,3309,3309);if e!=nil{return false}
 h:=sha256.Sum256(raw)
 return ecdsa.Verify(key,h[:],new(big.Int).SetBytes(a[:32]),new(big.Int).SetBytes(a[32:]))&&pqVerifyRoot(c.PQRoot,raw,b)
}
// Rebuild the exact JS canonical transcript. The response is not a blind
// digest signature: its peer hello and both public contributions are checked.
func scatteringSigningInput(raw []byte,ownClassical,ownPQ []byte,peer senderContact,evidence *scatteringEvidence)([32]byte,error){
 var zero [32]byte
 var outer,prefix []json.RawMessage
 if len(raw)>4096||!scatteringDecode(raw,&outer)||len(outer)!=3||!scatteringDecode(outer[0],&prefix)||len(prefix)!=5{return zero,portableRefusal}
 var domain,channel,previous,stage string;var generation int;var ids [][]string
 if !scatteringDecode(prefix[0],&domain)||!scatteringDecode(prefix[1],&channel)||!scatteringDecode(prefix[2],&generation)||!scatteringDecode(prefix[3],&previous)||!scatteringDecode(prefix[4],&ids)||!scatteringDecode(outer[1],&stage){return zero,portableRefusal}
 if domain!=scatteringSignDomain||!scatteringHex.MatchString(channel)||!scatteringHex.MatchString(previous)||generation<0||generation>65535||(generation==0)!=(previous==scatteringZero){return zero,portableRefusal}
 own:=[]string{scatteringPin(ownClassical),scatteringPin(ownPQ)}
 other:=[]string{scatteringPin(peer.ClassicalRoot),scatteringPin(peer.PQRoot)}
 seen:=map[string]bool{};for _,pin:=range append(append([]string{},own...),other...){if seen[pin]{return zero,portableRefusal};seen[pin]=true}
 expected:=[][]string{own,other};if stage=="response"{expected=[][]string{other,own}}
 if len(ids)!=2||len(ids[0])!=2||len(ids[1])!=2||ids[0][0]!=expected[0][0]||ids[0][1]!=expected[0][1]||ids[1][0]!=expected[1][0]||ids[1][1]!=expected[1][1]{return zero,portableRefusal}
 canonicalPrefix:=[]any{domain,channel,generation,previous,expected}
 var canonical []byte
 switch stage{
 case "hello":
  var b scatteringHelloBody
  if evidence!=nil||!scatteringDecode(outer[2],&b)||!scatteringHelloValid(b){return zero,portableRefusal}
  canonical,_=json.Marshal([]any{canonicalPrefix,stage,b})
 case "response":
  var transcript string
  if evidence==nil||!scatteringDecode(outer[2],&transcript)||!scatteringHex.MatchString(transcript)||!scatteringHelloValid(evidence.Hello.Body)||!scatteringResponseValid(evidence.Response){return zero,portableRefusal}
  hello,_:=json.Marshal([]any{canonicalPrefix,"hello",evidence.Hello.Body})
  if !scatteringVerify(peer,hello,evidence.Hello.Sig){return zero,portableRefusal}
  both,_:=json.Marshal([]any{canonicalPrefix,evidence.Hello,evidence.Response})
  if scatteringPin(both)!=transcript{return zero,portableRefusal}
  canonical,_=json.Marshal([]any{canonicalPrefix,stage,transcript})
 default:return zero,portableRefusal
 }
 if !bytes.Equal(raw,canonical){return zero,portableRefusal}
 // One signing attempt per peer, channel, generation and role; even a
 // different nonce or previous transcript cannot recycle the authorization.
 scope,_:=json.Marshal([]any{peer.Address,peer.Device,channel,generation,stage})
 return replayID("scattering-sign-lab/v1",scope),nil
}
func authorizeScatteringSignature(s signer,p *pqKeys,trust *senderTrust,j *replayLog,approve func(string)bool,body []byte,grant *scatteringRenewalGrant)(out json.RawMessage,err error){
 var q scatteringSignRequest
 // A failed or ambiguous delegated request terminates the grant. No fallback.
 defer func(){if q.Renewal&&err!=nil&&grant!=nil{grant.closed=true}}()
 if p==nil||trust==nil||j==nil||j.anchor==nil||len(body)>16000||!scatteringDecode(body,&q)||!strongAddr.MatchString(q.Address)||!strongDevice.MatchString(q.Device)||q.Address==p.address&&q.Device==p.device{return nil,portableRefusal}
 peer,ok:=trust.contacts[senderKey(q.Address,q.Device)];if !ok||peer.Expires<=time.Now().UnixMilli(){return nil,portableRefusal}
 raw,e:=decode(q.Raw,1,4096);if e!=nil{return nil,e}
 own,e:=x509.MarshalPKIXPublicKey(s.Public());if e!=nil{return nil,e}
 id,e:=scatteringSigningInput(raw,own,p.dsaPub,peer,q.Evidence);if e!=nil||j.has(id){return nil,portableRefusal}
 if q.Renewal{if grant==nil||!grant.consume(peer,raw,time.Now()){return nil,portableRefusal}}else if !approve("Session Scattering LAB avec "+peer.Address+" / "+peer.Device+" / SHA256 "+hexHash(raw)){return nil,portableRefusal}
 if peer.Expires<=time.Now().UnixMilli()||!j.beginContact(peer){return nil,portableRefusal}
 defer j.endContact()
 result,e:=j.reservePrivateSignature(id,func()([]byte,error){
  if peer.Expires<=time.Now().UnixMilli()||q.Renewal&&!grant.live(time.Now()){return nil,portableRefusal}
  a,e:=s.SignDigest(sha256.Sum256(raw));if e!=nil||len(a)!=64{return nil,portableRefusal}
  b,e:=p.dsa.sign(raw);if e!=nil||len(b)!=3309{return nil,portableRefusal}
  return json.Marshal(scatteringSignature{b64.EncodeToString(a),b64.EncodeToString(b)})
 })
 if e!=nil{return nil,e}
 if peer.Expires<=time.Now().UnixMilli()||q.Renewal&&!grant.live(time.Now()){return nil,portableRefusal}
 if e=j.anchor.check(j.anchorID,len(j.seen),j.tail);e!=nil{return nil,e}
 if q.Renewal&&!grant.live(time.Now()){return nil,portableRefusal}
 return result,nil
}
