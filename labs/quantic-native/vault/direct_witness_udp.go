package main

import (
 "bytes"
 stdcontext "context"
 "crypto/aes"
 "crypto/cipher"
 "crypto/ed25519"
 "crypto/hmac"
 "crypto/rand"
 "crypto/sha256"
 "encoding/json"
 "io"
 "net"
 "time"
)

// Private UDP laboratory adapter. Separate random 256-bit secret per
// witness/vault, provisioned out of band. No relay, DNS or HTTP. This
// adapter is not the Scattering cover carrier and offers no IP anonymity.
// Uncertain advances are never automatically retried.
const directUDPMax=1200
const directUDPWindow int64=5000
type directUDPKeys struct{ request,response cipher.AEAD }
func makeDirectUDPKeys(secret []byte,id string,public ed25519.PublicKey)(directUDPKeys,error){
 var out directUDPKeys
 if len(secret)!=32||bytes.Equal(secret,make([]byte,32))||!hashRE.MatchString(id)||len(public)!=ed25519.PublicKeySize{return out,portableRefusal}
 makeKey:=func(direction string)(cipher.AEAD,error){
  h:=hmac.New(sha256.New,secret)
  h.Write([]byte("quantic-direct-witness-udp/v1\x00"+direction+"\x00"+id+"\x00"));h.Write(public)
  key:=h.Sum(nil);defer clear(key)
  block,e:=aes.NewCipher(key);if e!=nil{return nil,e};return cipher.NewGCM(block)
 }
 var e error
 out.request,e=makeKey("request");if e!=nil{return directUDPKeys{},e}
 out.response,e=makeKey("response");if e!=nil{return directUDPKeys{},e}
 return out,nil
}
func directUDPSeal(a cipher.AEAD,plain []byte)([]byte,error){
 if len(plain)==0||len(plain)+a.NonceSize()+a.Overhead()>directUDPMax{return nil,portableRefusal}
 n:=make([]byte,a.NonceSize());if _,e:=rand.Read(n);e!=nil{return nil,e}
 return a.Seal(n,n,plain,[]byte("quantic-direct-witness-udp/v1")),nil
}
func directUDPOpen(a cipher.AEAD,raw []byte)([]byte,error){
 if len(raw)<=a.NonceSize()+a.Overhead()||len(raw)>directUDPMax{return nil,portableRefusal}
 return a.Open(nil,raw[:a.NonceSize()],raw[a.NonceSize():],[]byte("quantic-direct-witness-udp/v1"))
}
type directUDPPayload struct{
 Issued int64
 Request directWitnessRequest
}
func directUDPParse(raw []byte,now int64)(directWitnessRequest,error){
 var p directUDPPayload
 d:=json.NewDecoder(bytes.NewReader(raw));d.DisallowUnknownFields()
 var extra any
 if d.Decode(&p)!=nil||d.Decode(&extra)!=io.EOF||p.Issued<=0||p.Issued>now||now-p.Issued>directUDPWindow{return directWitnessRequest{},portableRefusal}
 canonical,e:=json.Marshal(p);if e!=nil||!bytes.Equal(raw,canonical){return directWitnessRequest{},portableRefusal}
 if _,e=directWitnessTranscript(p.Request);e!=nil{return directWitnessRequest{},e}
 return p.Request,nil
}
func directUDPAddress(a *net.UDPAddr)bool{
 return a!=nil&&a.Port>0&&a.Port<=65535&&a.Zone==""&&a.IP.To4()!=nil&&(a.IP.IsPrivate()||a.IP.IsLoopback())
}
func newDirectUDPExchange(addr *net.UDPAddr,secret []byte,id string,public ed25519.PublicKey)(directWitnessExchange,error){
 if !directUDPAddress(addr){return nil,portableRefusal}
 remote:=&net.UDPAddr{IP:append(net.IP(nil),addr.IP...),Port:addr.Port}
 keys,e:=makeDirectUDPKeys(secret,id,public);if e!=nil{return nil,e}
 return func(ctx stdcontext.Context,q directWitnessRequest)([]byte,error){
  if ctx.Err()!=nil||q.ID!=id{return nil,portableRefusal}
  if _,e:=directWitnessTranscript(q);e!=nil{return nil,e}
  deadline:=time.Now().Add(time.Duration(directUDPWindow)*time.Millisecond)
  if d,ok:=ctx.Deadline();ok&&d.Before(deadline){deadline=d}
  c,e:=net.DialUDP("udp4",nil,remote);if e!=nil{return nil,e};defer c.Close()
  stop:=stdcontext.AfterFunc(ctx,func(){c.Close()});defer stop()
  if e=c.SetDeadline(deadline);e!=nil{return nil,e}
  raw,e:=json.Marshal(directUDPPayload{time.Now().UnixMilli(),q});if e!=nil{return nil,e}
  packet,e:=directUDPSeal(keys.request,raw);if e!=nil{return nil,e}
  n,e:=c.Write(packet);if e!=nil||n!=len(packet){return nil,portableRefusal}
  buf:=make([]byte,directUDPMax+1)
  n,e=c.Read(buf);if e!=nil{return nil,e}
  plain,e:=directUDPOpen(keys.response,buf[:n])
  if e!=nil||len(plain)!=32+ed25519.SignatureSize||!bytes.Equal(plain[:32],q.Nonce[:])||ctx.Err()!=nil{return nil,portableRefusal}
  return append([]byte(nil),plain[32:]...),nil
 },nil
}
// A single provisioned identity per listener; independent witness keys and
// storage are supplied by the owner. Only authenticated requests reach CAS.
// Caller owns socket and must stop it on shutdown.
func serveDirectUDPWitness(ctx stdcontext.Context,c *net.UDPConn,secret []byte,id string,store checkpointAnchor,key ed25519.PrivateKey)error{
 if c==nil||store==nil||len(key)!=ed25519.PrivateKeySize{return portableRefusal}
 local,ok:=c.LocalAddr().(*net.UDPAddr);if !ok||!directUDPAddress(local){return portableRefusal}
 key=append(ed25519.PrivateKey(nil),key...);defer clear(key)
 keys,e:=makeDirectUDPKeys(secret,id,key.Public().(ed25519.PublicKey));if e!=nil{return e}
 buf:=make([]byte,directUDPMax+1)
 for ctx.Err()==nil{
  if e=c.SetReadDeadline(time.Now().Add(200*time.Millisecond));e!=nil{return e}
  n,from,e:=c.ReadFromUDP(buf)
  if e!=nil{if ne,ok:=e.(net.Error);ok&&ne.Timeout(){continue};return e}
  if !directUDPAddress(from){continue}
  raw,e:=directUDPOpen(keys.request,buf[:n]);if e!=nil{continue}
  q,e:=directUDPParse(raw,time.Now().UnixMilli());if e!=nil||q.ID!=id{continue}
  if ctx.Err()!=nil{break}
  sig,e:=signDirectWitness(q,id,store,key);if e!=nil{continue}
  response:=append(append([]byte(nil),q.Nonce[:]...),sig...)
  packet,e:=directUDPSeal(keys.response,response);if e!=nil{continue}
  if e=c.SetWriteDeadline(time.Now().Add(time.Second));e!=nil{return e}
  // A lost response never rolls back a successfully committed checkpoint.
  _,_=c.WriteToUDP(packet,from)
 }
 return ctx.Err()
}
