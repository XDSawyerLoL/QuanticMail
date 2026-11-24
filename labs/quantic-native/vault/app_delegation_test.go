package main

import (
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/json"
 "io"
 "testing"
)
func TestDelegatedNativeControllerSession(t *testing.T){
 rootPub,root,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
 ep,session,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
 other,_,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
 in,w:=io.Pipe();out,ow:=io.Pipe()
 defer in.Close();defer w.Close();defer out.Close();defer ow.Close()
 result:=make(chan error,1)
 received:=make(chan []byte,1)
 go func(){result<-authenticateFramesDelegated(ep,root,in,ow,func(r io.Reader,_ io.Writer)error{
  b,e:=io.ReadAll(r);received<-b;return e
 })}()
 var hello map[string]string
 if e=json.NewDecoder(out).Decode(&hello);e!=nil{t.Fatal(e)}
 nonce,e:=decode(hello["session"],32,32);if e!=nil{t.Fatal(e)}
 sig,e:=decode(hello["delegation"],64,64);if e!=nil{t.Fatal(e)}
 if !ed25519.Verify(rootPub,delegatedSessionDigest(nonce,ep),sig){t.Fatal("delegation verification failed")}
 if ed25519.Verify(rootPub,delegatedSessionDigest(nonce,other),sig){t.Fatal("different session key accepted")}
 altered:=append([]byte(nil),nonce...);altered[0]^=1
 if ed25519.Verify(rootPub,delegatedSessionDigest(altered,ep),sig){t.Fatal("different nonce accepted")}
 body:=[]byte(`{"op":"close"}`)
 digest:=appDigest(nonce,1,body)
 frame:=signedFrame{Seq:1,Body:b64.EncodeToString(body),Sig:b64.EncodeToString(ed25519.Sign(session,digest[:]))}
 if e=json.NewEncoder(w).Encode(frame);e!=nil{t.Fatal(e)}
 if e=<-result;e!=nil{t.Fatal(e)}
 if got:=<-received;!bytes.Equal(got,append(body,'\n')){t.Fatal("wrong authenticated message")}
}
