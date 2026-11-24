//go:build (linux || windows) && cgo && pqopenssl

package main
import (
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/sha256"
 "crypto/x509"
 "encoding/json"
 "strings"
 "testing"
)
func TestScatteringNativeSigningInput(t *testing.T){
 a,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if e!=nil{t.Fatal(e)}
 b,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if e!=nil{t.Fatal(e)}
 ak,e:=pqGenerate("ML-DSA-65");if e!=nil{t.Fatal(e)};defer ak.close()
 bk,e:=pqGenerate("ML-DSA-65");if e!=nil{t.Fatal(e)};defer bk.close()
 kem,e:=pqGenerate("ML-KEM-768");if e!=nil{t.Fatal(e)};defer kem.close()
 ap,_:=x509.MarshalPKIXPublicKey(&a.PublicKey);bp,_:=x509.MarshalPKIXPublicKey(&b.PublicKey);ad,_:=ak.der(false);bd,_:=bk.der(false);kp,_:=kem.der(false)
 peer:=senderContact{Address:"bob",Device:"device",ClassicalRoot:bp,PQRoot:bd}
 reverse:=senderContact{Address:"alice",Device:"device",ClassicalRoot:ap,PQRoot:ad}
 prefix:=[]any{scatteringSignDomain,strings.Repeat("a",96),0,scatteringZero,[][]string{{scatteringPin(ap),scatteringPin(ad)},{scatteringPin(bp),scatteringPin(bd)}}}
 h:=scatteringHelloBody{b64.EncodeToString(make([]byte,32)),b64.EncodeToString(ap),b64.EncodeToString(kp)}
 raw,_:=json.Marshal([]any{prefix,"hello",h})
 id,e:=scatteringSigningInput(raw,ap,ad,peer,nil);if e!=nil{t.Fatal("valid hello refused",e)}
 h.Nonce=b64.EncodeToString(make([]byte,32));raw2,_:=json.Marshal([]any{prefix,"hello",h})
 id2,e:=scatteringSigningInput(raw2,ap,ad,peer,nil);if e!=nil||id2!=id{t.Fatal("unstable replay scope")}
 if _,e=scatteringSigningInput(append(raw,' '),ap,ad,peer,nil);e==nil{t.Fatal("noncanonical accepted")}
 if _,e=scatteringSigningInput(raw,bp,bd,reverse,nil);e==nil{t.Fatal("wrong role accepted")}
 classical,e:=softwareSigner{a}.SignDigest(sha256.Sum256(raw));if e!=nil{t.Fatal(e)}
 pq,e:=ak.sign(raw);if e!=nil{t.Fatal(e)}
 evidence:=&scatteringEvidence{Hello:scatteringHello{h,scatteringSignature{b64.EncodeToString(classical),b64.EncodeToString(pq)}},Response:scatteringResponseBody{b64.EncodeToString(make([]byte,32)),b64.EncodeToString(bp),b64.EncodeToString(make([]byte,1088))}}
 both,_:=json.Marshal([]any{prefix,evidence.Hello,evidence.Response});response,_:=json.Marshal([]any{prefix,"response",scatteringPin(both)})
 if _,e=scatteringSigningInput(response,bp,bd,reverse,evidence);e!=nil{t.Fatal("valid response refused",e)}
 if _,e=scatteringSigningInput(response,bp,bd,reverse,nil);e==nil{t.Fatal("blind response accepted")}
 evidence.Response.Nonce=b64.EncodeToString(append([]byte{1},make([]byte,31)...))
 if _,e=scatteringSigningInput(response,bp,bd,reverse,evidence);e==nil{t.Fatal("substitution accepted")}
}
