package vaultsession

import (
 "bufio"
 "bytes"
 "crypto"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/base64"
 "encoding/binary"
 "encoding/json"
 "errors"
 "io"
 "time"
)

const maxBrokerLine=8192

type brokerHello struct{Session string `json:"session"`}
type brokerFrame struct{
 Seq uint32 `json:"seq"`
 Body string `json:"body"`
 Sig string `json:"sig"`
}
func strictDecode(raw []byte, v any)error{
 dec:=json.NewDecoder(bytes.NewReader(raw))
 dec.DisallowUnknownFields()
 if err:=dec.Decode(v);err!=nil{return err}
 var extra any
 if dec.Decode(&extra)!=io.EOF{return errors.New("unexpected trailing JSON")}
 return nil
}
func brokerLine(in *bufio.Reader)([]byte,error){
 raw,err:=in.ReadSlice('\n')
 if err!=nil||len(raw)>maxBrokerLine{return nil,errors.New("incomplete or oversized Vault frame")}
 return raw,nil
}
func controllerDigest(nonce []byte,seq uint32,body []byte)[32]byte{
 h:=sha256.New()
 h.Write([]byte("quantic-vault-controller-lab/v1\x00"))
 h.Write(nonce)
 var n [4]byte
 binary.BigEndian.PutUint32(n[:],seq)
 h.Write(n[:]);h.Write(body)
 var digest [32]byte
 copy(digest[:],h.Sum(nil))
 return digest
}

// ExchangeBrokerProof uses one newly opened, authenticated native Vault
// broker channel. The caller must own and close both pipes, enforce I/O
// deadlines (including user approval), and authenticate the broker binary.
// The signer must be the existing independently enrolled controller, NOT
// a new Sentinel identity. No private key bytes are exported or persisted.
// This function exposes only the fixed pq-proof-lab request. A successful
// return proves key possession, not permission to perform an OS action.
func ExchangeBrokerProof(in io.Reader,out io.Writer,s *Session,signer crypto.Signer,pinnedController ed25519.PublicKey)error{
 if in==nil||out==nil||s==nil||signer==nil||len(pinnedController)!=ed25519.PublicKeySize{return errors.New("missing trusted broker channel or controller")}
 pub,ok:=signer.Public().(ed25519.PublicKey)
 if !ok||!bytes.Equal(pub,pinnedController){return errors.New("controller key differs from enrollment")}
 reader:=bufio.NewReaderSize(in,maxBrokerLine)
 hello,err:=brokerLine(reader);if err!=nil{return err}
 var h brokerHello
 if strictDecode(hello,&h)!=nil{return errors.New("invalid broker session")}
 nonce,err:=base64.RawURLEncoding.DecodeString(h.Session)
 if err!=nil||len(nonce)!=32||base64.RawURLEncoding.EncodeToString(nonce)!=h.Session{return errors.New("invalid broker nonce")}
 body,err:=json.Marshal(s.Request());if err!=nil{return err}
 digest:=controllerDigest(nonce,1,body)
 sig,err:=signer.Sign(rand.Reader,digest[:],crypto.Hash(0))
 if err!=nil||!ed25519.Verify(pinnedController,digest[:],sig){return errors.New("controller signature refused")}
 frame,err:=json.Marshal(brokerFrame{Seq:1,Body:base64.RawURLEncoding.EncodeToString(body),Sig:base64.RawURLEncoding.EncodeToString(sig)})
 if err!=nil{return err}
 frame=append(frame,'\n')
 n,err:=out.Write(frame)
 if err!=nil{return err};if n!=len(frame){return io.ErrShortWrite}
 reply,err:=brokerLine(reader);if err!=nil{return err}
 return s.Verify(reply,time.Now())
}
