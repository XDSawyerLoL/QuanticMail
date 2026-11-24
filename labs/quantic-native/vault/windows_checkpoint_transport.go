//go:build windows && cgo && pqopenssl

package main

import(
 "bytes"
 "crypto/tls"
 "crypto/x509"
 "encoding/json"
 "io"
 "net/http"
 "path/filepath"
 "time"
)
type nativeCheckpointQuery struct{
 Address string `json:"address"`
 DeviceID string `json:"deviceId"`
 Nonce string `json:"nonce"`
 Expires int64 `json:"expires"`
}
type nativeCheckpointResult struct{
 Bundle json.RawMessage `json:"bundle"`
 Attestation json.RawMessage `json:"attestation"`
}
func winLoadSealedQuorum(dir,digest string,secret []byte)(*quorumAnchor,error){
 _,key,e:=readLocalTransportKey(dir,"anchor",digest,secret,false);if e!=nil{return nil,e};defer clear(key)
 raw,e:=winReadPrivate(filepath.Join(dir,"quorum.json"),65536);if e!=nil{return nil,e}
 return parseQuorumAnchor(bytes.NewReader(raw),func(c anchorConfig)(*remoteAnchor,error){
  if c.ServerCA!=filepath.Join(dir,"peer-anchor-ca.pem")||c.ClientCert!=filepath.Join(dir,"peer-anchor-cert.pem")||c.ClientKey!=filepath.Join(dir,"peer-anchor-key.vault"){return nil,portableRefusal}
  return remoteFromConfigReader(c,func(path string)([]byte,error){
   if path==c.ClientKey{return append([]byte(nil),key...),nil}
   if path!=c.ServerCA&&path!=c.ClientCert{return nil,portableRefusal}
   return winReadPrivate(path,16384)
  })
 })
}
func winCheckpointTransport(dir,digest,address,device string,secret []byte,contacts *senderTrust)(mailboxTransport,func(),error){
 _,key,e:=readLocalTransportKey(dir,"checkpoint",digest,secret,false);if e!=nil{return nil,nil,e};defer clear(key)
 ca,e:=winReadPrivate(filepath.Join(dir,"peer-checkpoint-ca.pem"),16384);if e!=nil{return nil,nil,e}
 cert,e:=winReadPrivate(filepath.Join(dir,"peer-checkpoint-cert.pem"),16384);if e!=nil{return nil,nil,e}
 if !activationTLSValid(activationTLS{ca,cert},key,digest,"checkpoint",time.Now()){return nil,nil,portableRefusal}
 roots:=x509.NewCertPool();if !roots.AppendCertsFromPEM(ca){return nil,nil,portableRefusal}
 pair,e:=tls.X509KeyPair(cert,key);if e!=nil{return nil,nil,e}
 raw,e:=winReadPrivate(filepath.Join(dir,"checkpoint-authorities.json"),16384);if e!=nil{return nil,nil,e}
 var authorities []activationCheckpoint
 d:=json.NewDecoder(bytes.NewReader(raw));d.DisallowUnknownFields();var extra any
 if d.Decode(&authorities)!=nil||d.Decode(&extra)!=io.EOF||len(authorities)!=4{return nil,nil,portableRefusal}
 seen:=map[string]bool{};tlsSeen:=map[string]bool{};origins:=map[string]bool{}
 type endpoint struct{url string;client *http.Client;tr *http.Transport}
 var clients []endpoint
 closeAll:=func(){for _,a:=range clients{a.tr.CloseIdleConnections()}}
 for _,a:=range authorities{
  origin,ok:=activationEndpoint(a.URL,"/native-checkpoint")
  der,e:=decode(a.PublicKey,44,44)
  if !ok||e!=nil||hexHash(der)!=a.Pin||!hashRE.MatchString(a.TLSPin)||seen[a.Pin]||tlsSeen[a.TLSPin]||origins[origin]{closeAll();return nil,nil,portableRefusal}
  seen[a.Pin]=true;tlsSeen[a.TLSPin]=true;origins[origin]=true
  pin:=a.TLSPin
  tr:=&http.Transport{Proxy:nil,DisableKeepAlives:true,DisableCompression:true,TLSClientConfig:&tls.Config{MinVersion:tls.VersionTLS13,RootCAs:roots,Certificates:[]tls.Certificate{pair},VerifyConnection:func(cs tls.ConnectionState)error{
   if len(cs.PeerCertificates)==0||hexHash(cs.PeerCertificates[0].Raw)!=pin{return portableRefusal};return nil
  }},ResponseHeaderTimeout:4*time.Second}
  clients=append(clients,endpoint{a.URL,&http.Client{Transport:tr,Timeout:4*time.Second,CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}},tr})
 }
 closed:=false
 return func(op string,body json.RawMessage)(json.RawMessage,error){
  if closed||op!="checkpoint"||len(body)>1024{return nil,portableRefusal}
  var q nativeCheckpointQuery;d:=json.NewDecoder(bytes.NewReader(body));d.DisallowUnknownFields()
  var extra any;if d.Decode(&q)!=nil||d.Decode(&extra)!=io.EOF||!strongAddr.MatchString(q.Address)||!strongDevice.MatchString(q.DeviceID)||!hashRE.MatchString(q.Nonce){return nil,portableRefusal}
  now:=time.Now().UnixMilli();if q.Expires<=now||q.Expires>now+15000{return nil,portableRefusal}
  if q.Address!=address||q.DeviceID!=device{
   c,ok:=contacts.contacts[senderKey(q.Address,q.DeviceID)];if !ok||c.Expires<=now{return nil,portableRefusal}
  }
  results:=make(chan nativeCheckpointResult,4)
  for _,a:=range clients{go func(a endpoint){
   var answer nativeCheckpointResult
   defer func(){results<-answer}()
   req,e:=http.NewRequest("POST",a.url,bytes.NewReader(body));if e!=nil{return};req.Header.Set("Content-Type","application/json")
   res,e:=a.client.Do(req);if e!=nil{return};defer res.Body.Close()
   if res.StatusCode!=200||res.ContentLength<1||res.ContentLength>24000||len(res.TransferEncoding)!=0{return}
   raw,e:=io.ReadAll(io.LimitReader(res.Body,24001));if e!=nil||int64(len(raw))!=res.ContentLength{return}
   d:=json.NewDecoder(bytes.NewReader(raw));d.DisallowUnknownFields()
   var r nativeCheckpointResult;var extra any
   if d.Decode(&r)!=nil||d.Decode(&extra)!=io.EOF||len(r.Bundle)<2||len(r.Bundle)>20000||len(r.Attestation)<2||len(r.Attestation)>2048{return}
   answer=r
  }(a)}
  // Select a single public bundle; the Node verifier still checks all signed
  // votes and independently binds the bundle. Malicious mismatch fails closed.
  var bundle json.RawMessage;votes:=[]json.RawMessage{}
  for i:=0;i<4;i++{a:=<-results;if len(a.Attestation)>0{if bundle==nil{bundle=a.Bundle};votes=append(votes,a.Attestation)}}
  if len(votes)<3||q.Expires<=time.Now().UnixMilli(){return nil,portableRefusal}
  out,e:=json.Marshal(struct{Bundle json.RawMessage `json:"bundle"`;Attestations []json.RawMessage `json:"attestations"`}{bundle,votes})
  if e!=nil||len(out)>28000{return nil,portableRefusal};return out,nil
 },func(){closed=true;closeAll()},nil
}
