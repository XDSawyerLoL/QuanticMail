package main

import (
 "crypto/rand"
 "encoding/hex"
 "encoding/json"
 "time"
)
type scatteringFenceContext struct{
 Channel string `json:"channel"`
 Generation int `json:"generation"`
 Previous string `json:"previous"`
}
type scatteringFenceReservation struct{
 Token string `json:"token"`
 Context scatteringFenceContext `json:"context"`
}
type scatteringFenceState struct{
 previous string
 pending *scatteringFenceReservation
 signed bool
 staged string
}
type scatteringFenceResult struct{
 Token string `json:"token"`
 Generation int `json:"generation"`
 Transcript string `json:"transcript"`
}
func(g *scatteringRenewalGrant) fenceID(stage string,generation int,transcript string)[32]byte{
 // Role and contact key changes cannot reset a spent channel.
 raw,_:=json.Marshal([]any{g.request.Address,g.request.Device,g.request.Channel,generation,transcript})
 return replayID("scattering-fence-"+stage+"/lab/v1",raw)
}
func(g *scatteringRenewalGrant) permitsFencedSignature(raw []byte)bool{
 f:=&g.fence
 if f.pending==nil||f.signed||f.staged!=""{return false}
 var outer,prefix []json.RawMessage
 var channel,previous string;var generation int
 return scatteringDecode(raw,&outer)&&len(outer)==3&&scatteringDecode(outer[0],&prefix)&&len(prefix)==5&&scatteringDecode(prefix[1],&channel)&&scatteringDecode(prefix[2],&generation)&&scatteringDecode(prefix[3],&previous)&&channel==f.pending.Context.Channel&&generation==f.pending.Context.Generation&&previous==f.pending.Context.Previous
}
// The journal is the durable authority. The random token and transcript
// cache are intentionally not recovered after broker exit: an old channel
// cannot resume from a stale controller or local SQLite snapshot.
func(g *scatteringRenewalGrant) fenceStep(j *replayLog,op string,body []byte,now time.Time)(out json.RawMessage,err error){
 defer func(){if err!=nil{g.closed=true}}()
 if !g.live(now)||j==nil||j.anchor==nil||j.failed||len(body)>1024{return nil,portableRefusal}
 f:=&g.fence
 switch op{
 case "reserve":
  var empty map[string]json.RawMessage
  if !scatteringDecode(body,&empty)||empty==nil||len(empty)!=0||f.pending!=nil||g.next>=scatteringRenewalAttempts{return nil,portableRefusal}
  previous:=f.previous;if g.next==0{previous=scatteringZero}
  if !scatteringHex.MatchString(previous)||(g.next==0)!=(previous==scatteringZero){return nil,portableRefusal}
  var random [32]byte;if _,e:=rand.Read(random[:]);e!=nil{return nil,e}
  r:=scatteringFenceReservation{hex.EncodeToString(random[:]),scatteringFenceContext{g.request.Channel,g.next,previous}}
  // Deliberately independent of token, transcript and previous hash.
  if e:=j.consume(g.fenceID("reserve",g.next,""));e!=nil{return nil,e}
  f.pending=&r;f.signed=false;f.staged=""
  return json.Marshal(r)
 case "stage","finish":
  var r scatteringFenceResult
  if !scatteringDecode(body,&r)||f.pending==nil||r.Token!=f.pending.Token||r.Generation!=f.pending.Context.Generation||g.next!=r.Generation+1||!f.signed||!scatteringHex.MatchString(r.Transcript)||r.Transcript==scatteringZero||r.Transcript==f.pending.Context.Previous{return nil,portableRefusal}
  if op=="stage"{
   if f.staged!=""{return nil,portableRefusal}
   if e:=j.consume(g.fenceID("stage",r.Generation,r.Transcript));e!=nil{return nil,e}
   f.staged=r.Transcript
  }else{
   if f.staged!=r.Transcript||!j.seen[g.fenceID("stage",r.Generation,r.Transcript)]{return nil,portableRefusal}
   // The trusted controller attests the authenticated UDP barrier. This
   // is NOT independent peer evidence verified by Go.
   if e:=j.consume(g.fenceID("finish",r.Generation,r.Transcript));e!=nil{return nil,e}
   f.previous=r.Transcript;f.pending=nil;f.staged="";f.signed=false
  }
  return json.Marshal(map[string]any{"generation":r.Generation,"transcript":r.Transcript})
 }
 return nil,portableRefusal
}
func scatteringFenceOperation(g *scatteringRenewalGrant,trust *senderTrust,j *replayLog,op string,body []byte)(json.RawMessage,error){
 if g==nil{return nil,portableRefusal}
 if trust==nil||j==nil||j.anchor==nil||!g.live(time.Now()){g.closed=true;return nil,portableRefusal}
 peer,ok:=trust.contacts[senderKey(g.request.Address,g.request.Device)]
 id,commit:=contactBinding(peer)
 if !ok||peer.Expires<=time.Now().UnixMilli()||id!=g.contactID||commit!=g.commitment||!j.beginContact(peer){g.closed=true;return nil,portableRefusal}
 defer j.endContact()
 out,e:=g.fenceStep(j,op,body,time.Now());if e!=nil{return nil,e}
 if e=j.anchor.check(j.anchorID,len(j.seen),j.tail);e!=nil||!g.live(time.Now())||peer.Expires<=time.Now().UnixMilli(){g.closed=true;return nil,portableRefusal}
 return out,nil
}
