package main

import (
 "encoding/json"
 "time"
)
const scatteringRenewalAttempts = 4
const scatteringRenewalLifetime = 2*time.Hour
type scatteringRenewalRequest struct {
 Address string `json:"address"`
 Device string `json:"deviceId"`
 Channel string `json:"channel"`
 Role string `json:"role"`
}
// Memory only, scoped to one authenticated broker process. No secret export,
// grant persistence, recovery or automatic extension. Counts attempts, not
// completed transport sessions. The durable journal remains authoritative.
type scatteringRenewalGrant struct{
 request scatteringRenewalRequest
 contactID,commitment string
 deadline time.Time
 expires int64
 next int
 closed bool
 fence scatteringFenceState
}
func newScatteringRenewal(q scatteringRenewalRequest,peer senderContact,now time.Time)(*scatteringRenewalGrant,error){
 if q.Address!=peer.Address||q.Device!=peer.Device||!strongAddr.MatchString(q.Address)||!strongDevice.MatchString(q.Device)||!scatteringHex.MatchString(q.Channel)||q.Channel==scatteringZero||(q.Role!="initiator"&&q.Role!="responder")||peer.Expires<=now.UnixMilli(){return nil,portableRefusal}
 id,commit:=contactBinding(peer)
 deadline:=now.Add(scatteringRenewalLifetime)
 if remaining:=time.Duration(peer.Expires-now.UnixMilli())*time.Millisecond;remaining<scatteringRenewalLifetime{deadline=now.Add(remaining)}
 return &scatteringRenewalGrant{request:q,contactID:id,commitment:commit,deadline:deadline,expires:deadline.UnixMilli()},nil
}
func(g *scatteringRenewalGrant)live(now time.Time)bool{
 return g!=nil&&!g.closed&&now.Before(g.deadline)&&now.UnixMilli()<g.expires
}
func(g *scatteringRenewalGrant)consume(peer senderContact,raw []byte,now time.Time)bool{
 if g==nil{return false}
 if !g.live(now)||g.next>=scatteringRenewalAttempts||peer.Expires<=now.UnixMilli(){g.closed=true;return false}
 id,commit:=contactBinding(peer)
 var outer,prefix []json.RawMessage
 var channel,stage string;var generation int
 valid:=id==g.contactID&&commit==g.commitment&&scatteringDecode(raw,&outer)&&len(outer)==3&&scatteringDecode(outer[0],&prefix)&&len(prefix)==5&&scatteringDecode(prefix[1],&channel)&&scatteringDecode(prefix[2],&generation)&&scatteringDecode(outer[1],&stage)
 if !valid||channel!=g.request.Channel||generation!=g.next||!(g.request.Role=="initiator"&&stage=="hello"||g.request.Role=="responder"&&stage=="response"){g.closed=true;return false}
 g.next++ // Burn the attempt before any anchored signature operation.
 return true
}
func issueScatteringRenewal(p *pqKeys,trust *senderTrust,j *replayLog,approve func(string)bool,body []byte)(*scatteringRenewalGrant,error){
 var q scatteringRenewalRequest
 if p==nil||trust==nil||j==nil||j.anchor==nil||len(body)>1024||!scatteringDecode(body,&q)||q.Address==p.address&&q.Device==p.device{return nil,portableRefusal}
 peer,ok:=trust.contacts[senderKey(q.Address,q.Device)];if !ok{return nil,portableRefusal}
 if _,e:=newScatteringRenewal(q,peer,time.Now());e!=nil{return nil,e}
 if !approve("Autoriser au maximum 4 tentatives Scattering LAB pendant 2 heures avec "+peer.Address+" / "+peer.Device+" / "+q.Role+" / canal "+q.Channel+" ?")||!j.beginContact(peer){return nil,portableRefusal}
 defer j.endContact()
 return newScatteringRenewal(q,peer,time.Now())
}
