package main

import (
 "encoding/json"
 "strings"
 "testing"
 "time"
)
func TestScatteringRenewalScope(t *testing.T){
 now:=time.Now()
 peer:=senderContact{Address:"bob~"+strings.Repeat("a",32)+"@quantic",Device:"d-"+strings.Repeat("b",32),ClassicalRoot:[]byte{1},PQRoot:[]byte{2},Expires:now.Add(3*time.Hour).UnixMilli()}
 q:=scatteringRenewalRequest{peer.Address,peer.Device,strings.Repeat("c",96),"initiator"}
 makeGrant:=func()*scatteringRenewalGrant{g,e:=newScatteringRenewal(q,peer,now);if e!=nil{t.Fatal(e)};return g}
 frame:=func(channel,stage string,generation int)[]byte{v,_:=json.Marshal([]any{[]any{scatteringSignDomain,channel,generation,scatteringZero,nil},stage,nil});return v}
 g:=makeGrant()
 for i:=0;i<4;i++{if !g.consume(peer,frame(q.Channel,"hello",i),now){t.Fatal("valid scope refused",i)}}
 if g.consume(peer,frame(q.Channel,"hello",4),now)||!g.closed{t.Fatal("budget exceeded")}
 for _,bad:=range [][]byte{frame(q.Channel,"hello",1),frame(q.Channel,"response",0),frame(strings.Repeat("d",96),"hello",0),[]byte("null")}{
  g=makeGrant();if g.consume(peer,bad,now)||g.consume(peer,frame(q.Channel,"hello",0),now){t.Fatal("bad scope or subsequent retry accepted")}
 }
 g=makeGrant();if !g.consume(peer,frame(q.Channel,"hello",0),now)||g.consume(peer,frame(q.Channel,"hello",0),now){t.Fatal("duplicate generation accepted")}
 g=makeGrant();changed:=peer;changed.PQRoot=[]byte{3};if g.consume(changed,frame(q.Channel,"hello",0),now){t.Fatal("changed keys accepted")}
 g=makeGrant();if g.consume(peer,frame(q.Channel,"hello",0),now.Add(2*time.Hour)){t.Fatal("expired grant accepted")}
 short:=peer;short.Expires=now.Add(time.Minute).UnixMilli();g,e:=newScatteringRenewal(q,short,now);if e!=nil||g.live(now.Add(time.Minute)){t.Fatal("contact expiry ignored")}
}
