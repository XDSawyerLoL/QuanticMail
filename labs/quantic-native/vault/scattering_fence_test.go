package main
import (
 "encoding/json"
 "strings"
 "testing"
 "time"
)
func TestScatteringNativeFenceJournal(t *testing.T){
 p,s,e,app:=testJournal(t);j,err:=openReplay(p,s,e,app);if err!=nil{t.Fatal(err)}
 defer func(){if j!=nil{j.close()}}()
 id,_:=anchorID(s,e,app);q:=&quorumAnchor{};var witnesses [4]*fakeAnchor
 for i:=range witnesses{witnesses[i]=&fakeAnchor{tail:j.tail};q.members[i]=witnesses[i]}
 if err=j.attachAnchor(q,id);err!=nil{t.Fatal(err)}
 now:=time.Now();peer:=senderContact{Address:"bob~"+strings.Repeat("a",32)+"@quantic",Device:"d-"+strings.Repeat("b",32),Expires:now.Add(3*time.Hour).UnixMilli()}
 cfg:=scatteringRenewalRequest{peer.Address,peer.Device,strings.Repeat("c",96),"initiator"}
 newGrant:=func()*scatteringRenewalGrant{g,e:=newScatteringRenewal(cfg,peer,now);if e!=nil{t.Fatal(e)};return g}
 g:=newGrant()
 reserve:=func(g *scatteringRenewalGrant)scatteringFenceReservation{
  raw,e:=g.fenceStep(j,"reserve",[]byte("{}"),now);if e!=nil{t.Fatal(e)}
  var r scatteringFenceReservation;if json.Unmarshal(raw,&r)!=nil{t.Fatal("reservation")};return r
 }
 for gen:=0;gen<2;gen++{
  r:=reserve(g);if r.Context.Generation!=gen{t.Fatal("generation")}
  if gen==1&&r.Context.Previous!=strings.Repeat("d",96){t.Fatal("previous")}
  raw,_:=json.Marshal([]any{[]any{scatteringSignDomain,r.Context.Channel,gen,r.Context.Previous,nil},"hello",nil})
  if !g.permitsFencedSignature(raw){t.Fatal("valid context refused")}
  bad,_:=json.Marshal([]any{[]any{scatteringSignDomain,r.Context.Channel,gen,strings.Repeat("f",96),nil},"hello",nil})
  if g.permitsFencedSignature(bad){t.Fatal("previous hash changed")}
  // Simulate the independently tested signature operation.
  g.next++;g.fence.signed=true
  transcript:=strings.Repeat(string(rune('d'+gen)),96)
  body,_:=json.Marshal(scatteringFenceResult{r.Token,gen,transcript})
  if _,e:=g.fenceStep(j,"stage",body,now);e!=nil{t.Fatal(e)}
  if _,e:=g.fenceStep(j,"finish",body,now);e!=nil{t.Fatal(e)}
 }
 if len(j.seen)!=6{t.Fatal("durable phase count")}
 for _,w:=range witnesses{if w.count!=6||w.tail!=j.tail{t.Fatal("missing witness records")}}
 // Interrupted next reservation burns the channel; no recovery via a fresh grant.
 reserve(g);j.close();j=nil
 j,err=openReplay(p,s,e,app);if err!=nil{t.Fatal(err)}
 if err=j.attachAnchor(q,id);err!=nil{t.Fatal(err)}
 restarted:=newGrant();if _,e:=restarted.fenceStep(j,"reserve",[]byte("{}"),now);e==nil||!restarted.closed{t.Fatal("channel recycled")}
 // A different channel cannot reserve without 3 available witnesses.
 cfg.Channel=strings.Repeat("9",96);g=newGrant();witnesses[0].fail=true;witnesses[1].fail=true
 if _,e:=g.fenceStep(j,"reserve",[]byte("{}"),now);e==nil||!j.failed{t.Fatal("quorum failure released reservation")}
}
