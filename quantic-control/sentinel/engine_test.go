package sentinel

import("fmt";"testing";"time")
func feed(d *Detector,kind Kind,n int,now time.Time)*Alert{
    var last *Alert
    for i:=0;i<n;i++{if a:=d.Observe(Event{Path:fmt.Sprintf("file-%03d",i),Kind:kind,At:now.Add(time.Duration(i)*time.Millisecond)});a!=nil{last=a}}
    return last
}
func TestBurstDetection(t *testing.T){
    d:=NewDetector(Policy{})
    if a:=feed(d,Written,19,time.Now());a!=nil{t.Fatalf("false burst: %+v",a)}
    if a:=d.Observe(Event{Path:"file-019",Kind:Written,At:time.Now().Add(50*time.Millisecond)});a==nil||a.Level!="warning"{t.Fatalf("no burst alert %+v",a)}
}
func TestDestructiveThreshold(t *testing.T){
    d:=NewDetector(Policy{});a:=feed(d,Removed,8,time.Now())
    if a==nil||a.Level!="high"{t.Fatalf("missing destructive alert %+v",a)}
}
func TestRateLimitedAlerts(t *testing.T){
    d:=NewDetector(Policy{});now:=time.Now()
    if a:=feed(d,Removed,8,now);a==nil{t.Fatal("expected first alert")}
    if a:=feed(d,Removed,9,now.Add(time.Second));a!=nil{t.Fatalf("alert not rate-limited %+v",a)}
    if a:=feed(d,Removed,8,now.Add(time.Minute));a==nil{t.Fatal("expected alert after cooldown")}
}
func TestRepeatingOneFileDoesNotTriggerBurst(t *testing.T){
    d:=NewDetector(Policy{});now:=time.Now()
    for i:=0;i<500;i++{if a:=d.Observe(Event{Path:"single.txt",Kind:Written,At:now.Add(time.Duration(i)*time.Millisecond)});a!=nil{t.Fatalf("single path triggered: %+v",a)}}
}
func TestSuspiciousExtensionAndOverflow(t *testing.T){
    d:=NewDetector(Policy{});now:=time.Now()
    for i:=0;i<4;i++{
        a:=d.Observe(Event{Path:fmt.Sprintf("x-%d.locked",i),Kind:Renamed,At:now.Add(time.Duration(i)*time.Millisecond)})
        if i==3&&(a==nil||a.Level!="high"){t.Fatalf("expected alert %+v",a)}
    }
    d2:=NewDetector(Policy{})
    if a:=d2.Observe(Event{Kind:Overflow,At:now});a==nil{t.Fatal("overflow ignored")}
}
func TestOldEventsExpire(t *testing.T){
    d:=NewDetector(Policy{});now:=time.Now()
    if a:=feed(d,Written,19,now);a!=nil{t.Fatal("premature alert")}
    if a:=d.Observe(Event{Path:"new.txt",Kind:Written,At:now.Add(20*time.Second)});a!=nil{t.Fatal("old activity included")}
}
