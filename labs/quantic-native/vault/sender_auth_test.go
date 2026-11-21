package main
import (
 "strings"
 "testing"
)
func TestSenderTrustExpiryAndExactDevice(t *testing.T){
 c:=pqContext{From:"bob~"+strings.Repeat("a",32)+"@quantic",FromDeviceID:"d-"+strings.Repeat("b",32)}
 s:=senderTrust{contacts:map[string]senderContact{senderKey(c.From,c.FromDeviceID):{Expires:2000}}}
 if _,ok:=s.contact(c,1999);!ok{t.Fatal("known sender refused")}
 if _,ok:=s.contact(c,2000);ok{t.Fatal("expired sender accepted")}
 c.FromDeviceID="d-"+strings.Repeat("c",32)
 if _,ok:=s.contact(c,1999);ok{t.Fatal("untrusted device accepted")}
}
