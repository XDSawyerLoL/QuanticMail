package main
import "encoding/json"

// The pinned directory supplies the key material, but cannot by itself
// authorize delivery. Each mail operation uses the same contact bound into
// both the read-only precheck and the durable checkpoint CAS.
func contactBinding(s senderContact)(string,string){
 id,_:=json.Marshal([]string{"quantic-contact-id-lab/v1",s.Address,s.Device})
 keys,_:=json.Marshal([]string{"quantic-contact-keys-lab/v1",s.Address,s.Device,hexHash(s.ClassicalRoot),hexHash(s.PQRoot),hexHash(s.Encryption),hexHash(s.KEM)})
 return hexHash(id),hexHash(keys)
}
func(j *replayLog) beginContact(s senderContact)bool{
 if j==nil{return false}
 a,ok:=j.anchor.(*freshQuorum);if !ok||a.localProof==nil||a.contactID!=""{return false}
 a.contactID,a.contactCommitment=contactBinding(s)
 if a.check(j.anchorID,len(j.seen),j.tail)!=nil{j.endContact();return false}
 return true
}
func(j *replayLog) endContact(){
 if a,ok:=j.anchor.(*freshQuorum);ok{a.contactID,a.contactCommitment="",""}
}
