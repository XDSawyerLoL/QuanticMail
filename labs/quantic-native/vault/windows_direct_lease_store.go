//go:build windows && cgo && pqopenssl

package main

import "path/filepath"

// Open an already provisioned, separate contact journal inside a private
// NTFS directory. No auto-provisioning or unanchored recovery path.
// The caller must supply the original independently approved card and
// roster pin, and must enforce revocation policy before opening.
func winOpenDirectLeaseStore(dir string,self directIdentity,initial senderContact,members [4]directWitnessMember,rosterPin string)(*directLeaseStore,error){
 id,e:=directLeaseJournalID(initial,self.Address,self.Device,rosterPin);if e!=nil{return nil,e}
 j,e:=winOpenReplay(filepath.Join(dir,"lease-journal.log"),self.SigningPin,self.EncryptionPin,id);if e!=nil{return nil,e}
 if e=attachDirectPeerQuorum(j,id,members,rosterPin);e!=nil{j.close();return nil,e}
 s,e:=newDirectLeaseStore(j,dir,initial,self.Address,self.Device,rosterPin,winReadPrivate,winWritePrivate)
 if e!=nil{j.close();return nil,e};return s,nil
}
func(s *directLeaseStore)close(){if s!=nil&&s.j!=nil{s.j.close();s.j=nil}}

// Native private-network adapter. An independently provisioned roster and
// contact pin are mandatory; no web or unanchored fallback.
func winOpenDirectUDPLeaseStore(dir string,self directIdentity,initial senderContact,config [4]directUDPConfig,rosterPin string)(*directLeaseStore,error){
 id,e:=directLeaseJournalID(initial,self.Address,self.Device,rosterPin);if e!=nil{return nil,e}
 members,e:=directUDPQuorumMembers(config,id,rosterPin);if e!=nil{return nil,e}
 return winOpenDirectLeaseStore(dir,self,initial,members,rosterPin)
}
