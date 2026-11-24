//go:build windows && cgo && pqopenssl

package main

import (
 "bytes"
 "os"
 "path/filepath"
 "testing"
)

func TestWindowsEncryptedDraftDPAPI(t *testing.T){
 dir:=filepath.Join(t.TempDir(),"private-drafts")
 if e:=winCreatePrivateDirectory(dir);e!=nil{t.Fatal(e)}
 p:=filepath.Join(dir,"draft-a1478dbe30034bb58fda0123456789ab.json")
 plain:=[]byte("{\"context\":{\"clientMessageId\":\"synthetic\"},\"payload\":{\"body\":\"a unique confidential marker\"}}")
 if e:=winWriteEncryptedDraft(p,plain);e!=nil{t.Fatal(e)}
 if e:=winWriteEncryptedDraft(p,plain);e==nil{t.Fatal("overwrote existing draft")}
 raw,e:=winReadPrivate(p,16384);if e!=nil{t.Fatal(e)}
 if !bytes.HasPrefix(raw,draftMagic){t.Fatal("encrypted version marker absent")}
 if bytes.Contains(raw,[]byte("unique confidential marker")){t.Fatal("plaintext persisted")}
 opened,e:=winReadEncryptedDraft(p);if e!=nil{t.Fatal(e)}
 if !bytes.Equal(opened,plain){t.Fatal("DPAPI roundtrip mismatch")}
 clear(opened)
 other:=filepath.Join(dir,"draft-5678012345674a6bacde0123456789ab.json")
 if e:=winWritePrivate(other,raw);e!=nil{t.Fatal(e)}
 if _,e=winReadEncryptedDraft(other);e==nil{t.Fatal("ciphertext relocated without path binding")}
 legacy:=filepath.Join(dir,"draft-legacy.json")
 if e:=winWritePrivate(legacy,plain);e!=nil{t.Fatal(e)}
 if _,e=winReadEncryptedDraft(legacy);e==nil{t.Fatal("legacy cleartext draft was accepted")}
 raw[len(raw)-1]^=1
 if e=os.WriteFile(p,raw,0600);e!=nil{t.Fatal(e)}
 if _,e=winReadEncryptedDraft(p);e==nil{t.Fatal("tampered ciphertext accepted")}
}
