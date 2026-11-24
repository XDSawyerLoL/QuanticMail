//go:build windows && cgo && pqopenssl

package main

/*
#cgo LDFLAGS: -lcrypt32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <dpapi.h>

// DPAPI CurrentUser only. Never permit CryptProtectData to prompt, roam,
// use machine scope, or persist plaintext during a failed encryption.
static int qs_draft_dpapi(int decrypt, BYTE *source, DWORD size,
                          BYTE *entropy, DWORD entropySize,
                          BYTE **result, DWORD *resultSize) {
  DATA_BLOB incoming={size,source};
  DATA_BLOB additional={entropySize,entropy};
  DATA_BLOB output={0,NULL};
  BOOL ok=decrypt
    ? CryptUnprotectData(&incoming,NULL,&additional,NULL,NULL,CRYPTPROTECT_UI_FORBIDDEN,&output)
    : CryptProtectData(&incoming,L"Quantic Sillage private laboratory draft",&additional,NULL,NULL,CRYPTPROTECT_UI_FORBIDDEN,&output);
  if(!ok)return 0;
  *result=output.pbData;
  *resultSize=output.cbData;
  return 1;
}
static void qs_draft_free(BYTE *b,DWORD size) {
  if(b){SecureZeroMemory(b,size);LocalFree(b);}
}
*/
import "C"

import (
 "bytes"
 "crypto/sha256"
 "errors"
 "path/filepath"
 "unsafe"
)

var draftMagic=[]byte{'Q','S','D','2',0}
var draftUnavailable=errors.New("encrypted Windows Alpha draft unavailable")

// Extra entropy binds the ciphertext to the exact private path. It is NOT
// the encryption key; Windows CurrentUser DPAPI supplies the key protection.
// This interim Windows-only lab container is not PQ, portable or production.
func draftEntropy(path string)[32]byte{
 return sha256.Sum256([]byte("quantic-sillage-alpha-draft/current-user/v2\x00"+path))
}
func draftDPAPI(path string,source []byte,decrypt bool)([]byte,error){
 if len(source)<1||len(source)>16384{return nil,draftUnavailable}
 entropy:=draftEntropy(path)
 var output *C.BYTE
 var outputLength C.DWORD
 mode:=C.int(0)
 if decrypt{mode=1}
 if C.qs_draft_dpapi(mode,(*C.BYTE)(unsafe.Pointer(&source[0])),C.DWORD(len(source)),
   (*C.BYTE)(unsafe.Pointer(&entropy[0])),C.DWORD(len(entropy)),&output,&outputLength)==0{
   return nil,draftUnavailable
 }
 defer C.qs_draft_free(output,outputLength)
 if outputLength<1||outputLength>16384{return nil,draftUnavailable}
 return C.GoBytes(unsafe.Pointer(output),C.int(outputLength)),nil
}
func winWriteEncryptedDraft(path string,plaintext []byte)error{
 if _,_,e:=winPathParts(path);e!=nil{return e}
 if !clientDraftName.MatchString(filepath.Base(path))||len(plaintext)<2||len(plaintext)>8192{
   return draftUnavailable
 }
 ciphertext,e:=draftDPAPI(path,plaintext,false)
 if e!=nil{return e}
 defer clear(ciphertext)
 packed:=make([]byte,0,len(draftMagic)+len(ciphertext))
 packed=append(packed,draftMagic...)
 packed=append(packed,ciphertext...)
 defer clear(packed)
 if len(packed)>16384{return draftUnavailable}
 return winWritePrivate(path,packed) // CREATE_NEW, ACL check, fsync. Never plaintext.
}
func winReadEncryptedDraft(path string)([]byte,error){
 if _,_,e:=winPathParts(path);e!=nil{return nil,e}
 if !clientDraftName.MatchString(filepath.Base(path)){return nil,draftUnavailable}
 packed,e:=winReadPrivate(path,16384)
 if e!=nil{return nil,e}
 defer clear(packed)
 if len(packed)<=len(draftMagic)||!bytes.Equal(packed[:len(draftMagic)],draftMagic){
   return nil,draftUnavailable // Refuse legacy plaintext JSON, never auto-migrate.
 }
 opened,e:=draftDPAPI(path,packed[len(draftMagic):],true)
 if e!=nil{return nil,e}
 if len(opened)<2||len(opened)>8192{clear(opened);return nil,draftUnavailable}
 return opened,nil // Caller must immediately clear after bounded private pipe transfer.
}
