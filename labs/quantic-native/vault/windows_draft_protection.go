//go:build windows && cgo && pqopenssl

package main

/*
#cgo LDFLAGS: -lcrypt32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
static int qv_draft_crypt(int decrypt, BYTE *data, DWORD n, BYTE *entropy, DWORD en, DATA_BLOB *out) {
 DATA_BLOB in={n,data}, extra={en,entropy};
 if(decrypt) return CryptUnprotectData(&in,NULL,&extra,NULL,NULL,CRYPTPROTECT_UI_FORBIDDEN,out);
 return CryptProtectData(&in,L"Quantic Sillage draft v1",&extra,NULL,NULL,CRYPTPROTECT_UI_FORBIDDEN,out);
}
static void qv_draft_free(DATA_BLOB *b) {
 if(b->pbData){SecureZeroMemory(b->pbData,b->cbData);LocalFree(b->pbData);}
}
*/
import "C"
import (
 "bytes"
 "crypto/sha256"
 "encoding/json"
 "path/filepath"
 "unsafe"
)

const draftMagic="QSDRAFT-DPAPI-v1\x00"

// DPAPI current-user protection is defense in depth for data at rest,
// NOT isolation from arbitrary code running as the same Windows user.
func winDraftCrypt(path string, data []byte, decrypt bool)([]byte,error){
 if !clientDraftName.MatchString(filepath.Base(path)) || len(data)<1 || len(data)>32768{return nil,portableRefusal}
 if _,_,e:=winPathParts(path);e!=nil{return nil,e}
 entropy:=sha256.Sum256([]byte("quantic-draft-path/v1\x00"+path))
 var out C.DATA_BLOB
 mode:=C.int(0);if decrypt{mode=1}
 ok:=C.qv_draft_crypt(mode,(*C.BYTE)(unsafe.Pointer(&data[0])),C.DWORD(len(data)),(*C.BYTE)(unsafe.Pointer(&entropy[0])),C.DWORD(len(entropy)),&out)
 defer C.qv_draft_free(&out)
 if ok==0||out.pbData==nil||out.cbData==0||out.cbData>32768{return nil,portableRefusal}
 return C.GoBytes(unsafe.Pointer(out.pbData),C.int(out.cbData)),nil
}
func winWriteProtectedDraft(path string,plain []byte)error{
 if len(plain)<1||len(plain)>8192||!json.Valid(plain){return portableRefusal}
 sealed,e:=winDraftCrypt(path,plain,false);if e!=nil{return e};defer clear(sealed)
 raw:=append([]byte(draftMagic),sealed...);defer clear(raw)
 return winWritePrivate(path,raw)
}
func winReadProtectedDraft(path string)([]byte,error){
 raw,e:=winReadPrivate(path,32768+len(draftMagic));if e!=nil{return nil,e};defer clear(raw)
 if !bytes.HasPrefix(raw,[]byte(draftMagic)){return nil,portableRefusal}
 plain,e:=winDraftCrypt(path,raw[len(draftMagic):],true)
 if e!=nil{return nil,e}
 if len(plain)>8192||!json.Valid(plain){clear(plain);return nil,portableRefusal}
 return plain,nil
}
