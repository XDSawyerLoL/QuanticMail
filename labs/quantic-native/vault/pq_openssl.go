//go:build linux && cgo && pqopenssl

package main

/*
#cgo pkg-config: openssl
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>
#include <stdlib.h>
static EVP_PKEY *pqgen(const char *alg) {
 EVP_PKEY_CTX *ctx=EVP_PKEY_CTX_new_from_name(NULL,alg,NULL); EVP_PKEY *k=NULL;
 if(ctx && EVP_PKEY_keygen_init(ctx)>0 && EVP_PKEY_generate(ctx,&k)>0) {} else {EVP_PKEY_free(k);k=NULL;}
 EVP_PKEY_CTX_free(ctx);return k;
}
static EVP_PKEY *pqread(const unsigned char *p,long n){ const unsigned char *end=p+n; EVP_PKEY *k=d2i_AutoPrivateKey(NULL,&p,n);if(p!=end){EVP_PKEY_free(k);return NULL;}return k; }
static int pqverifyroot(const unsigned char *der,long dn,const unsigned char *m,size_t mn,const unsigned char *sig,size_t sn){
 const unsigned char *p=der; EVP_PKEY *k=d2i_PUBKEY(NULL,&p,dn);
 EVP_MD_CTX *c=EVP_MD_CTX_new();
 int ok=k&&p==der+dn&&EVP_PKEY_is_a(k,"ML-DSA-65")==1&&c&&EVP_DigestVerifyInit(c,NULL,NULL,NULL,k)>0&&EVP_DigestVerify(c,sig,sn,m,mn)==1;
 EVP_MD_CTX_free(c);EVP_PKEY_free(k);return ok;
}
static int pqpriv(EVP_PKEY *k,unsigned char *out,int cap){PKCS8_PRIV_KEY_INFO *p=EVP_PKEY2PKCS8(k);if(!p)return -1;int n=i2d_PKCS8_PRIV_KEY_INFO(p,NULL);if(n>0&&n<=cap)i2d_PKCS8_PRIV_KEY_INFO(p,&out);else n=-1;PKCS8_PRIV_KEY_INFO_free(p);return n;}
static int pqpub(EVP_PKEY *k,unsigned char *out,int cap){int n=i2d_PUBKEY(k,NULL);if(n<=0||n>cap)return -1;return i2d_PUBKEY(k,&out);}
static int pqdec(EVP_PKEY *k,const unsigned char *ct,size_t n,unsigned char *out){EVP_PKEY_CTX *c=EVP_PKEY_CTX_new_from_pkey(NULL,k,NULL);size_t len=32;int ok=c&&EVP_PKEY_decapsulate_init(c,NULL)>0&&EVP_PKEY_decapsulate(c,out,&len,ct,n)>0&&len==32;EVP_PKEY_CTX_free(c);return ok;}
static int pqsign(EVP_PKEY *k,const unsigned char *m,size_t n,unsigned char *out,size_t *len){EVP_MD_CTX *c=EVP_MD_CTX_new();int ok=c&&EVP_DigestSignInit(c,NULL,NULL,NULL,k)>0&&EVP_DigestSign(c,out,len,m,n)>0;EVP_MD_CTX_free(c);return ok;}
static int pqverify(EVP_PKEY *k,const unsigned char *m,size_t n,const unsigned char *sig,size_t len){EVP_MD_CTX *c=EVP_MD_CTX_new();int ok=c&&EVP_DigestVerifyInit(c,NULL,NULL,NULL,k)>0&&EVP_DigestVerify(c,sig,len,m,n)>0;EVP_MD_CTX_free(c);return ok;}
*/
import "C"
import (
	"errors"
	"unsafe"
)

type pqKey struct{ k *C.EVP_PKEY }

func ptr(b []byte) *C.uchar { return (*C.uchar)(unsafe.Pointer(&b[0])) }
func pqGenerate(alg string) (pqKey, error) {
	s := C.CString(alg)
	defer C.free(unsafe.Pointer(s))
	k := C.pqgen(s)
	if k == nil {
		return pqKey{}, errors.New("PQ generation refused")
	}
	return pqKey{k}, nil
}
func pqImport(raw []byte, alg string) (pqKey, error) {
	if len(raw) == 0 || len(raw) > 16384 {
		return pqKey{}, errors.New("PQ size")
	}
	k := C.pqread(ptr(raw), C.long(len(raw)))
	s := C.CString(alg)
	defer C.free(unsafe.Pointer(s))
	if k == nil || C.EVP_PKEY_is_a(k, s) != 1 {
		C.EVP_PKEY_free(k)
		return pqKey{}, errors.New("PQ import refused")
	}
	return pqKey{k}, nil
}
func (k pqKey) close() { C.EVP_PKEY_free(k.k) }
func (k pqKey) der(priv bool) ([]byte, error) {
	b := make([]byte, 16384)
	var n C.int
	if priv {
		n = C.pqpriv(k.k, ptr(b), C.int(len(b)))
	} else {
		n = C.pqpub(k.k, ptr(b), C.int(len(b)))
	}
	if n <= 0 {
		clear(b)
		return nil, errors.New("PQ DER")
	}
	return b[:int(n)], nil
}
func (k pqKey) dec(ct []byte) ([]byte, error) {
	if len(ct) != 1088 {
		return nil, errors.New("ML-KEM ciphertext size")
	}
	b := make([]byte, 32)
	if C.pqdec(k.k, ptr(ct), C.size_t(len(ct)), ptr(b)) != 1 {
		clear(b)
		return nil, errors.New("ML-KEM refused")
	}
	return b, nil
}
func (k pqKey) sign(m []byte) ([]byte, error) {
	if len(m) == 0 {
		return nil, errors.New("empty proof")
	}
	b := make([]byte, 3309)
	n := C.size_t(len(b))
	if C.pqsign(k.k, ptr(m), C.size_t(len(m)), ptr(b), &n) != 1 || int(n) != 3309 || C.pqverify(k.k, ptr(m), C.size_t(len(m)), ptr(b), n) != 1 {
		return nil, errors.New("ML-DSA refused")
	}
	return b, nil
}

func pqVerifyRoot(der, message, signature []byte) bool {
	if len(der)!=1974 || len(message)==0 || len(signature)!=3309 { return false }
	return C.pqverifyroot(ptr(der),C.long(len(der)),ptr(message),C.size_t(len(message)),ptr(signature),C.size_t(len(signature)))==1
}
