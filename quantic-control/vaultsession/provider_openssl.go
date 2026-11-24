//go:build (linux || windows) && cgo && pqopenssl

package vaultsession

/*
#cgo pkg-config: openssl
#include <openssl/evp.h>
#include <openssl/x509.h>
static int available(void) {
 EVP_SIGNATURE *s=EVP_SIGNATURE_fetch(NULL,"ML-DSA-65",NULL);
 int ok=s!=NULL;
 EVP_SIGNATURE_free(s);
 return ok;
}
static int verify65(const unsigned char *der, long dn, const unsigned char *msg,
 size_t mn, const unsigned char *sig, size_t sn) {
 const unsigned char *p=der;
 EVP_PKEY *k=d2i_PUBKEY(NULL,&p,dn);
 EVP_MD_CTX *c=EVP_MD_CTX_new();
 int ok=k&&p==der+dn&&EVP_PKEY_is_a(k,"ML-DSA-65")==1&&c&&
 EVP_DigestVerifyInit(c,NULL,NULL,NULL,k)>0&&EVP_DigestVerify(c,sig,sn,msg,mn)==1;
 EVP_MD_CTX_free(c); EVP_PKEY_free(k);
 return ok;
}
*/
import "C"
import "unsafe"
func providerAvailable()bool{return C.available()==1}
func verifyMLDSA65(der,msg,sig []byte)bool{
 if len(der)!=1974||len(msg)==0||len(sig)!=3309{return false}
 return C.verify65((*C.uchar)(unsafe.Pointer(&der[0])),C.long(len(der)),
 (*C.uchar)(unsafe.Pointer(&msg[0])),C.size_t(len(msg)),
 (*C.uchar)(unsafe.Pointer(&sig[0])),C.size_t(len(sig)))==1
}
