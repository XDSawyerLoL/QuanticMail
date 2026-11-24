//go:build (linux || windows) && cgo && pqopenssl

package main

// Native public enrollment claim. The root signing keys and the device keys
// are generated independently. A signed claim is not an enrollment, contact
// permission, attestation or transport credential.
import (
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/sha256"
 "crypto/x509"
 "encoding/base64"
 "encoding/json"
 "regexp"
 "time"
)

var enrollmentHandle=regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,31}$`)
type enrollmentJWK struct {
 Kty string `json:"kty"`
 Crv string `json:"crv"`
 X string `json:"x"`
 Y string `json:"y"`
}
func enrollmentPoint(point []byte)(enrollmentJWK,error){
 if len(point)!=65||point[0]!=4{return enrollmentJWK{},portableRefusal}
 x,y:=elliptic.Unmarshal(elliptic.P256(),point)
 if x==nil||y==nil{return enrollmentJWK{},portableRefusal}
 return enrollmentJWK{"EC","P-256",b64.EncodeToString(point[1:33]),b64.EncodeToString(point[33:])},nil
}
func enrollmentFingerprint(j enrollmentJWK)string{
 return hexHash([]byte("P-256:"+j.X+":"+j.Y))[:32]
}
func enrollmentSignature(k *ecdsa.PrivateKey,raw []byte)(string,error){
 h:=sha256.Sum256(raw)
 r,s,e:=ecdsa.Sign(rand.Reader,k,h[:])
 if e!=nil{return "",e}
 sig:=make([]byte,64)
 r.FillBytes(sig[:32]);s.FillBytes(sig[32:])
 return base64.StdEncoding.EncodeToString(sig),nil
}
type enrollmentManifestDevice struct {
 DeviceID string `json:"deviceId"`
 Label string `json:"label"`
 PublicKey enrollmentJWK `json:"publicKey"`
 DeviceSigningPublicKey enrollmentJWK `json:"deviceSigningPublicKey"`
 Kind string `json:"kind"`
 IssuedAt string `json:"issuedAt"`
}
type enrollmentManifestPayload struct {
 Version int `json:"version"`
 Sequence int `json:"sequence"`
 CanonicalAddress string `json:"canonicalAddress"`
 Handle string `json:"handle"`
 Fingerprint string `json:"fingerprint"`
 IdentityPublicKey enrollmentJWK `json:"identityPublicKey"`
 IdentitySigningPublicKey enrollmentJWK `json:"identitySigningPublicKey"`
 Devices []enrollmentManifestDevice `json:"devices"`
 Revocations []json.RawMessage `json:"revocations"`
 IssuedAt string `json:"issuedAt"`
}
type enrollmentManifest struct {
 Format string `json:"format"`
 Version int `json:"version"`
 Payload enrollmentManifestPayload `json:"payload"`
 Signature string `json:"signature"`
}
type enrollmentPQDevice struct {
 DeviceID string `json:"deviceId"`
 MLKEMAlgorithm string `json:"mlKemAlgorithm"`
 MLKEMPublicKeySPKI string `json:"mlKemPublicKeySpki"`
 MLDSAAlgorithm string `json:"mlDsaAlgorithm"`
 MLDSAPublicKeySPKI string `json:"mlDsaPublicKeySpki"`
}
type enrollmentProfilePayload struct {
 Version int `json:"version"`
 Sequence int `json:"sequence"`
 CanonicalAddress string `json:"canonicalAddress"`
 IdentitySigningPublicKey enrollmentJWK `json:"identitySigningPublicKey"`
 IdentityManifestSequence int `json:"identityManifestSequence"`
 Policy string `json:"policy"`
 IdentityMLDSAAlgorithm string `json:"identityMlDsaAlgorithm"`
 IdentityMLDSAPublicKeySPKI string `json:"identityMlDsaPublicKeySpki"`
 Devices []enrollmentPQDevice `json:"devices"`
 IssuedAt string `json:"issuedAt"`
}
type enrollmentProfile struct {
 Format string `json:"format"`
 Version int `json:"version"`
 Payload enrollmentProfilePayload `json:"payload"`
 Signatures struct{
  P256 string `json:"p256"`
  MLDSA65Self string `json:"mlDsa65Self"`
 } `json:"signatures"`
}
type enrollmentClaim struct{
 Format string `json:"format"`
 Version int `json:"version"`
 LabOnly bool `json:"labOnly"`
 Status string `json:"status"`
 RemotelyEnrolled bool `json:"remotelyEnrolled"`
 MailAuthorized bool `json:"mailAuthorized"`
 Address string `json:"address"`
 DeviceID string `json:"deviceId"`
 RootPin string `json:"rootPin"`
 PQRootPin string `json:"pqRootPin"`
 SigningPin string `json:"signingPin"`
 EncryptionPin string `json:"encryptionPin"`
 KemPin string `json:"kemPin"`
 DsaPin string `json:"dsaPin"`
 ManifestDigest string `json:"manifestDigest"`
 ProfileDigest string `json:"profileDigest"`
 Manifest enrollmentManifest `json:"manifest"`
 Profile enrollmentProfile `json:"profile"`
}
func nativeEnrollmentClaim(handle string,owner *ecdsa.PrivateKey,device portableKeys,pq *pqKeys,rootPQ pqKey,now time.Time)(enrollmentClaim,error){
 var out enrollmentClaim
 if !enrollmentHandle.MatchString(handle)||owner==nil||device.signing==nil||device.agreement==nil||pq==nil||now.IsZero(){return out,portableRefusal}
 rootJWK,e:=enrollmentPoint(elliptic.Marshal(elliptic.P256(),owner.X,owner.Y));if e!=nil{return out,e}
 signJWK,e:=enrollmentPoint(elliptic.Marshal(elliptic.P256(),device.signing.X,device.signing.Y));if e!=nil{return out,e}
 encJWK,e:=enrollmentPoint(device.agreement.PublicKey().Bytes());if e!=nil{return out,e}
 if rootJWK==signJWK||rootJWK==encJWK||signJWK==encJWK{return out,portableRefusal}
 fp:=enrollmentFingerprint(rootJWK)
 addr:=handle+"~"+fp+"@quantic"
 id:="d-"+enrollmentFingerprint(encJWK)
 if pq.address!=addr||pq.device!=id{return out,portableRefusal}
 rootDER,e:=rootPQ.der(false)
 if e!=nil||len(rootDER)!=1974||hexHash(rootDER)==pq.dsaPin||len(pq.kemPub)!=1206||len(pq.dsaPub)!=1974{return out,portableRefusal}
 stamp:=now.UTC().Format("2006-01-02T15:04:05.000Z")
 mp:=enrollmentManifestPayload{1,1,addr,handle,fp,encJWK,rootJWK,
  []enrollmentManifestDevice{{id,"Windows Alpha lab",encJWK,signJWK,"root",stamp}},
  []json.RawMessage{},stamp}
 mraw,e:=json.Marshal(mp);if e!=nil{return out,e}
 ms,e:=enrollmentSignature(owner,mraw);if e!=nil{return out,e}
 pp:=enrollmentProfilePayload{2,1,addr,rootJWK,1,"hybrid-required","ML-DSA-65",b64.EncodeToString(rootDER),
  []enrollmentPQDevice{{id,"ML-KEM-768",b64.EncodeToString(pq.kemPub),"ML-DSA-65",b64.EncodeToString(pq.dsaPub)}},stamp}
 praw,e:=json.Marshal(pp);if e!=nil{return out,e}
 ps,e:=enrollmentSignature(owner,praw);if e!=nil{return out,e}
 qs,e:=rootPQ.sign(praw);if e!=nil||!pqVerifyRoot(rootDER,praw,qs){return out,portableRefusal}
 profile:=enrollmentProfile{Format:"quantic-crypto-profile",Version:2,Payload:pp}
 profile.Signatures.P256=ps;profile.Signatures.MLDSA65Self=b64.EncodeToString(qs)
 s,a:=portablePins(device)
 return enrollmentClaim{
  Format:"quantic-native-enrollment-claim-lab/v1",Version:1,LabOnly:true,Status:"signed-claim-not-enrolled",
  Address:addr,DeviceID:id,RootPin:publicPin(&owner.PublicKey),PQRootPin:hexHash(rootDER),
  SigningPin:s,EncryptionPin:a,KemPin:pq.kemPin,DsaPin:pq.dsaPin,
  ManifestDigest:hexHash(mraw),ProfileDigest:hexHash(praw),
  Manifest:enrollmentManifest{"quantic-identity-manifest",1,mp,ms},Profile:profile,
 },nil
}
// Protect the two independent owner private keys with a separate, third
// passphrase, unique salt and authenticated binding. Never export plaintext.
func sealEnrollmentRoots(owner *ecdsa.PrivateKey,rootPQ pqKey,claim enrollmentClaim,password []byte)([]byte,error){
 if !validPortablePassword(password)||owner==nil||!strongAddr.MatchString(claim.Address)||
  !hashRE.MatchString(claim.RootPin)||!hashRE.MatchString(claim.PQRootPin){return nil,portableRefusal}
 if publicPin(&owner.PublicKey)!=claim.RootPin{return nil,portableRefusal}
 rootPub,e:=rootPQ.der(false);if e!=nil||hexHash(rootPub)!=claim.PQRootPin{return nil,portableRefusal}
 classical,e:=x509.MarshalPKCS8PrivateKey(owner);if e!=nil{return nil,e};defer clear(classical)
 post,e:=rootPQ.der(true);if e!=nil{return nil,e};defer clear(post)
 raw,e:=json.Marshal([][]byte{classical,post});if e!=nil{return nil,e};defer clear(raw)
 var salt [16]byte;var nonce [12]byte
 if _,e=rand.Read(salt[:]);e!=nil{return nil,e}
 if _,e=rand.Read(nonce[:]);e!=nil{return nil,e}
 aead,e:=portableAEAD(password,salt[:]);if e!=nil{return nil,e}
 header:=[]byte("QV-OWNER-ROOTS-LAB-V1\x00"+claim.Address+"\x00"+claim.RootPin+claim.PQRootPin+"\x00")
 header=append(header,salt[:]...);header=append(header,nonce[:]...)
 return aead.Seal(header,nonce[:],raw,header),nil
}
