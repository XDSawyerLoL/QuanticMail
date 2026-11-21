// Never silently strip a newer cryptographic envelope at the legacy send boundary.
export function hasUnsupportedNativeFields(body){
 if(!body||typeof body!=='object'||Array.isArray(body))return true;
 return ['format','version','context','envelope','pqContext','pqEnvelope','senderAuth','signatures','cryptoSuite','pqKemCiphertext','classicalEphemeralPublicKey','preKeyId','keyMode'].some(k=>Object.hasOwn(body,k));
}
