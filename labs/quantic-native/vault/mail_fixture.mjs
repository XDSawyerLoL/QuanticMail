// Test fixture: same WebCrypto ECDH->AES-GCM wire format as QuanticMail crypto.ts.
// Recipient is a native public point. No private key is provided to Node.
const raw=Buffer.from(process.argv[2],'base64url');
if(raw.length!==65||raw[0]!==4)throw Error('invalid recipient');
const recipientPublicJwk={kty:'EC',crv:'P-256',x:raw.subarray(1,33).toString('base64url'),y:raw.subarray(33).toString('base64url')};
const recipientPublicKey=await crypto.subtle.importKey('jwk',recipientPublicJwk,{name:'ECDH',namedCurve:'P-256'},false,[]);
const ephemeral=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveKey']);
const aesKey=await crypto.subtle.deriveKey({name:'ECDH',public:recipientPublicKey},ephemeral.privateKey,{name:'AES-GCM',length:256},false,['encrypt']);
const iv=crypto.getRandomValues(new Uint8Array(12));
const plaintext=new TextEncoder().encode(JSON.stringify({subject:'interop',body:'synthetic mail only'}));
const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv},aesKey,plaintext);
console.log(JSON.stringify({ciphertext:Buffer.from(ciphertext).toString('base64'),iv:Buffer.from(iv).toString('base64'),ephemeralPublicKey:await crypto.subtle.exportKey('jwk',ephemeral.publicKey)}));
