// Native-specific routes; local experimental path, no browser CORS or generic downgrade.
import {authenticateLocalDevice,RelayError} from './relay.ts';
import {nativeRecordDigest,normalizeNativeRecord,enqueueNativeRecord,pullNativeRecord,acknowledgeNativeRecord,recoverNativeRecord} from './native-mailbox.mjs';
import {verifyNativeWire,bindNativeContact} from './native-identity-bridge.mjs';
const check=ok=>{if(!ok)throw new RelayError('Autorisation native refusée.',403);};
const addr=/^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$/;
const dev=/^d-[a-f0-9]{32}$/;
export async function nativeMailboxOperation(runtime,peerSource,op,body,token){
 check(body&&typeof body==='object'&&!Array.isArray(body)&&typeof peerSource==='function');
 let record,who,device;
 try{
  if(op==='send'){record=normalizeNativeRecord(body);who=record.context.from;device=record.context.fromDeviceId;}
  else{who=body.address;device=body.deviceId;}
 }catch{throw new RelayError('Enveloppe native invalide.',400);}
 check(typeof who==='string'&&addr.test(who)&&typeof device==='string'&&dev.test(device));
 function auth(){
  const result=authenticateLocalDevice(who,token,device);
  check(result.canonicalAddress===who&&result.deviceId===device);
 }
 await runtime.read(auth);
 let own,other;
 try{
  own=await peerSource(who,device);
  if(op==='send')other=await peerSource(record.context.to,record.context.toDeviceId);
 }catch{throw new RelayError('Autorité native indisponible.',503);}
 function current(peer,address,deviceId){
  const result=bindNativeContact(peer.bundle,peer.checkpoint);
  check(result.address===address&&result.deviceId===deviceId);
 }
 // Attestation acquisition is outside the serialized state mutation; recheck
 // expiration, identity and token inside it before making durable changes.
 return runtime.mutate(()=>{
  auth();
  try{
   current(own,who,device);
   if(op==='send'){
    current(other,record.context.to,record.context.toDeviceId);
    verifyNativeWire(record,own.bundle,own.checkpoint,other.bundle,other.checkpoint);
    return enqueueNativeRecord(record);
   }
   if(op==='pull')return {item:pullNativeRecord(who,device)};
   if(op==='ack')return acknowledgeNativeRecord(who,device,body.id,body.digest);
   if(op==='recover'){
    const item=recoverNativeRecord(who,device,body.id,body.digest);
    check(item.digest===nativeRecordDigest(item.record));return {item};
   }
   throw Error('unknown operation');
  }catch(e){if(e instanceof RelayError)throw e;throw new RelayError('Message ou autorisation native refusé.',409);}
 });
}
