// Separate pinned Scattering epoch for renewal, with no HTTP listener.
// The native vault adapter owns all private keys, policy and durable quorum.
// Only signed public renewal protocol messages cross this boundary.
import {startPrivateCarrierHost} from '../standalone-relay/native-scattering-host.mjs';
import {startScatteringMailboxEndpoint} from '../standalone-relay/native-scattering-mailbox.mjs';
const check=x=>{if(!x)throw Error('Native renewal carrier refused');};
const MAX=8192;
export async function startDirectRenewalCarrier(plan,{windowsBootstrap,issueNative,startHost=startPrivateCarrierHost}={}){
 const issuer=plan?.carrier?.role==='relay';
 check(issuer?typeof issueNative==='function':plan?.carrier?.role==='client'&&issueNative===undefined);
 const host=await startHost(plan,{windowsBootstrap,startEndpoint:(c,opts)=>startScatteringMailboxEndpoint(c,{...opts,profile:'direct-renewal',
  directRenew:issuer?async raw=>{
   check(Buffer.isBuffer(raw)&&raw.length>0&&raw.length<=MAX);
   const proof=await issueNative(raw);
   check(Buffer.isBuffer(proof)&&proof.length>0&&proof.length<=MAX);
   return {status:200,body:proof};
  }:undefined})});
 try{
  check(host.httpPort===undefined&&(issuer||typeof host.requestRenewal==='function'));
  let failed=false,busy=false;
  return Object.freeze({role:issuer?'issuer':'requester',closed:host.closed,close:host.close,authenticatedPeerSeen:host.authenticatedPeerSeen,
   ...(!issuer?{async exchange(raw){
    check(!failed&&!busy&&Buffer.isBuffer(raw)&&raw.length>0&&raw.length<=MAX&&host.authenticatedPeerSeen());
    busy=true;
    try{
     const response=await host.requestRenewal(raw);
     check(response?.status===200&&Buffer.isBuffer(response.body)&&response.body.length>0&&response.body.length<=MAX);
     return response.body;
    }catch(e){
     // A missing or rejected proof may follow a committed issuer operation.
     // Retire this lane; never issue another request on an uncertain epoch.
     failed=true;
     try{await host.close();}catch{}
     throw Error('Native renewal result not confirmed');
    }finally{busy=false;}
   }}:{})});
 }catch(e){await host.close();throw e;}
}
