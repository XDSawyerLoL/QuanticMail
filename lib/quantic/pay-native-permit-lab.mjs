// Native wallet pre-signing authorization, fixed roster laboratory only.
// Each validator independently verifies its own retained certified checkpoint.
// A separate durable round per wallet and shard height prevents conflicting
// authorizations under the non-rollback assumption. This is NOT a reservation
// in the financial ledger, and cannot guarantee funds remain available later.
import {createHash} from 'node:crypto';
import {openShardedPayLab} from './pay-sharded-lab.mjs';
import {createPayRoundLab} from './pay-round-lab.mjs';
import {openPersistentPayRound} from './pay-round-store.mjs';
const check=v=>{if(!v)throw Error('Native Pay permit refused');};
const hash=v=>createHash('sha256').update(JSON.stringify(v)).digest('hex');
const pin=s=>createHash('sha256').update(Buffer.from(s,'base64url')).digest('hex');
const hex=s=>typeof s==='string'&&/^[a-f0-9]{64}$/.test(s);
const exact=(v,k)=>v&&typeof v==='object'&&Object.keys(v).length===k.length&&k.every(x=>Object.hasOwn(v,x));
const safe=Number.isSafeInteger;
export function openNativePayPermitLab({config,checkpoint,anchor,payer}){
 const cfg=structuredClone(config),lab=openShardedPayLab(cfg),state=lab.verifyCheckpoint(checkpoint,anchor);
 const wallet=cfg.wallets.find(w=>w.id===payer),shard=cfg.shards.find(s=>s.id===state.shard);
 check(wallet&&wallet.shard===state.shard&&state.height<256&&shard);
 const authorities=shard.authorities.slice().sort((a,b)=>a.pin<b.pin?-1:1);
 const policy=hash(['quantic-native-pay-policy/lab/v1',state.shard,payer,authorities.map(a=>[a.pin,a.pqPin])]);
 const signingPin=pin(wallet.publicKey),pqPin=pin(wallet.pqPublicKey),available=state.balances[payer],spent=new Set(checkpoint.spent);
 const rc={network:hash(['quantic-native-permit-round/lab/v1',state.network,state.shard,payer]),height:state.height+1,previousRoot:state.root,authorities,admissionRound:true,committeeMode:true};
 const round=createPayRoundLab(rc);
 function candidate(intent,now){
  check(exact(intent,['Payee','Cents','Nonce','Issued','Expires'])&&['demo-shop','demo-person'].includes(intent.Payee)&&intent.Payee!==payer&&cfg.wallets.some(w=>w.id===intent.Payee)&&safe(intent.Cents)&&intent.Cents>=1&&intent.Cents<=10000&&intent.Cents<=available&&hex(intent.Nonce)&&safe(intent.Issued)&&intent.Issued>=0&&safe(intent.Expires)&&intent.Expires-intent.Issued===120000&&safe(now)&&now>=intent.Issued&&now<intent.Expires);
  check(!spent.has(hash(['quantic-shard-nonce/v1',state.network,payer,intent.Nonce])));
  const digest=hash(['quantic-pay-native-simulation/v1',signingPin,pqPin,intent.Payee,intent.Cents,'EUR',intent.Nonce,intent.Issued,intent.Expires,false]);
  const value=hash(['quantic-native-pay-permit/lab/v1',policy,state.network,state.shard,payer,state.height,state.root,available,digest,true]);
  return {value,digest};
 }
 return Object.freeze({policy,scope:round.scope,
  openAuthority({directory,createNew=false,credentials,clock=Date.now}){
   const store=openPersistentPayRound({directory,createNew,config:rc,...credentials});
   return Object.freeze({
    prepare(intent){return store.prepare({round:0,value:candidate(intent,clock()).value,viewCertificate:null});},
    commit(intent,qc){check(qc.round===0&&qc.value===candidate(intent,clock()).value);return store.commit(qc);},close:store.close
   });
  },
  candidate,
  permit(intent,certificate,now=Date.now()){
   const {value,digest}=candidate(intent,now),f=round.finalized(certificate);check(f.round===0&&f.value===value);
   return {policy,network:state.network,shard:state.shard,payer,height:state.height,root:state.root,available,intentDigest:digest,authorities:structuredClone(authorities),certificate:structuredClone(certificate),simulationOnly:true,realPaymentAuthorized:false};
  }
 });
}
