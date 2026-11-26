// Bounded GUI transaction policy; one command at a time, no network fallback.
import {randomUUID} from 'node:crypto';
import {win32} from 'node:path';
import {saveWindowsDraft} from './native-windows-draft.mjs';
import {makeGuiDepositApproval} from './native-windows-gui-approval.mjs';
const check=x=>{if(!x)throw Error('Hybrid GUI operation refused');};
const exact=(x,k)=>x&&typeof x==='object'&&!Array.isArray(x)&&Object.keys(x).length===k.length&&k.every(n=>Object.hasOwn(x,n));
export async function handleHybridGuiCommand({command,config,contacts,storage,session,publish,decision,save=saveWindowsDraft,makeId=randomUUID}){
 check(session.status()==='ready'&&typeof publish==='function'&&typeof decision==='function');
 const p=config.managedHybridScattering,dir=config.windowsLab.dir;
 const reply=(status,rest={})=>({phase:'result',status,...rest,remoteDeliveryVerified:false});
 const ask=async(phase,expected)=>{const waiting=decision();publish({phase});return (await waiting)===expected;};
 if(command?.op==='send'){
  check(exact(command,['op','fields'])&&exact(command.fields,['to','subject','body'])&&command.fields.to===p.peerAddress);
  const draft=await save(config,contacts,storage,command.fields);
  check(/^draft-[a-f0-9]{32}\.json$/.test(draft.file));
  publish({phase:'draft-saved'});
  let waiting;
  const r=await session.compose({input:win32.join(dir,draft.file),output:win32.join(dir,'wire-'+makeId().replaceAll('-','')+'.json'),
   approve:makeGuiDepositApproval(phase=>{waiting=decision();publish(phase);},()=>waiting)});
  if(r.status==='deposited'){check(['queued','acknowledged'].includes(r.relayStatus));return reply(r.relayStatus==='acknowledged'?'acknowledged-by-local-relay':'queued-on-local-relay');}
  if(r.status==='deposit-unconfirmed')return reply('delivery-unknown');
  return reply(r.status==='saved-not-sent'?'encrypted-saved-not-sent':'not-sent');
 }
 if(command?.op==='receive'){
  check(exact(command,['op']));
  const r=await session.mail({operation:'receive',path:win32.join(dir,'receipt-'+makeId().replaceAll('-','')+'.json'),approve:()=>ask('message-awaiting-approval','OPEN')});
  if(r.status==='empty'||r.status==='cancelled')return reply(r.status);
  check(r.status==='acknowledged'&&typeof r.display==='string'&&r.display.length>0&&r.display.length<=10000);
  return reply('opened-and-acknowledged-on-local-relay',{display:r.display});
 }
 if(command?.op==='retry'){
  check(exact(command,['op','selection'])&&exact(command.selection,['name','digest'])&&/^wire-[a-z0-9-]{1,48}\.json$/.test(command.selection.name)&&/^[a-f0-9]{64}$/.test(command.selection.digest));
  const r=await session.mail({operation:'retry-send',path:win32.join(dir,command.selection.name),expectedDigest:command.selection.digest,approve:()=>true});
  check(r.digest===command.selection.digest&&['deposited','deposit-unconfirmed','cancelled'].includes(r.status));
  return reply(r.status,{digest:r.digest});
 }
 throw Error('Unsupported command');
}
