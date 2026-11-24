// Native mailbox bootstrap for an endpoint which already has trusted
// local identity keys and a connected UDP socket. No keys on disk or IPC.
// Experimental: caller supplies pinned peer/context and owns bootstrap socket.
import {createHash} from 'node:crypto';
import {negotiateUdpSessionLab} from '../lib/quantic/scattering-session-udp-endpoint-lab.mjs';
import {startScatteringMailboxEndpoint} from './native-scattering-mailbox.mjs';
const check=x=>{if(!x)throw Error('Negotiated mailbox endpoint refused');};
export async function startNegotiatedScatteringMailboxEndpoint({config,socket,local,privateKeys,signHandshake,peer,context,windowsBootstrap,timeoutMs=8000}){
 check(config&&typeof config==='object'&&!Array.isArray(config)&&config.labOnly===true);
 // Do not silently accept the historical pre-shared-key format.
 const keys=['labOnly','role','queueDir','stateDir','recvPort','httpPort'];
 check(Object.keys(config).length===keys.length&&keys.every(k=>Object.hasOwn(config,k)));
 check(['client','relay'].includes(config.role)&&typeof config.queueDir==='string'&&typeof config.stateDir==='string'
  &&Number.isInteger(config.recvPort)&&config.recvPort>=0&&config.recvPort<=65535
  &&Number.isInteger(config.httpPort)&&config.httpPort>=(config.role==='client'?0:1)&&config.httpPort<=65535);
 if(process.platform==='win32')check(windowsBootstrap);
 let material,endpoint,ephemeral;
 try{
  material=await negotiateUdpSessionLab({socket,role:config.role==='client'?'initiator':'responder',
   local,privateKeys,signHandshake,peer,context,timeoutMs});
  // The existing transport reserves the negotiated epoch in the local
  // durable guard before opening its data listener. No bypass or fallback.
  ephemeral={...config,secretHex:material.secret.toString('hex'),epochHex:material.epoch.toString('hex')};
  endpoint=await startScatteringMailboxEndpoint(ephemeral,{windowsBootstrap,profile:'mailbox'});
  const epochId=createHash('sha256').update(material.epoch).digest('hex');
  return Object.freeze({...endpoint,epochId,transcript:material.transcript,negotiated:true});
 }catch(e){endpoint?.close();throw e;}
 finally{
  if(ephemeral){delete ephemeral.secretHex;delete ephemeral.epochHex;}
  material?.secret.fill(0);material?.epoch.fill(0);
 }
}
