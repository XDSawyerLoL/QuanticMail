// Windows GUI-only receiver adapter for synthetic, previously configured PQ vaults.
// Receipt persistence, authenticated readback and ACK ordering remain owned
// exclusively by the existing native Windows mail-flow engine.
import {randomUUID} from 'node:crypto';
import {win32} from 'node:path';
import {runWindowsScatteringMail,windowsScatteringScope} from './native-windows-mail-flow.mjs';

export async function receiveWindowsLabFromGUI(config,storage,{
 approve,connect,mailboxFactory,sessionController,
 receive=runWindowsScatteringMail,makeId=randomUUID
}={}){
 windowsScatteringScope(config);
 if(typeof approve!=='function'||typeof receive!=='function'||typeof makeId!=='function'){
  throw Error('Native GUI receive refused');
 }
 const id=makeId();
 if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(id)){
  throw Error('Invalid native receipt ID');
 }
 const path=win32.join(config.windowsLab.dir,'receipt-'+id.replaceAll('-','')+'.json');
 const result=await receive(config,storage,{
  operation:'receive',path,approve,connect,mailboxFactory,sessionController
 });
 if(result?.status==='empty')return Object.freeze({status:'empty',remoteDeliveryVerified:false});
 if(result?.status==='cancelled')return Object.freeze({status:'cancelled',remoteDeliveryVerified:false});
 if(result?.status!=='acknowledged'||typeof result.display!=='string'
  ||result.display.length===0||result.display.length>10000){
  throw Error('Unverified native receipt');
 }
 return Object.freeze({status:'opened-and-acknowledged-on-local-relay',
  display:result.display,remoteDeliveryVerified:false});
}
