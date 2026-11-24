import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {runWindowsScatteringMail,windowsScatteringScope} from '../desktop/native-windows-mail-flow.mjs';
const dir='C:\\Quantic\\private',address='alice~'+'a'.repeat(32)+'@quantic',deviceId='d-'+'b'.repeat(32);
const scope={enabled:true,address,deviceId,receiptKeyFile:dir+'\\receipt.key',endpoint:'http://127.0.0.1:49003/'};
const cfg={windowsLab:{dir},pqMode:{enabled:true,address,deviceId},windowsScattering:scope};
const id='01234567-89ab-4cde-8fab-0123456789ab',digest='a'.repeat(64),path=dir+'\\receipt-one.json',payload={subject:'Synthetic',body:'Private'};
test('remote endpoint and mismatched account refused',()=>{
 for(const bad of [{endpoint:'https://example.com/'},{deviceId:'d-'+'c'.repeat(32)},{receiptKeyFile:'C:\\elsewhere\\receipt.key'}])assert.throws(()=>windowsScatteringScope({...cfg,windowsScattering:{...scope,...bad}}));
});
test('receive persists encrypted receipt before acknowledgement; explicit recovery and confirm',async()=>{
 const key=randomBytes(32);let saved,acked=0,opened=0,closed=0;
 const storage={read:async p=>p===scope.receiptKeyFile?Buffer.from(key):Buffer.from(saved),writeReceipt:async(p,b)=>{assert.equal(p,path);saved=Buffer.from(b);}};
 const item={id,digest,record:{}};
 const client={pull:async()=>item,recover:async()=>item,ack:async()=>{assert.ok(saved);assert.ok(!saved.includes(Buffer.from(payload.body)));acked++;}};
 const deps={approve:async()=>true,mailboxFactory:async()=>client,connect:async()=>({openHybrid:async(r,o)=>{assert.ok(o.recover);opened++;return payload;},close(){closed++;}})};
 const res=await runWindowsScatteringMail(cfg,storage,{...deps,operation:'recover-receive',path});
 assert.equal(res.status,'acknowledged');assert.equal(opened,1);assert.equal(acked,1);assert.equal(closed,1);
 assert.equal((await runWindowsScatteringMail(cfg,storage,{...deps,operation:'confirm-receipt',path})).status,'acknowledged');assert.equal(acked,2);
 storage.writeReceipt=async()=>{throw Error('disk');};
 await assert.rejects(runWindowsScatteringMail(cfg,storage,{...deps,operation:'recover-receive',path}));assert.equal(acked,2);
 saved=Buffer.from('{}');
 await assert.rejects(runWindowsScatteringMail(cfg,storage,{...deps,operation:'confirm-receipt',path}));assert.equal(acked,2);
});

test('sealed receive uses one native broker for pull, authenticated opening and ACK; refuses plain token fallback',async()=>{
 const {token,...plainScope}=scope;
 const sealed={...cfg,windowsScattering:{...plainScope,credentialMode:'vault-sealed-v1'}};
 assert.throws(()=>windowsScatteringScope({...sealed,windowsScattering:{...sealed.windowsScattering,token:'x'.repeat(43)}}));
 const key=randomBytes(32);let saved,opened=0,closed=0,connected=0,acked=0;
 const storage={read:async p=>p===scope.receiptKeyFile?Buffer.from(key):Buffer.from(saved),writeReceipt:async(p,b)=>{assert.equal(p,path);saved=Buffer.from(b);}};
 const item={id,digest,record:{}};
 const mailbox={pull:async()=>item,ack:async()=>{assert.ok(saved);assert.equal(closed,0);acked++;}};
 const connect=async config=>{connected++;assert.equal(config.guiWindowsApproval,true);assert.equal(config.windowsScattering.token,undefined);
  return {mailbox,openHybrid:async()=>{opened++;return payload;},close(){closed++;}};
 };
 const res=await runWindowsScatteringMail(sealed,storage,{operation:'receive',path,approve:async()=>true,connect,mailboxFactory:()=>{throw Error('plaintext fallback');}});
 assert.equal(res.status,'acknowledged');assert.deepEqual({connected,opened,acked,closed},{connected:1,opened:1,acked:1,closed:1});
 await assert.rejects(runWindowsScatteringMail(sealed,storage,{operation:'receive',path,approve:async()=>true,connect:async()=>({close(){closed++;}}),mailboxFactory:()=>{throw Error('plaintext fallback');}}));
 assert.equal(closed,2);
});
