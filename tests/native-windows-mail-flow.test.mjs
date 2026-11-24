import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {sealReceipt} from '../desktop/native-receipt-store.mjs';
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


test('long authenticated receipt uses bounded native approval and never reopens cryptography',async()=>{
 const key=randomBytes(32),long={subject:'Long message',body:'é'.repeat(3000)};
 const encoded=Buffer.from(JSON.stringify(sealReceipt(key,scope,{id,digest},long)));
 let recovered=0,acked=0,prompts=0;
 const storage={read:async p=>p===scope.receiptKeyFile?Buffer.from(key):Buffer.from(encoded)};
 const client={recover:async(a,b)=>{assert.equal(a,id);assert.equal(b,digest);recovered++;return{id,digest};},ack:async()=>{acked++;}};
 const deps={operation:'confirm-receipt',path,mailboxFactory:async()=>client,connect:async()=>{throw Error('No second decryption');},approve:async p=>{
  prompts++;assert.ok(Buffer.byteLength(p.replaceAll('\n',' | '))<=1024);assert.ok(p.includes(id)&&p.includes(digest));assert.ok(!p.includes(long.body));return true;
 }};
 assert.equal((await runWindowsScatteringMail(cfg,storage,deps)).status,'acknowledged');
 assert.equal(recovered,1);assert.equal(acked,1);assert.equal(prompts,1);
 assert.equal((await runWindowsScatteringMail(cfg,storage,{...deps,approve:async()=>false})).status,'cancelled');
 assert.equal(recovered,1);assert.equal(acked,1);
});
