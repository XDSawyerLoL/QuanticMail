import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {win32} from 'node:path';
import {sealReceipt} from '../desktop/native-receipt-store.mjs';
import {randomBytes} from 'node:crypto';
import {approveWindowsGUIPrompt,composeSendWindowsGUI,receiveWindowsGUI,listWindowsGUIReceipts,readWindowsGUIReceipt} from '../desktop/native-windows-gui-send.mjs';

const dir='C:\\Quantic\\private',binary='C:\\Quantic\\bin\\Vault-PQ-lab.exe';
const boot={binary,binarySha256:'a'.repeat(64),dir};
const config={...boot,labOnly:true,pqMode:{enabled:true},windowsLab:{enabled:true,dir}};
const file='draft-a1478dbe30034bb58fda0123456789ab.json';
const fields={to:'alice~'+'a'.repeat(32)+'@quantic',subject:'Test',body:'Bonjour labo'};
function fixture(){
 let saved=0,composed=0;
 const storage={verifyBinary:async()=>true,env:{SystemRoot:'C:\\Windows'},
  read:async path=>{
   assert.equal(path,win32.join(dir,'desktop.json'));
   return Buffer.from(JSON.stringify(config),'utf8');
  }};
 const deps={makeStorage:async()=>storage,
  saveDraft:async (b,f,options)=>{
   saved++;assert.deepEqual(b,boot);assert.deepEqual(f,fields);
   assert.equal(await options.makeStorage(),storage);
   return{status:'draft-saved-not-sent',file};
  },
  compose:async(cfg,s,args)=>{
   composed++;assert.equal(cfg.labOnly,true);assert.equal(s,storage);
   assert.equal(args.input,win32.join(dir,file));
   assert.equal(args.output,win32.join(dir,file.replace('draft-','wire-')));
   assert.equal(args.recover,false);
   assert.equal(await args.approve('Confirmation'),true);
   return{status:'deposited',digest:'b'.repeat(64)};
  },
  approve:async()=>true,connect:async()=>{throw Error('No real native controller in test');}};
 return {deps,stats:()=>({saved,composed})};
}
test('GUI compose keeps encrypted draft then passes exact wire to explicit native operation',async()=>{
 const f=fixture();
 const out=await composeSendWindowsGUI(boot,fields,f.deps);
 assert.deepEqual(f.stats(),{saved:1,composed:1});
 assert.equal(out.status,'deposited');
 assert.equal(out.encryptedDraft,file);
 assert.equal(out.noAutomaticRetry,true);
 assert.equal(out.remoteDeliveryVerified,false);
 assert.equal(out.liveAccountEnrollmentAuthorized,false);
});
test('Unknown local signing outcome never calls compose twice',async()=>{
 const f=fixture();
 f.deps.compose=async()=>{throw Error('Ambiguous native relay result');};
 await assert.rejects(composeSendWindowsGUI(boot,fields,f.deps),/Ambiguous/);
 assert.deepEqual(f.stats(),{saved:1,composed:0});
});
test('Unexpected operation status is never reported as delivered',async()=>{
 const f=fixture();
 f.deps.compose=async()=>({status:'sent-to-world'});
 await assert.rejects(composeSendWindowsGUI(boot,fields,f.deps));
});
test('Native GUI confirmation accepts only exact output and rejects oversized prompts',async()=>{
 const seen=[];
 const spawnProcess=(path,args,opts)=>{
  seen.push({path,args,opts});
  const child=new EventEmitter();
  child.stdout=new EventEmitter();
  child.stdin={on(){},end(bytes){
   seen.push(bytes.toString('utf8'));
   queueMicrotask(()=>{child.stdout.emit('data',Buffer.from('APPROVED\n'));child.emit('close',0)});
  }};
  child.kill=()=>{};
  return child;
 };
 const storage={env:{SystemRoot:'C:\\Windows'},verifyBinary:async()=>true};
 assert.equal(await approveWindowsGUIPrompt(boot,storage,'Confirmer ?\nTest',{spawnProcess}),true);
 assert.equal(seen[0].path,binary);
 assert.deepEqual(seen[0].args,['--windows-gui-approve-lab']);
 assert.equal(seen[1],'Confirmer ? | Test');
 assert.equal(seen[0].opts.windowsHide,true);
 await assert.rejects(approveWindowsGUIPrompt(boot,storage,'x'.repeat(1025),{spawnProcess}));
 assert.equal(seen.length,2,'No native process for invalid detail');
});

function receiveFixture(){
 const address='bobby~'+'b'.repeat(32)+'@quantic',deviceId='d-'+'b'.repeat(32);
 const scope={enabled:true,address,deviceId,endpoint:'http://127.0.0.1:49111/',receiptKeyFile:win32.join(dir,'receipt.key')};
 const cfg={...config,pqMode:{enabled:true,address,deviceId},windowsScattering:scope};
 const key=randomBytes(32),receipt={id:'01234567-89ab-4cde-8fab-0123456789ab',digest:'b'.repeat(64)};
 const payload={subject:'Test PQ',body:'Message authentifie'};
 const file='receipt-0123456789ab4cde8fab0123456789ab.json';
 let raw,ran=0;
 const storage={read:async p=>{
  if(p===win32.join(dir,'desktop.json'))return Buffer.from(JSON.stringify(cfg));
  if(p===scope.receiptKeyFile)return Buffer.from(key);
  assert.equal(p,win32.join(dir,file));
  if(!raw)throw Error('no durable receipt');
  return Buffer.from(raw);
 }};
 const write=()=>{raw=Buffer.from(JSON.stringify(sealReceipt(key,scope,receipt,payload)));};
 const deps={makeStorage:async()=>storage,makeId:()=>receipt.id,approve:async()=>true,run:async(c,s,a)=>{
  ran++;assert.equal(c.labOnly,true);assert.equal(s,storage);assert.equal(a.path,win32.join(dir,file));
  assert.ok(await a.approve('Confirm?'));write();return{status:'acknowledged',...receipt};
 }};
 return{deps,file,payload,receipt,write,ran:()=>ran,corrupt:()=>{raw=Buffer.from('{}');}};
}
test('GUI receive independently authenticates the saved receipt and reports relay ACK',async()=>{
 const f=receiveFixture();const r=await receiveWindowsGUI(boot,'receive',undefined,f.deps);
 assert.equal(r.status,'acknowledged');assert.equal(r.receiptFile,f.file);
 assert.ok(r.display.includes(f.payload.body));assert.equal(f.ran(),1);
 assert.equal(r.noAutomaticRetry,true);assert.equal(r.liveAccountEnrollmentAuthorized,false);
});
test('GUI ACK failure preserves and authenticates receipt without retry; explicit confirm uses exact file',async()=>{
 const f=receiveFixture();let calls=0;
 f.deps.run=async()=>{calls++;f.write();throw Error('ACK timeout');};
 const r=await receiveWindowsGUI(boot,'receive',undefined,f.deps);
 assert.equal(r.status,'receipt-saved-ack-unknown');assert.equal(r.receiptFile,f.file);assert.equal(calls,1);
 f.deps.run=async(c,s,a)=>{assert.equal(a.operation,'confirm-receipt');assert.equal(a.path,win32.join(dir,f.file));calls++;return{status:'acknowledged',...f.receipt};};
 assert.equal((await receiveWindowsGUI(boot,'confirm-receipt',f.file,f.deps)).status,'acknowledged');
 assert.equal(calls,2);
});
test('GUI refuses a corrupt receipt, missing receipt, unexpected status and path escape',async()=>{
 const f=receiveFixture();f.deps.run=async()=>{throw Error('not saved');};
 await assert.rejects(receiveWindowsGUI(boot,'receive',undefined,f.deps),/not saved/);
 f.deps.run=async()=>{f.write();f.corrupt();throw Error('corrupt');};
 await assert.rejects(receiveWindowsGUI(boot,'receive',undefined,f.deps),/corrupt/);
 f.deps.run=async()=>({status:'delivered-to-world'});
 await assert.rejects(receiveWindowsGUI(boot,'receive',undefined,f.deps));
 await assert.rejects(receiveWindowsGUI(boot,'confirm-receipt','..\\receipt-test.json',f.deps));
});


test('local receipt inbox authenticates every candidate and reads only explicitly selected message',async()=>{
 const f=receiveFixture();f.write();
 const good=f.file,bad='receipt-invalid.json';
 const read=f.deps.makeStorage;
 const deps={enumerate:async d=>{assert.equal(d,dir);return ['desktop.json','receipt.key',good,bad,'..\\receipt-traversal.json'];},
  makeStorage:async()=>{
   const s=await read();
   return {...s,read:async p=>p===win32.join(dir,bad)?Buffer.from('{}'):s.read(p)};
  }};
 const out=await listWindowsGUIReceipts(boot,deps);
 assert.equal(out.status,'authenticated-local-receipts');
 assert.deepEqual(out.items,[{file:good,subject:'Test PQ'}]);
 assert.equal(out.refused,1);assert.equal(out.remaining,0);assert.equal(out.deliveryVerified,false);
 assert.ok(!JSON.stringify(out).includes(f.payload.body));
 const item=await readWindowsGUIReceipt(boot,good,deps);
 assert.equal(item.status,'authenticated-local-receipt');assert.ok(item.display.includes(f.payload.body));
 assert.equal(item.deliveryVerified,false);
 await assert.rejects(readWindowsGUIReceipt(boot,bad,deps));
 await assert.rejects(readWindowsGUIReceipt(boot,'..\\receipt-test.json',deps));
 assert.equal(f.ran(),0,'local browsing must not run a network operation');
});
