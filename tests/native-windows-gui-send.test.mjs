import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {win32} from 'node:path';
import {approveWindowsGUIPrompt,composeSendWindowsGUI} from '../desktop/native-windows-gui-send.mjs';

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
