import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {listWindowsMailAttempts} from '../desktop/native-windows-mail-status.mjs';

const boot={binary:'C:\\Quantic\\bin\\Vault-PQ-lab.exe',binarySha256:'a'.repeat(64),dir:'C:\\Quantic\\private'};
function fixture(record,exitCode=0){
 const observations=[];
 const spawnProcess=(file,args,opts)=>{
  observations.push({file,args,opts});
  const proc=new EventEmitter();
  proc.stdout=new EventEmitter();
  proc.kill=()=>{};
  queueMicrotask(()=>{
   proc.stdout.emit('data',Buffer.from(JSON.stringify(record)+'\n'));
   proc.emit('close',exitCode);
  });
  return proc;
 };
 const makeStorage=async()=>({env:{SystemRoot:'C:\\Windows'},verifyBinary:async()=>{observations.push({verified:true});}});
 return {spawnProcess,makeStorage,observations};
}
const good={status:'local-files-only-unverified',deliveryVerified:false,
 items:[{id:'a'.repeat(32),draft:true,wire:false},{id:'b'.repeat(32),draft:true,wire:true}]};
test('Read-only mail inventory never treats local wire as a delivered message',async()=>{
 const f=fixture(good);
 const out=await listWindowsMailAttempts(boot,f);
 assert.equal(out.items.length,2);
 assert.equal(out.deliveryVerified,false);
 assert.deepEqual(f.observations[1].args,['--windows-client-mail-status-lab',boot.dir]);
 assert.equal(f.observations[1].opts.shell,false);
 assert.equal(f.observations[1].opts.windowsHide,true);
 assert.equal(out.items[1].wire,true);
});
test('Fake delivery, duplicate references, unexpected fields and malformed statuses fail closed',async()=>{
 for(const bad of [
  {...good,deliveryVerified:true},
  {...good,status:'remote-delivered'},
  {...good,items:[good.items[0],good.items[0]]},
  {...good,items:[{...good.items[0],hidden:'x'}]},
  {...good,items:[{...good.items[0],id:'../secret'}]},
  {...good,items:[{...good.items[0],draft:false,wire:false}]},
  {...good,items:new Array(65).fill(good.items[0])}
 ])await assert.rejects(listWindowsMailAttempts(boot,fixture(bad)));
});
test('Native error exit refuses to display an unverified status',async()=>{
 await assert.rejects(listWindowsMailAttempts(boot,fixture(good,1)));
});
