import test from 'node:test';
import assert from 'node:assert/strict';
import {createRoundDownload,ROUND_TRANSFER_CHUNK} from '../lib/quantic/pay-round-transfer.mjs';
import {synchronizePayReplica} from '../lib/quantic/pay-replica-sync.mjs';
test('bounded record download enforces ordering and expiry',()=>{
 let now=0;
 const record={admission:{sample:'x'.repeat(40000)},certificate:{}};
 const d=createRoundDownload({clock:()=>now,readRecord:h=>{assert.equal(h,1);return record;}});
 let m=d.begin({height:1});assert.throws(()=>d.begin({height:1}));assert.throws(()=>d.chunk({id:m.id,offset:1}));
 const bytes=[];
 for(let offset=0;offset<m.size;offset+=ROUND_TRANSFER_CHUNK)bytes.push(Buffer.from(d.chunk({id:m.id,offset}).data,'base64url'));
 assert.deepEqual(JSON.parse(Buffer.concat(bytes)),record);assert.throws(()=>d.chunk({id:m.id,offset:0}));
 m=d.begin({height:1});now+=120000;assert.throws(()=>d.chunk({id:m.id,offset:0}));
});
test('sync refuses duplicated pins and stops on ambiguous mutation without contacting another source',async()=>{
 const network='a'.repeat(64),targetPin='b'.repeat(64),other='c'.repeat(64),next='d'.repeat(64),root='e'.repeat(64);
 const state=(authorityPin,sequence)=>({network,authorityPin,sequence,root,simulationOnly:true});
 let learned=0,second=0;
 const target={status:async()=>state(targetPin,0),learn:async()=>{learned++;throw Error('unknown result');}};
 const peers=[{authorityPin:other,client:{status:async()=>state(other,1),record:async()=>({})}},{authorityPin:next,client:{status:async()=>state(next,1),record:async()=>{second++;return {};}}}];
 await assert.rejects(synchronizePayReplica({network,targetPin,target,peers:[peers[0],peers[0]]}));
 const r=await synchronizePayReplica({network,targetPin,target,peers});
 assert.equal(r.state,'reconcile-required');assert.equal(learned,1);assert.equal(second,0);
});
