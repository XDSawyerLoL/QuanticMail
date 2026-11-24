import test from 'node:test';
import assert from 'node:assert/strict';
import {createRoundUpload,encodeRoundPrepare,ROUND_TRANSFER_CHUNK} from '../lib/quantic/pay-round-transfer.mjs';
test('bounded uploads require exact offsets, digest and full view-change payload; expire without authorizing anything',()=>{
 let now=1000;
 const upload=createRoundUpload({clock:()=>now}),payload={round:2,value:'a'.repeat(64),viewCertificate:{round:2,reports:['x'.repeat(50000)]}};
 const {raw,size,digest}=encodeRoundPrepare(payload);
 const begin=()=>upload.begin({size,digest});
 const fill=id=>{for(let offset=0;offset<size;offset+=ROUND_TRANSFER_CHUNK)upload.chunk({id,offset,data:raw.subarray(offset,offset+ROUND_TRANSFER_CHUNK).toString('base64url')});};
 let {id}=begin();
 assert.throws(begin);assert.throws(()=>upload.chunk({id,offset:1,data:'YQ'}));
 assert.throws(()=>upload.finish({id}));assert.throws(()=>upload.finish({id}));
 ({id}=upload.begin({size,digest:'0'.repeat(64)}));fill(id);assert.throws(()=>upload.finish({id}));
 ({id}=begin());fill(id);assert.deepEqual(upload.finish({id}),payload);assert.throws(()=>upload.finish({id}));
 ({id}=begin());now+=120000;assert.throws(()=>upload.chunk({id,offset:0,data:raw.subarray(0,ROUND_TRANSFER_CHUNK).toString('base64url')}));
 assert.throws(()=>upload.begin({size:1000000,digest}));({id}=begin());upload.clear();assert.throws(()=>upload.finish({id}));
 raw.fill(0);
});
