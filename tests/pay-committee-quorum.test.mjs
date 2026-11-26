import test from 'node:test';
import assert from 'node:assert/strict';
import {collectCommitteeVotes} from '../lib/quantic/pay-committee-quorum.mjs';
test('collector rejects absent, duplicate and wrong-identity votes without retry',async()=>{
 const peers=Array.from({length:16},(_,i)=>({authorityPin:i.toString(16).padStart(64,'0'),client:i}));
 const lab={committee:{size:16,quorum:11},scope:'a'.repeat(64),inspectOutput:(_p,_i,v,pin)=>{assert.equal(v.pin,pin);},prepared:c=>assert.equal(c.votes.length,11)};
 let calls=0;
 const opts={lab,authorities:peers,phase:'prepare',round:0,value:'b'.repeat(64),invoke:async i=>{calls++;if(i>=11)throw Error('offline');return {pin:peers[i].authorityPin};}};
 const c=await collectCommitteeVotes(opts);assert.equal(c.votes.length,11);assert.equal(calls,16);
 calls=0;await assert.rejects(collectCommitteeVotes({...opts,invoke:async i=>{calls++;if(i>=10)throw Error('offline');return {pin:peers[i].authorityPin};}}));assert.equal(calls,16);
 await assert.rejects(collectCommitteeVotes({...opts,authorities:[...peers.slice(0,10),peers[0]]}));
 await assert.rejects(collectCommitteeVotes({...opts,invoke:async()=>({pin:peers[0].authorityPin})}));
});
