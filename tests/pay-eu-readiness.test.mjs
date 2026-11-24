import test from 'node:test';
import assert from 'node:assert/strict';
import {payEuropeanReadiness} from '../lib/quantic/pay-eu-readiness.mjs';
import {createDigitalEuroLabAdapter} from '../lib/quantic/pay-iso20022-preview.mjs';
test('European readiness baseline distinguishes partial lab controls and external requirements; cannot report live authorization',()=>{
 const r=payEuropeanReadiness(),a=createDigitalEuroLabAdapter();
 assert.equal(r.requirements.length,13);
 assert.equal(new Set(r.requirements.map(x=>x.id)).size,13);
 assert.ok(r.requirements.every(x=>['partial-lab','not-implemented','external-required'].includes(x.status)));
 assert.equal(r.normativeStatus,'draft-scheme-legislation-pending');
 assert.equal(r.productionReady,false);assert.equal(r.certified,false);assert.equal(r.realPaymentAuthorized,false);assert.equal(r.despConnected,false);
 assert.throws(()=>{r.requirements[0].status='certified'});
 assert.deepEqual(a.readiness(),r);
 assert.throws(()=>a.submit({certified:true,providerConnected:true,realPaymentAuthorized:true}));
 assert.throws(()=>a.settle({status:'confirmed',settlementVerified:true}));
});
