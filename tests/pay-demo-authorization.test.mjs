import test from 'node:test';
import assert from 'node:assert/strict';
import {createPaySandbox} from '../lib/quantic/pay-sandbox.mjs';
import {createDemoPayAuthorization} from '../lib/quantic/pay-demo-authorization.mjs';
test('real test signatures bind amount, payee, session, freshness and single consumption',()=>{
 let t=1000;const clock=()=>t;
 const engine=createPaySandbox({clock}),auth=createDemoPayAuthorization({clock});
 const i=engine.prepare({payeeId:'demo-shop',amount:'2.35'});
 assert.throws(()=>auth.authorize(i,false));
 const proof=auth.authorize(i,true);
 assert.equal(auth.verifyProof(i,proof),true);
 assert.equal(Buffer.from(proof.p256,'base64url').length,64);
 assert.equal(Buffer.from(proof.mlDsa65,'base64url').length,3309);
 for(const change of [{cents:236},{payeeId:'demo-person'},{currency:'USD'},{realPayment:true},{id:'DEMO-000002'},{expiresAt:i.expiresAt+1}])assert.equal(auth.verifyProof({...i,...change},proof),false);
 for(const f of ['p256','mlDsa65']){const b=Buffer.from(proof[f],'base64url');b[0]^=1;assert.equal(auth.verifyProof(i,{...proof,[f]:b.toString('base64url')}),false);}
 const other=createDemoPayAuthorization({clock});assert.equal(other.verifyProof(i,proof),false);
 assert.equal(auth.consume(i,proof).realPaymentAuthorized,false);
 assert.throws(()=>auth.consume(i,proof));assert.throws(()=>auth.authorize(i,true));
 assert.equal(engine.confirm(i.id).status,'simulated');
 assert.equal(engine.snapshot().balanceCents,9765);
 t=i.expiresAt;assert.equal(auth.verifyProof(i,proof),false);
});
