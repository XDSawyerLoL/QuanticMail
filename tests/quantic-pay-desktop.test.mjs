import test from 'node:test';
import assert from 'node:assert/strict';
import {simulateDesktopPay} from '../scripts/quantic-pay-desktop.mjs';
const req={amount:'12,50',payee:'demo-bob',consent:true,witnesses:3};
test('desktop payment simulation invokes signed local quorum, never authorizes money',()=>{
 const r=simulateDesktopPay(req);
 assert.equal(r.status,'confirmed');
 assert.equal(r.realPaymentAuthorized,false);
 assert.equal(r.witnesses,3);
 assert.equal(r.cents,1250);
 assert.equal(r.balanceCents,8750);
 assert.match(r.reference,/^LAB-[a-f0-9]{30}$/);
});
test('desktop simulation refuses insufficient simulated witnesses without spending',()=>{
 const r=simulateDesktopPay({...req,witnesses:2});
 assert.equal(r.status,'refused');
 assert.equal(r.balanceCents,10000);
 assert.equal(r.realPaymentAuthorized,false);
});
test('desktop simulation rejects missing consent, real recipients and invalid amounts',()=>{
 for(const invalid of [{consent:false},{payee:'IBAN'},{amount:'100.01'},{amount:'0'},{witnesses:5},{extra:true}]){
  assert.throws(()=>simulateDesktopPay({...req,...invalid}));
 }
});
