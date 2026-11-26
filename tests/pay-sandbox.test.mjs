import test from 'node:test';
import assert from 'node:assert/strict';
import {createPaySandbox,parseDemoAmount,formatDemoAmount} from '../lib/quantic/pay-sandbox.mjs';
test('integer cents and explicit confirmation; duplicate confirmation cannot debit twice',()=>{
 const p=createPaySandbox(),i=p.prepare({payeeId:'demo-shop',amount:'12,50'});
 assert.equal(p.snapshot().balanceCents,10000);
 assert.throws(()=>p.confirm('unknown'));
 assert.throws(()=>p.prepare({payeeId:'demo-person',amount:'1'}));
 const receipt=p.confirm(i.id);
 assert.equal(receipt.realPayment,false);assert.equal(receipt.status,'simulated');
 assert.equal(p.snapshot().balanceCents,8750);assert.equal(p.confirm(i.id),receipt);
 assert.equal(p.snapshot().balanceCents,8750);assert.throws(()=>p.cancel(i.id));
});
test('refuse non-demo payee, invalid amount, overdraft, cancel and expire without debit',()=>{
 let t=1000;const p=createPaySandbox({clock:()=>t});
 for(const amount of ['0','-1','1.001','1e2','Infinity','100.01','0001'])assert.throws(()=>parseDemoAmount(amount));
 assert.equal(parseDemoAmount('0,01'),1);assert.equal(formatDemoAmount(1),'0,01 EUR fictifs');
 assert.throws(()=>p.prepare({payeeId:'real-bank',amount:'1'}));
 const i=p.prepare({payeeId:'demo-shop',amount:'100'});
 assert.equal(p.cancel(i.id).status,'cancelled');assert.equal(p.snapshot().balanceCents,10000);
 const j=p.prepare({payeeId:'demo-person',amount:'100'});t+=120000;assert.throws(()=>p.confirm(j.id));assert.equal(p.snapshot().balanceCents,10000);
 const k=p.prepare({payeeId:'demo-person',amount:'99.99'});p.confirm(k.id);
 assert.equal(p.snapshot().balanceCents,1);assert.throws(()=>p.prepare({payeeId:'demo-person',amount:'0.02'}));assert.equal(p.snapshot().redeemable,false);
});
