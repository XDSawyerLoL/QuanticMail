import test from 'node:test';
import assert from 'node:assert/strict';
import {win32} from 'node:path';
import {validateHybridMailProfile,openWindowsNegotiatedMailSession} from '../desktop/native-windows-negotiated-session.mjs';
const dir='C:\\Quantic\\private',address='alice~'+'a'.repeat(32)+'@quantic',deviceId='d-'+'b'.repeat(32),peerAddress='bob~'+'c'.repeat(32)+'@quantic',peerDeviceId='d-'+'d'.repeat(32);
const profile={version:1,channel:'a'.repeat(96),peerAddress,peerDeviceId,bootstrapListen:'127.0.0.1:48001',bootstrapTarget:'127.0.0.1:48002',listen:'127.0.0.1:48003',target:'127.0.0.1:48004',epochs:4};
const config={labOnly:true,windowsLab:{dir},pqMode:{enabled:true,address,deviceId},windowsScattering:{enabled:true,address,deviceId,credentialMode:'vault-sealed-v1',receiptKeyFile:win32.join(dir,'receipt.vault'),endpoint:'http://127.0.0.1:48005/'},managedHybridScattering:profile};
const contacts=[{address:peerAddress,deviceId:peerDeviceId,expires:Date.now()+60000}];
test('secret-free hybrid profile rejects downgrade, wrong peer and endpoint collision',()=>{
 assert.equal(validateHybridMailProfile(config,contacts).httpPort,48005);
 for(const patch of [{secretHex:'a'.repeat(64)},{peerDeviceId:deviceId},{epochs:5},{target:profile.listen},{listen:'127.0.0.1:48005'}]){
  assert.throws(()=>validateHybridMailProfile({...config,managedHybridScattering:{...profile,...patch}},contacts));
 }
 assert.throws(()=>validateHybridMailProfile({...config,managedScattering:{}},contacts));
 assert.throws(()=>validateHybridMailProfile(config,[{...contacts[0],expires:0}]));
});
test('one controller shared by rotation, compose and mail; no operation before readiness',async()=>{
 let connections=0,closures=0,provisioned=[],calls=0,notify,complete;
 const lifecycle=new AbortController();
 const controller={lifecycleSignal:lifecycle.signal,close(){if(!lifecycle.signal.aborted){closures++;lifecycle.abort();}}};
 const storage={dir,binary:'C:\\Quantic\\Vault.exe',binarySha256:'a'.repeat(64),env:{},read:async()=>Buffer.from(JSON.stringify(contacts)),verifyBinary:async()=>{},createScatteringEpoch:async n=>{provisioned.push(n);return win32.join(dir,n);}};
 const socket={close(){}};
 const session=await openWindowsNegotiatedMailSession(config,storage,{pacer:'C:\\Quantic\\Pacer.exe',binaryPin:'b'.repeat(64)},{
  connect:async()=>{connections++;return controller;},bootstrap:async()=>socket,
  rotate:options=>{assert.equal(options.controller,controller);assert.equal(options.epochs.length,4);assert.ok(options.epochs.every(e=>e.socket===socket&&!Object.hasOwn(e.config,'secretHex')));notify=options.onState;const closed=new Promise(r=>{complete=r;});return {closed,close:async()=>complete({status:'stopped'})};},
  compose:async(c,s,o)=>{calls++;assert.equal(o.sessionController,controller);return 'composed';},
  mail:async(c,s,o)=>{calls++;assert.equal(o.sessionController,controller);return 'received';}
 });
 assert.equal(new Set(provisioned).size,4);assert.equal(connections,1);
 await assert.rejects(session.compose({}));notify({status:'ready',generation:0,httpPort:48005});
 assert.equal(await session.compose({}),'composed');assert.equal(await session.mail({}),'received');assert.equal(closures,0);
 notify({status:'negotiating',generation:1});await assert.rejects(session.mail({}));
 await session.close();assert.equal(closures,1);assert.equal(calls,2);assert.equal(session.status(),'closed');
});
