import test from 'node:test';
import assert from 'node:assert/strict';
import {win32} from 'node:path';
import {saveWindowsDraft} from '../desktop/native-windows-draft.mjs';

const dir='C:\\Quantic\\private';
const address='alice~'+'a'.repeat(32)+'@quantic', peer='bobby~'+'b'.repeat(32)+'@quantic';
const device='d-'+'c'.repeat(32),other='d-'+'d'.repeat(32);
const cfg={windowsLab:{dir},pqMode:{enabled:true,address,deviceId:device},
 windowsScattering:{enabled:true,address,deviceId:device,
 receiptKeyFile:win32.join(dir,'receipt.key'),endpoint:'http://127.0.0.1:49510/'}};
const contacts=[{address:peer,deviceId:other,expires:9999999999999}];
const uuid='a1478dbe-3003-4bb5-8fda-0123456789ab';
function setup(){
 let writes=0;const files=new Map();
 const storage={
  async writeDraft(path,raw){assert.equal(files.has(path),false);writes++;files.set(path,Buffer.from(raw));},
  async read(path){assert.ok(files.has(path));return Buffer.from(files.get(path));}
 };
 return{storage,files,stats:()=>writes};
}
const fields={to:peer,subject:'Bonjour',body:'Un message de test depuis le logiciel.'};
test('Native GUI draft is private, uniquely named and never sent',async()=>{
 const s=setup();
 const r=await saveWindowsDraft(cfg,contacts,s.storage,fields,{makeId:()=>uuid});
 assert.equal(r.status,'draft-saved-not-sent');
 assert.equal(r.remoteDeliveryVerified,false);
 assert.equal(r.liveAccountEnrollmentAuthorized,false);
 assert.equal(r.legacyDeletionAuthorized,false);
 assert.equal(r.file,'draft-a1478dbe30034bb58fda0123456789ab.json');
 assert.equal(s.stats(),1);
 const doc=JSON.parse(s.files.get(win32.join(dir,r.file)).toString('utf8'));
 assert.deepEqual(doc.payload,{subject:fields.subject,body:fields.body});
 assert.deepEqual(doc.context,{clientMessageId:'qs-'+uuid,from:address,fromDeviceId:device,to:peer,toDeviceId:other});
 await assert.rejects(saveWindowsDraft(cfg,contacts,s.storage,fields,{makeId:()=>uuid}));
 assert.equal(s.stats(),1,'no overwrite of existing draft');
});
test('Unknown/expired/duplicate contacts and foreign sender cannot create a draft',async()=>{
 for(const c of [[],[{...contacts[0],expires:1}],[...contacts,...contacts]]){
  const s=setup();await assert.rejects(saveWindowsDraft(cfg,c,s.storage,fields,{makeId:()=>uuid}));assert.equal(s.stats(),0);
 }
 const s=setup();await assert.rejects(saveWindowsDraft({...cfg,pqMode:{...cfg.pqMode,address:peer}},contacts,s.storage,fields,{makeId:()=>uuid}));assert.equal(s.stats(),0);
});
test('Bounds and malformed fields fail before any private file write',async()=>{
 for(const f of [{...fields,body:'x'.repeat(9000)},{...fields,subject:''},
  {...fields,to:address},{...fields,body:'   '},{...fields,hidden:'test'}]){
  const s=setup();await assert.rejects(saveWindowsDraft(cfg,contacts,s.storage,f,{makeId:()=>uuid}));assert.equal(s.stats(),0);
 }
});

test('new enrollment saves exclusively through native encrypted writer, no plaintext fallback',async()=>{
 const s=setup();const sealed={...cfg,windowsScattering:{...cfg.windowsScattering,receiptKeyFile:win32.join(dir,'receipt.vault'),credentialMode:'vault-sealed-v1'}};
 await assert.rejects(saveWindowsDraft(sealed,contacts,s.storage,fields,{makeId:()=>uuid}));assert.equal(s.stats(),0);
 s.storage.writeEncryptedDraft=async(path,raw)=>{
  assert.equal(JSON.parse(raw).payload.body,fields.body);assert.equal(s.files.has(path),false);
  s.files.set(path,Buffer.from(JSON.stringify({format:'quantic-local-draft',version:1,file:win32.basename(path),iv:'synthetic',ciphertext:'synthetic'})));
 };
 const r=await saveWindowsDraft(sealed,contacts,s.storage,fields,{makeId:()=>uuid});
 assert.equal(r.status,'draft-saved-not-sent');assert.equal(s.stats(),0);assert.ok(!s.files.get(win32.join(dir,r.file)).includes(Buffer.from(fields.body)));
});
