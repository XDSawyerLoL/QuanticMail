
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {startDemoSite} from '../examples/quantic-id-site-demo/server.mjs';
const pair=generateKeyPairSync('ed25519');
const pub=pair.publicKey.export({format:'der',type:'spki'});
const keyId='qid_'+createHash('sha256').update(pub).digest('hex').slice(0,32);
test('site demo: signed login, user visibility, revoke and TTL',async(t)=>{
  let now=Date.now();
  const site=await startDemoSite({port:0,now:()=>now});
  t.after(()=>site.close());
  const post=async(path,body,origin=site.url)=>{
    const res=await fetch(site.url+'/api/'+path,{method:'POST',headers:{origin,'content-type':'application/json'},body:JSON.stringify(body)});
    return {status:res.status,data:await res.json()};
  };
  const visible=async()=>await(await fetch(site.url+'/api/presence')).json();
  const challenge=(await post('challenge',{purpose:'activate'})).data.challenge;
  const payload=JSON.stringify({version:1,keyId,challenge,audience:site.url,issuedAt:new Date(now).toISOString()});
  const proof={version:1,keyId,algorithm:'ed25519',payload,publicKey:pub.toString('base64url'),
    signature:sign(null,Buffer.from(payload),pair.privateKey).toString('base64url')};
  const active=await post('activate',{challenge,proof,displayName:'Démonstrateur'});
  assert.equal(active.status,200);
  assert.equal((await visible()).visitors[0].name,'Démonstrateur');
  assert.equal(JSON.stringify(await visible()).includes(keyId),false);
  assert.match((await fetch(site.url)).headers.get('cache-control'),/no-store/);
  const reject=await post('challenge',{purpose:'activate'},'https://evil.example');
  assert.equal(reject.status,403);
  assert.equal((await post('lock',{token:active.data.token})).data.revoked,true);
  assert.deepEqual((await visible()).visitors,[]);
  const c2=(await post('challenge',{purpose:'activate'})).data.challenge;
  const p2=JSON.stringify({version:1,keyId,challenge:c2,audience:site.url,issuedAt:new Date(now).toISOString()});
  await post('activate',{challenge:c2,displayName:'Démonstrateur',proof:{...proof,payload:p2,signature:sign(null,Buffer.from(p2),pair.privateKey).toString('base64url')}});
  now+=10001;
  assert.deepEqual((await visible()).visitors,[]);
});
test('site demo: forged proof does not produce presence',async(t)=>{
  const site=await startDemoSite();
  t.after(()=>site.close());
  const headers={origin:site.url,'content-type':'application/json'};
  const request=async(path,body)=>fetch(site.url+'/api/'+path,{method:'POST',headers,body:JSON.stringify(body)});
  const c=await(await request('challenge',{purpose:'activate'})).json();
  const payload=JSON.stringify({version:1,keyId,challenge:c.challenge,audience:site.url,issuedAt:new Date().toISOString()});
  const response=await request('activate',{challenge:c.challenge,proof:{version:1,keyId,algorithm:'ed25519',publicKey:pub.toString('base64url'),payload,signature:Buffer.alloc(64).toString('base64url')}});
  assert.equal(response.status,400);
  assert.deepEqual((await(await fetch(site.url+'/api/presence')).json()).visitors,[]);
});
