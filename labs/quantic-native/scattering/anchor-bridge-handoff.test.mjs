// Exercise admission between two separate real native carrier epochs.
import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {createInterface} from 'node:readline';
import {fileURLToPath} from 'node:url';
import {setTimeout as sleep} from 'node:timers/promises';
test('bounded handoff preserves the next connection before prior TCP close', {timeout:20000}, async()=>{
 const peers=new Set();
 const upstream=net.createServer(s=>{peers.add(s);s.on('error',()=>s.destroy());s.on('close',()=>peers.delete(s));s.pipe(s);});
 upstream.listen(0,'127.0.0.1');await once(upstream,'listening');
 const bridge=spawn(process.execPath,[fileURLToPath(new URL('./anchor-bridge.mjs',import.meta.url)),String(upstream.address().port),'--synthetic-loopback-only'],{stdio:['ignore','pipe','inherit']});
 const lines=createInterface({input:bridge.stdout});let a,b,c;
 const closed=once(bridge,'exit');
 async function connect(port){
  const s=net.connect(port,'127.0.0.1');
  s.on('error',()=>{});
  await once(s,'connect');return s;
 }
 async function echo(socket,message){
  const response=once(socket,'data');
  socket.write(message);
  const [got]=await response;assert.equal(got.toString(),message);
 }
 try{
  const [line]=await once(lines,'line');const {port}=JSON.parse(line);
  a=await connect(port);await echo(a,'first');
  b=await connect(port);const reply=once(b,'data');let premature=false;
  b.once('close',()=>{premature=true;});
  b.write('second');await sleep(100);
  assert.equal(premature,false,'next connection refused while predecessor is active');
  // The one-slot queue must not admit another overlapping connection.
  c=await connect(port);await once(c,'close');
  assert.equal(premature,false);
  a.destroy();const [message]=await reply;
  assert.equal(message.toString(),'second');
 }finally{
  a?.destroy();b?.destroy();c?.destroy();
  bridge.kill('SIGTERM');await closed;
  lines.close();for(const s of peers)s.destroy();
  await new Promise(resolve=>upstream.close(resolve));
 }
});
