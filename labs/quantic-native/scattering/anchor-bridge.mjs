// Disposable single-host integration laboratory. Fixed loopback destination.
// The TLS endpoints remain in Go and Python; the bridge handles ciphertext only.
import net from 'node:net';
import dgram from 'node:dgram';
import {randomBytes} from 'node:crypto';
import {mkdtempSync,mkdirSync,rmSync} from 'node:fs';
import {join,dirname} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';
import {cellKey} from './scattering-cell.mjs';
import {reliableCellStream} from './scattering-reliable-lab.mjs';
const port=Number(process.argv[2]);
if(process.argv[3]!=='--synthetic-loopback-only'||!Number.isInteger(port)||port<1||port>65535)throw Error('lab target required');
const dualFeed=process.argv[4]==='--dual-proof-feed-lab';
const persistentFeed=dualFeed||process.argv[4]==='--persistent-feed-lab';
if(process.argv.length>5 || (process.argv[4]&&!persistentFeed))throw Error('unknown bridge mode');
const root=mkdtempSync(join(tmpdir(),'qv-scattering-'));const native=join(dirname(fileURLToPath(import.meta.url)),'QuanticNativePacer_v7_1_linux_amd64');
const dirs=[0,1].map(i=>{const p=join(root,String(i));mkdirSync(p,{mode:0o700});return p});
const stats={connections:0,datagrams:[0,0],wrongSize:0,streamErrors:0,bytes:[0,0]};let active=null,stopping=false;const pacers=[];
const udp=await Promise.all([0,1].map(i=>new Promise((resolve,reject)=>{const s=dgram.createSocket('udp4');s.once('error',reject);s.on('message',m=>{stats.datagrams[i]++;if(m.length!==168)stats.wrongSize++;active?.cells[i].receive(m)});s.bind(0,'127.0.0.1',()=>resolve(s))})));
for(let i=0;i<2;i++){const p=spawn(native,['-target','127.0.0.1:'+udp[1-i].address().port,'-queue-dir',dirs[i],'-period-us',persistentFeed&&!dualFeed?'20000':'5000','-poll','10ms','-duration','60s','-wait-mode','native'],{stdio:['ignore','ignore','ignore']});p.on('error',()=>stop(1));p.on('exit',()=>{if(!stopping)stop(1)});pacers.push(p)}
const server=net.createServer(client=>{
  if(active||stopping){client.destroy();return}
  const secret=randomBytes(32),salt=randomBytes(32),ab=cellKey(secret,salt,'a-b'),ba=cellKey(secret,salt,'b-a');secret.fill(0);salt.fill(0);
  const cells=[reliableCellStream({sendKey:ab,recvKey:ba,dir:dirs[0],compactPacing:persistentFeed,dualProofPacing:dualFeed}),reliableCellStream({sendKey:ba,recvKey:ab,dir:dirs[1],compactPacing:persistentFeed,dualProofPacing:dualFeed})];ab.fill(0);ba.fill(0);
  const upstream=net.connect({host:'127.0.0.1',port});const sockets=[client,upstream];let closed=false;
  const end=()=>{if(closed)return;closed=true;clearTimeout(timer);for(const s of sockets)s.destroy();for(const c of cells)c.stream.destroy();if(active?.cells===cells)active=null};
  active={cells,end};stats.connections++;const timer=setTimeout(end,persistentFeed?55000:12000);
  // Do not translate TLS or the HTTP request. Acknowledgements are transport-only.
  for(let i=0;i<2;i++){const s=sockets[i],stream=cells[i].stream;s.on('error',end);stream.on('error',()=>{stats.streamErrors++;end()});s.on('data',chunk=>{stats.bytes[i]+=chunk.length});s.pipe(stream,{end:false});stream.pipe(s,{end:false});}
  client.on('close',end);
  // HTTP/1.0 authority sends a bounded Content-Length. The client closes
  // the connection after its TLS HTTP response; no general TCP EOF protocol.
});
function stop(code=0){if(stopping)return;stopping=true;active?.end();server.close();for(const u of udp)u.close();for(const p of pacers)if(p.exitCode===null)p.kill();console.log(JSON.stringify({stats}));setTimeout(()=>{rmSync(root,{recursive:true,force:true});process.exit(code)},100).unref()}
process.on('SIGTERM',()=>stop());process.on('SIGINT',()=>stop());server.listen(0,'127.0.0.1',()=>console.log(JSON.stringify({port:server.address().port})));
