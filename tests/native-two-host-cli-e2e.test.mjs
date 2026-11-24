import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createSocket} from 'node:dgram';
import {fileURLToPath} from 'node:url';
import {setTimeout as sleep} from 'node:timers/promises';

const script=fileURLToPath(new URL('../scripts/native-two-host-network-lab.mjs',import.meta.url));
async function pickPort(){
 const s=createSocket('udp4');
 await new Promise((ok,no)=>{s.once('error',no);s.bind(0,'127.0.0.1',ok);});
 const port=s.address().port;
 await new Promise(ok=>s.close(ok));
 return port;
}
function launch(args,input){
 const child=spawn(process.execPath,[script,...args],{
  shell:false,windowsHide:true,stdio:['pipe','pipe','pipe'],env:{...process.env}});
 let stdout='',stderr='';
 child.stdout.on('data',x=>{stdout+=x.toString('utf8');if(stdout.length>4096)child.kill();});
 child.stderr.on('data',x=>{stderr+=x.toString('utf8');if(stderr.length>4096)child.kill();});
 const closed=new Promise((ok,no)=>{
  child.once('error',no);
  child.once('close',(code,signal)=>ok({code,signal}));
 });
 child.stdin.end(input);
 return {child,closed,stdout:()=>stdout,stderr:()=>stderr};
}
async function waitJSON(p,n,ms=4000){
 for(let i=0;i<Math.ceil(ms/25);i++){
  const lines=p.stdout().split('\n').filter(Boolean);
  if(lines.length>=n)return JSON.parse(lines[n-1]);
  if(p.child.exitCode!==null)break;
  await sleep(25);
 }
 throw Error('Expected a complete native CLI report: '+p.stdout()+' '+p.stderr());
}
test('real native CLI: receiver and piped sender succeed over UDP without TTY or real keys',{timeout:14000},async()=>{
 const port=await pickPort();
 const receive=launch(['receive',String(port),'8']);
 let send;
 try{
  const ready=await waitJSON(receive,1);
  assert.equal(ready.status,'receiver-ready');
  assert.match(ready.code,/^[a-f0-9]{24}$/);
  send=launch(['send','127.0.0.1',String(port),'5'],ready.code);
  const sendResult=await send.closed;
  assert.equal(sendResult.code,0,send.stderr());
  const report=await waitJSON(send,1);
  assert.equal(report.status,'synthetic-udp-mutual-proof');
  assert.equal(report.cryptographicMailDelivered,false);
  const recvResult=await receive.closed;
  assert.equal(recvResult.code,0,receive.stderr());
  assert.equal((await waitJSON(receive,2)).status,'synthetic-udp-acknowledged');
 }finally{
  send?.child.kill();receive.child.kill();
 }
});
test('real native CLI refuses direct missing code rather than interpreting it as consent',{timeout:7000},async()=>{
 const s=launch(['send','127.0.0.1','49001','5'],'');
 const result=await s.closed;
 assert.notEqual(result.code,0);
 assert.match(s.stderr(),/REFUSE/);
});
