// Authenticated readiness barrier over the dedicated connected bootstrap socket.
// READY asserts local staging + gated native carrier readiness. ACK asserts
// receipt of the peer READY. Not an atomic distributed commit or delivery proof.
import {createHmac,timingSafeEqual,hkdfSync} from 'node:crypto';
const check=x=>{if(!x)throw Error('Scattering cutover refused');};
const hex=(x,n)=>typeof x==='string'&&x.length===n&&/^[a-f0-9]+$/.test(x);
export async function confirmScatteringCutover({socket,role,material,context,timeoutMs=5000,signal}){
 check(socket&&typeof socket.remoteAddress==='function'&&typeof socket.send==='function'&&['initiator','responder'].includes(role));
 check(Number.isInteger(timeoutMs)&&timeoutMs>=2000&&timeoutMs<=15000&&!signal?.aborted);
 socket.remoteAddress();
 check(material&&Buffer.isBuffer(material.secret)&&material.secret.length===32&&Buffer.isBuffer(material.epoch)&&material.epoch.length===32&&hex(material.transcript,96)&&context&&hex(context.channel,96)&&hex(context.previous,96)&&Number.isInteger(context.generation)&&context.generation>=0&&context.generation<=65535&&context.generation===material.generation);
 const key=Buffer.from(hkdfSync('sha384',material.secret,material.epoch,Buffer.from('quantic-cutover-key/lab/v1'),48));
 const other=role==='initiator'?'responder':'initiator';
 const packet=(kind,who)=>Buffer.concat([Buffer.from(kind==='ready'?'QCR1':'QCA1'),createHmac('sha384',key).update(JSON.stringify(['quantic-cutover/lab/v1',kind,who,context.channel,context.generation,context.previous,material.transcript])).digest()]);
 const ready=packet('ready',role),ack=packet('ack',role),peerReady=packet('ready',other),peerAck=packet('ack',other);
 key.fill(0);
 return await new Promise((resolve,reject)=>{
  let ended=false,seenReady=false,seenAck=false,received=0,timer,tick,linger;
  function finish(error){
   if(ended)return;ended=true;clearTimeout(timer);clearTimeout(linger);clearInterval(tick);
   socket.off('message',onMessage);socket.off('error',onError);socket.off('close',onError);signal?.removeEventListener('abort',onError);
   for(const b of [ready,ack,peerReady,peerAck])b.fill(0);
   if(error)reject(error);else resolve();
  }
  function onError(){finish(Error('Scattering cutover interrupted'));}
  function transmit(){if(ended)return;try{socket.send(Buffer.from(ready),e=>{if(e)onError();});if(seenReady)socket.send(Buffer.from(ack),e=>{if(e)onError();});}catch{onError();}}
  function onMessage(b){
   if(ended)return;
   if(++received>4096){onError();return;}
   if(!Buffer.isBuffer(b)||b.length!==52)return;
   if(timingSafeEqual(b,peerReady))seenReady=true;
   else if(timingSafeEqual(b,peerAck))seenAck=true;
   else return;
   // Continue periodic READY+ACK long enough to tolerate bounded loss.
   if(seenReady&&seenAck&&!linger){transmit();linger=setTimeout(()=>finish(),600);}
  }
  socket.on('message',onMessage);socket.on('error',onError);socket.on('close',onError);signal?.addEventListener('abort',onError,{once:true});
  timer=setTimeout(()=>finish(Error('Scattering cutover peer not confirmed')),timeoutMs);tick=setInterval(transmit,100);
  if(signal?.aborted)onError();else transmit();
 });
}
