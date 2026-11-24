// Temporary, authenticated IPv4 UDP diagnostic. This is NOT QuanticMail,
// Scattering anonymity, or proof of delivery between physical devices.
import {randomBytes,createHmac,timingSafeEqual} from 'node:crypto';
import {createSocket} from 'node:dgram';
import {isIPv4} from 'node:net';

const magic=Object.freeze({hello:Buffer.from('QSNETA01'),reply:Buffer.from('QSNETB01'),
 finish:Buffer.from('QSNETC01'),done:Buffer.from('QSNETD01')});
const refuse=x=>{if(!x)throw Error('Two-host synthetic network proof refused');};
const portOK=x=>Number.isInteger(x)&&x>=1024&&x<=65535;
const hostOK=x=>typeof x==='string'&&isIPv4(x)&&x!=='0.0.0.0'&&!x.startsWith('224.')&&!x.startsWith('255.');
const equal=(a,b)=>Buffer.isBuffer(a)&&Buffer.isBuffer(b)&&a.length===b.length&&timingSafeEqual(a,b);
const tag=(secret,body)=>createHmac('sha256',secret).update(body).digest().subarray(0,16);
const packet=(secret,header,...payload)=>{
 const bare=Buffer.concat([header,...payload]);
 return Buffer.concat([bare,tag(secret,bare)]);
};
function parse(secret,wire,header,size){
 if(!Buffer.isBuffer(wire)||wire.length!==size||!wire.subarray(0,8).equals(header))return null;
 const bare=wire.subarray(0,-16);
 return equal(wire.subarray(-16),tag(secret,bare))?bare.subarray(8):null;
}
function validateSecret(code){
 refuse(typeof code==='string'&&/^[a-f0-9]{24}$/.test(code));
 return Buffer.from(code,'hex');
}
function timeout(ms,onTimeout){
 const t=setTimeout(onTimeout,ms);
 t.unref?.();
 return t;
}
function doneReport(kind){
 return Object.freeze({status:kind,cryptographicMailDelivered:false,
  distinctPhysicalComputersVerified:false,anonymousTransportVerified:false,
  labOnly:true});
}
// Returns as soon as a real bound UDP socket is ready. The caller is
// responsible for presenting the one-use code privately to the second host.
export async function startTwoHostReceiver({port,listen='0.0.0.0',seconds=90,
 code=randomBytes(12).toString('hex')}={}){
 refuse(portOK(port)&&Number.isInteger(seconds)&&seconds>=5&&seconds<=120);
 refuse(listen==='0.0.0.0'||hostOK(listen));
 const secret=validateSecret(code);
 const socket=createSocket('udp4');
 let current=null,ended=false,settle,fail;
 const result=new Promise((resolve,reject)=>{settle=resolve;fail=reject;});
 let timer;
 const stop=(error,success=false)=>{
  if(ended)return;ended=true;clearTimeout(timer);
  socket.close();
  secret.fill(0);
  error?fail(error):settle(doneReport(success?'synthetic-udp-acknowledged':'synthetic-udp-unconfirmed'));
 };
 socket.on('error',()=>stop(Error('Receiver UDP socket refused')));
 socket.on('message',(wire,peer)=>{
  if(ended)return;
  const incoming=parse(secret,wire,magic.hello,40);
  if(incoming&&(!current||current.address===peer.address&&current.port===peer.port&&equal(current.challenge,incoming))){
   if(!current){
    current={address:peer.address,port:peer.port,challenge:Buffer.from(incoming),nonce:randomBytes(16),completed:false};
   }
   if(!current.completed){
    socket.send(packet(secret,magic.reply,current.challenge,current.nonce),current.port,current.address);
   }
   return;
  }
  if(!current||current.address!==peer.address||current.port!==peer.port)return;
  const response=parse(secret,wire,magic.finish,40);
  if(response&&equal(response,current.nonce)){
   current.completed=true;
   socket.send(packet(secret,magic.done,current.nonce),current.port,current.address);
   // One second grace to answer duplicate FINISH packets if ACK was lost.
   clearTimeout(timer);
   timer=timeout(1000,()=>stop(null,true));
  }
 });
 try{
  await new Promise((resolve,reject)=>{
   socket.once('listening',resolve);
   socket.once('error',reject);
   socket.bind(port,listen);
  });
 }catch{
  socket.close();
  secret.fill(0);
  throw Error('UDP receiver cannot bind');
 }
 timer=timeout(seconds*1000,()=>stop(Error('No authenticated synthetic UDP exchange')));
 return Object.freeze({status:'receiver-ready',code,port,wait:result,cancel:()=>stop(Error('Receiver cancelled'))});
}
export async function runTwoHostSender({host,port,code,seconds=15}={}){
 refuse(hostOK(host)&&portOK(port)&&Number.isInteger(seconds)&&seconds>=5&&seconds<=120);
 const secret=validateSecret(code);
 const challenge=randomBytes(16);
 const hello=packet(secret,magic.hello,challenge);
 const socket=createSocket('udp4');
 let phase=0,remoteNonce=null,ended=false,settle,fail,period,timer;
 const result=new Promise((resolve,reject)=>{settle=resolve;fail=reject;});
 const stop=(error,success=false)=>{
  if(ended)return;ended=true;clearTimeout(period);clearTimeout(timer);
  socket.close();secret.fill(0);challenge.fill(0);remoteNonce?.fill(0);
  error?fail(error):settle(doneReport(success?'synthetic-udp-mutual-proof':'synthetic-udp-unconfirmed'));
 };
 const send=()=>{
  if(ended)return;
  const b=phase===0?hello:packet(secret,magic.finish,remoteNonce);
  socket.send(b,port,host,e=>{if(e)stop(Error('UDP sender transport failure'));});
 };
 socket.on('error',()=>stop(Error('UDP sender socket refused')));
 socket.on('message',(wire,peer)=>{
  if(ended||peer.address!==host||peer.port!==port)return;
  if(phase===0){
   const reply=parse(secret,wire,magic.reply,56);
   if(!reply||!equal(reply.subarray(0,16),challenge))return;
   remoteNonce=Buffer.from(reply.subarray(16,32));phase=1;send();
  }else{
   const ack=parse(secret,wire,magic.done,40);
   if(ack&&equal(ack,remoteNonce))stop(null,true);
  }
 });
 try{
  await new Promise((resolve,reject)=>{
   socket.once('listening',resolve);
   socket.once('error',reject);
   socket.bind(0,'0.0.0.0');
  });
 }catch{
  socket.close();secret.fill(0);challenge.fill(0);
  throw Error('UDP sender bind failed');
 }
 timer=timeout(seconds*1000,()=>stop(Error('No authenticated synthetic UDP response')));
 send();
 period=setInterval(send,750);
 period.unref?.();
 return await result;
}
