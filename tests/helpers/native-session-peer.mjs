// Independent synthetic process: private keys never leave this process.
// IPC carries public configuration and a synthetic session-key commitment only.
import {createSocket} from 'node:dgram';
import {generateKeyPairSync,createPublicKey,createHash} from 'node:crypto';
import {openCompactSender,openCompactReceiver} from '../../lib/quantic/scattering-mux-compact-lab.mjs';
import {negotiateUdpSessionLab} from '../../lib/quantic/scattering-session-udp-endpoint-lab.mjs';
const socket=createSocket('udp4');
const classical=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),pq=generateKeyPairSync('ml-dsa-65');
const local={classical:classical.publicKey,pq:pq.publicKey};
const privateKeys={classical:classical.privateKey,pq:pq.privateKey};
const encode=k=>k.export({format:'der',type:'spki'}).toString('base64url');
const decode=s=>createPublicKey({key:Buffer.from(s,'base64url'),format:'der',type:'spki'});
let active=false,ending=false;
function end(message){
 if(ending)return;ending=true;
 socket.close(()=>process.send(message,()=>process.disconnect()));
}
socket.on('error',()=>end({type:'refused'}));
process.once('disconnect',()=>{if(!ending)socket.close();});
process.once('message',async m=>{
 if(active||m.type!=='start')return end({type:'refused'});
 active=true;let material;
 try{
  const peer={classical:decode(m.peer.classical),pq:decode(m.peer.pq)};
  await new Promise((resolve,reject)=>{socket.once('error',reject);socket.connect(m.port,'127.0.0.1',resolve);});
  material=await negotiateUdpSessionLab({socket,role:m.role,local,privateKeys,peer,context:m.context,timeoutMs:4000});
  const commitment=createHash('sha256').update('synthetic-test-only/v1').update(material.secret).update(material.epoch).digest('hex');
  if(m.exchange!==true){end({type:'agreed',commitment,transcript:material.transcript});return;}
  // Both directions derive separate keys from the independently negotiated
  // material. The parent receives no secret or plaintext, only test evidence.
  const direction=m.role==='initiator'?'a-b':'b-a',opposite=direction==='a-b'?'b-a':'a-b';
  const label=Buffer.from(m.context.channel,'hex').subarray(0,16);
  const sender=openCompactSender({...material,label,direction}),receiver=openCompactReceiver({...material,label,direction:opposite});
  const plain=Buffer.from('synthetic independent payload '+direction);
  const expected=Buffer.from('synthetic independent payload '+opposite);
  const frame=sender.seal(plain);plain.fill(0);
  let received=false,reported=false,started=false,tick,deadline;
  const cleanup=()=>{clearInterval(tick);clearTimeout(deadline);socket.off('message',onData);sender.close();receiver.close();frame.fill(0);expected.fill(0);};
  function onData(packet){
   if(packet.length!==128)return;
   try{
    const data=receiver.open(packet);
    if(data){
     if(received||!data.equals(expected)){data.fill(0);cleanup();return end({type:'refused'});}
     received=true;data.fill(0);return;
    }
    if(received&&started&&!reported){
     reported=true;process.send({type:'exchanged',authenticatedPayload:true,replayRefused:true});
    }
   }catch{cleanup();end({type:'refused'});}
  }
  socket.on('message',onData);
  deadline=setTimeout(()=>{cleanup();end({type:'refused'});},6000);
  process.on('message',command=>{
   if(command.type==='exchange'&&!started){
    started=true;
    const send=()=>{if(!ending)socket.send(frame,e=>{if(e&&!ending){cleanup();end({type:'refused'});}});};
    tick=setInterval(send,150);send();
   }else if(command.type==='stop'&&reported){cleanup();end({type:'done'});}
  });
  process.send({type:'agreed',commitment,transcript:material.transcript});
 }catch{end({type:'refused'});}
 finally{material?.secret.fill(0);material?.epoch.fill(0);}
});
socket.bind(0,'127.0.0.1',()=>process.send({type:'ready',port:socket.address().port,publicKeys:{classical:encode(local.classical),pq:encode(local.pq)}}));
