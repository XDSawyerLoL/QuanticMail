// Independent synthetic process: private keys never leave this process.
// IPC carries public configuration and a synthetic session-key commitment only.
import {createSocket} from 'node:dgram';
import {generateKeyPairSync,createPublicKey,createHash} from 'node:crypto';
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
  end({type:'agreed',commitment,transcript:material.transcript});
 }catch{end({type:'refused'});}
 finally{material?.secret.fill(0);material?.epoch.fill(0);}
});
socket.bind(0,'127.0.0.1',()=>process.send({type:'ready',port:socket.address().port,publicKeys:{classical:encode(local.classical),pq:encode(local.pq)}}));
