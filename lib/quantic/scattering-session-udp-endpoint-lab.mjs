// Experimental endpoint-local handshake over an explicitly connected UDP socket.
// Trust is pinned out of band. No PSK, discovery, durable distributed cutover
// or resistance to traffic analysis/DoS is claimed.
import {createHmac,timingSafeEqual} from 'node:crypto';
import {openHybridSessionLab} from './scattering-session-lab.mjs';
import {fragmentSession,openSessionAssembly} from './scattering-session-udp-bootstrap-lab.mjs';
const check=x=>{if(!x)throw Error('Native UDP negotiation refused');};
function receipt(m){
 return Buffer.concat([Buffer.from('QHAC'),createHmac('sha384',m.secret)
  .update(JSON.stringify(['quantic-public-bootstrap/accept/lab/v1',m.generation,m.transcript,m.epoch.toString('hex')])).digest()]);
}
// Caller owns the connected socket and the independently pinned public context.
// A successful result only confirms a local key agreement; never authorize mail
// until the application's durable fencing and peer policy checks have passed.
export async function negotiateUdpSessionLab({socket,role,local,privateKeys,signHandshake,peer,context,timeoutMs=8000,signal}){
 check(socket&&typeof socket.remoteAddress==='function'&&typeof socket.send==='function'
  &&['initiator','responder'].includes(role)&&Number.isInteger(timeoutMs)&&timeoutMs>=2000&&timeoutMs<=15000&&!signal?.aborted);
 socket.remoteAddress(); // refuse a socket without an explicit peer
 const session=openHybridSessionLab({role,local,privateKeys,signHandshake,peer,context});
 let result,phase,assembly,out=[],timer,tick,linger,finished=false,received=0;
 try{
  return await new Promise((resolve,reject)=>{
   function finish(error){
    if(finished)return;finished=true;
    clearTimeout(timer);clearInterval(tick);clearTimeout(linger);
    socket.off('message',onMessage);socket.off('error',onError);socket.off('close',onError);signal?.removeEventListener('abort',onError);
    if(error){result?.secret.fill(0);result?.epoch.fill(0);reject(error);}
    else resolve(result);
   }
   const onError=()=>finish(Error('UDP bootstrap socket failed'));
   function transmit(){if(finished)return;try{for(const p of out)socket.send(p,e=>{if(e)onError();});}catch(e){finish(e);}}
   function setPhase(next,kind,frame){
    phase=next;assembly=next==='ack'||next==='linger'?null:openSessionAssembly(next,context);
    out=kind?fragmentSession(kind,frame,context):[];transmit();
   }
   function onMessage(packet){
    if(finished)return;
    try{
     check(++received<=4096);
     if(phase==='linger'||phase==='signing')return;
     if(phase==='ack'){
      const expected=receipt(result);
      if(packet.length===expected.length&&timingSafeEqual(packet,expected)){
       // Keep the connected socket alive while the responder repeats its
       // receipt; immediate teardown can generate ICMP port-unreachable
       // and cause the other endpoint to refuse an otherwise valid session.
       phase='linger';out=[];
       linger=setTimeout(()=>finish(),1100);
      }
      return;
     }
     const frame=assembly.push(packet);if(!frame)return;
     if(phase==='hello'){
      phase='signing';out=[];
      Promise.resolve(session.respond(frame)).then(response=>{if(!finished)setPhase('finish','response',response);}).catch(finish);
     }else if(phase==='response'){
      const final=session.finish(frame);result=session.take();
      setPhase('ack','finish',final);
     }else if(phase==='finish'){
      session.accept(frame);result=session.take();
      phase='linger';assembly=null;out=[receipt(result)];transmit();
      // Repeat the authenticated receipt for bounded loss recovery. A peer
      // failure after local completion is still possible; no atomic cutover.
      linger=setTimeout(()=>finish(),900);
     }else check(false);
    }catch(e){finish(e);}
   }
   socket.on('message',onMessage);socket.on('error',onError);socket.on('close',onError);signal?.addEventListener('abort',onError,{once:true});
   timer=setTimeout(()=>finish(Error('UDP bootstrap timeout')),timeoutMs);
   tick=setInterval(transmit,150);
   try{
    if(signal?.aborted){onError();return;}
    if(role==='initiator'){phase='signing';Promise.resolve(session.begin()).then(hello=>{if(!finished)setPhase('response','hello',hello);}).catch(finish);}
    else setPhase('hello');
   }catch(e){finish(e);}
  });
 }finally{session.close();}
}
