// Synthetic trusted-gateway multiplex experiment. Not anonymous access, a mixnet,
// a network handshake, or a persistent replay ledger. Separate fresh epochs and
// pre-shared independent member keys are mandatory. Use a reliable outer stream.
// The gateway knows member identities and plaintext in this model.
import {createCipheriv,createDecipheriv,createHash,hkdfSync,randomBytes} from 'node:crypto';
export const MUX_POLICY=Object.freeze({frame:128,payload:78,maxMembers:64,maxPerMember:32,maxTotal:512,maxSeq:8192});
const {frame,payload,maxMembers,maxPerMember,maxTotal,maxSeq}=MUX_POLICY;
const check=v=>{if(!v)throw Error('Multiplex lab refused');};
const id=v=>typeof v==='string'&&/^demo-[a-z0-9]{1,24}$/.test(v);
const domain=Buffer.from('quantic-scattering-multiplex/lab/v1');
function provision({members,epoch,direction}){
 check(Array.isArray(members)&&members.length>=2&&members.length<=maxMembers&&Buffer.isBuffer(epoch)&&epoch.length===32&&['a-b','b-a'].includes(direction));
 const byId=new Map(),byLabel=new Map(),seen=new Set();
 for(const m of members){
  check(id(m.id)&&!byId.has(m.id)&&Buffer.isBuffer(m.secret)&&m.secret.length===32);
  const fp=createHash('sha256').update(m.secret).digest('hex');check(!seen.has(fp));seen.add(fp);
  const material=Buffer.from(hkdfSync('sha256',m.secret,epoch,Buffer.from(domain.toString()+':'+direction+':'+m.id),48));
  const key=Buffer.from(material.subarray(0,32)),label=Buffer.from(material.subarray(32)),name=label.toString('hex');material.fill(0);
  check(!byLabel.has(name));
  const state={id:m.id,key,label,seq:0,queue:[]};byId.set(m.id,state);byLabel.set(name,state);
 }
 return {byId,byLabel,close(){for(const s of byId.values()){s.key.fill(0);s.label.fill(0);for(const b of s.queue)b.fill(0);s.queue.length=0;}byId.clear();byLabel.clear();}};
}
function seal(s,data){
 check(s.seq<maxSeq);const p=randomBytes(84);p.writeUInt32BE(s.seq,0);p.writeUInt16BE(data.length,4);data.copy(p,6);
 const nonce=randomBytes(12),c=createCipheriv('aes-256-gcm',s.key,nonce);
 c.setAAD(Buffer.concat([domain,s.label]));const out=Buffer.concat([s.label,nonce,c.update(p),c.final(),c.getAuthTag()]);
 p.fill(0);s.seq++;return out;
}
export function openMultiplexSender(config){
 const p=provision(config),states=[...p.byId.values()];let cursor=0,queued=0,slots=0,closed=false;
 return Object.freeze({
  enqueue(member,data){
   check(!closed&&Buffer.isBuffer(data)&&data.length>=1&&data.length<=payload);
   const s=p.byId.get(member);check(s&&s.queue.length<maxPerMember&&queued<maxTotal&&s.seq+s.queue.length<maxSeq);
   s.queue.push(Buffer.from(data));queued++;
  },
  // Called exactly once per externally scheduled slot, never by enqueue().
  nextSlot(){
   check(!closed);slots++;
   for(let i=0;i<states.length;i++){
    const j=(cursor+i)%states.length,s=states[j];
    if(s.queue.length){const data=s.queue[0],out=seal(s,data);s.queue.shift();data.fill(0);queued--;cursor=(j+1)%states.length;return out;}
   }
   return randomBytes(frame);
  },
  stats:()=>Object.freeze({queued,slots}),
  close(){if(!closed){closed=true;queued=0;p.close();}}
 });
}
export function openMultiplexReceiver(config){
 const p=provision(config);let closed=false;
 return Object.freeze({
  receive(packet){
   check(!closed&&Buffer.isBuffer(packet)&&packet.length===frame);
   const s=p.byLabel.get(packet.subarray(0,16).toString('hex'));if(!s)return null;
   let plain;try{
    const d=createDecipheriv('aes-256-gcm',s.key,packet.subarray(16,28));
    d.setAAD(Buffer.concat([domain,s.label]));d.setAuthTag(packet.subarray(112,128));
    plain=Buffer.concat([d.update(packet.subarray(28,112)),d.final()]);
    const seq=plain.readUInt32BE(0),len=plain.readUInt16BE(4);
    if(seq!==s.seq||seq>=maxSeq||len<1||len>payload)return null;
    const data=Buffer.from(plain.subarray(6,6+len));s.seq++;return {member:s.id,data};
   }catch{return null;}finally{plain?.fill(0);}
  },
  close(){if(!closed){closed=true;p.close();}}
 });
}
