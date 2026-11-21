// RC2 laboratory only; not an audited transport or a production receipt protocol.
import {createCipheriv,createDecipheriv,randomBytes} from 'node:crypto';
import {Duplex} from 'node:stream';
import {performance} from 'node:perf_hooks';
import {readdirSync,unlinkSync} from 'node:fs';
import {join} from 'node:path';
import {writeSpool} from './scattering-cell.mjs';
export const POLICY=Object.freeze({periodMs:100,cellsPerTick:8,payload:128,maxSeq:8192,window:256,writeDeadlineMs:3000});
const AAD=Buffer.from('quantic-scattering-v8-rc2/reliable');
const check=(ok,msg)=>{if(!ok)throw Error(msg)};
export function sealReliable(key,{seq=null,ack,data=Buffer.alloc(0)}){
  check(Buffer.isBuffer(key)&&key.length===32,'bad key');
  check(Number.isInteger(ack)&&ack>=0&&ack<=POLICY.maxSeq,'bad ack');
  check(Buffer.isBuffer(data)&&((seq===null&&data.length===0)||(Number.isInteger(seq)&&seq>=0&&seq<POLICY.maxSeq&&data.length>=1&&data.length<=128)),'bad data');
  const p=randomBytes(140);p[0]=seq===null?0:1;p[1]=0;p.writeUInt16BE(data.length,2);p.writeUInt32BE(seq??0,4);p.writeUInt32BE(ack,8);data.copy(p,12);
  const nonce=randomBytes(12),c=createCipheriv('aes-256-gcm',key,nonce);c.setAAD(AAD);return Buffer.concat([nonce,c.update(p),c.final(),c.getAuthTag()]);
}
export function openReliable(key,packet){try{
  if(!Buffer.isBuffer(packet)||packet.length!==168)return null;
  const c=createDecipheriv('aes-256-gcm',key,packet.subarray(0,12));c.setAAD(AAD);c.setAuthTag(packet.subarray(-16));const p=Buffer.concat([c.update(packet.subarray(12,-16)),c.final()]);
  const len=p.readUInt16BE(2),seq=p.readUInt32BE(4),ack=p.readUInt32BE(8);if(p[1]!==0||ack>POLICY.maxSeq)return null;
  if(p[0]===0&&len===0&&seq===0)return {seq:null,ack,data:Buffer.alloc(0)};
  if(p[0]!==1||len<1||len>128||seq>=POLICY.maxSeq)return null;return {seq,ack,data:p.subarray(12,12+len)};
}catch{return null;}}
// Per epoch. ACKs acknowledge volatile stream admission, NOT durable message delivery.
// Fixed periodic transmission: receive() never publishes or schedules a retry.
// publish accepts a batch of exactly eight opaque cells; native pacer remains autonomous.
export function reliableCellStream({sendKey,recvKey,dir,autoTick=true,publish,clock=()=>performance.now(),compactPacing=false}){
  check(Buffer.isBuffer(sendKey)&&sendKey.length===32&&Buffer.isBuffer(recvKey)&&recvKey.length===32&&!sendKey.equals(recvKey),'distinct direction keys required');
  // Fixed profile selected at startup, never derived from traffic.
  const periodMs=compactPacing?50:POLICY.periodMs, cellsPerTick=compactPacing?2:POLICY.cellsPerTick;
  const retryMs=compactPacing?250:0;
  sendKey=Buffer.from(sendKey);recvKey=Buffer.from(recvKey);
  let next=0,expect=0,acked=0,advertised=0,closed=false,blocked=false,writing=null,timer=null,lastTick=-Infinity;
  const outbound=new Map(),pending=new Map();const stats={ticks:0,queued:0,retransmitted:0,auth:0,duplicates:0,coverOrInvalid:0,delivered:0,acked:0,backloggedTicks:0};
  if(!publish)publish=(packets)=>{
    const names=readdirSync(dir);for(const name of names)if(/^[0-9a-f]{32}\.loaded$/.test(name))unlinkSync(join(dir,name));
    if(names.filter(x=>x.endsWith('.ready')||x.endsWith('.working')).length>=4)return false;
    writeSpool(dir,packets);return true;
  };
  function drain(){while(!blocked&&pending.has(expect)){const data=pending.get(expect);pending.delete(expect);expect++;stats.delivered++;if(!s.push(data))blocked=true;}}
  function finishWrite(){if(writing&&acked>=writing.end){const cb=writing.cb;writing=null;cb();}}
  const s=new Duplex({read(){blocked=false;drain();},write(chunk,_,cb){try{
    check(!closed&&!writing&&Buffer.isBuffer(chunk)&&chunk.length>0,'invalid write');const parts=Math.ceil(chunk.length/128);check(parts<=POLICY.window&&next+parts<=POLICY.maxSeq,'epoch capacity exceeded');
    for(let off=0;off<chunk.length;off+=128)outbound.set(next++,{data:Buffer.from(chunk.subarray(off,off+128)),sent:false,lastSent:-Infinity});
    writing={end:next,cb,deadline:clock()+POLICY.writeDeadlineMs};
  }catch(e){cb(e);}},destroy(e,cb){closed=true;if(timer)clearInterval(timer);for(const f of outbound.values())f.data.fill(0);outbound.clear();pending.clear();sendKey.fill(0);recvKey.fill(0);const w=writing;writing=null;if(w)w.cb(e??Error('epoch closed before acknowledgement'));cb(e);}});
  function tick(){if(closed)return;try{
    const now=clock();check(Number.isFinite(now)&&now>=lastTick,'clock rollback');if(now-lastTick<periodMs-1)return;lastTick=now;
    if(writing)check(now<writing.deadline,'ack deadline expired');
    // Send eligible oldest cells, including timed-out cells. Unsent cells can progress
    // while earlier cells await cumulative acknowledgement. Fixed batch size remains unchanged.
    const chosen=[...outbound.entries()].filter(([,f])=>!f.sent||now-f.lastSent>=retryMs).slice(0,cellsPerTick),packets=[];
    for(let i=0;i<cellsPerTick;i++){const x=chosen[i];packets.push(sealReliable(sendKey,x?{seq:x[0],ack:expect,data:x[1].data}:{ack:expect}));}
    stats.ticks++;if(publish(packets)===false){stats.backloggedTicks++;return;}
    for(const [seq,f] of chosen){if(f.sent)stats.retransmitted++;f.sent=true;f.lastSent=now;advertised=Math.max(advertised,seq+1);}stats.queued+=packets.length;
  }catch(e){s.destroy(e);}}
  function receive(packet){if(closed)return;const f=openReliable(recvKey,packet);if(!f){stats.coverOrInvalid++;return;}stats.auth++;
    if(f.ack>advertised){s.destroy(Error('ack for unsent sequence'));return;}
    if(f.ack>acked){for(let seq=acked;seq<f.ack;seq++){outbound.get(seq)?.data.fill(0);outbound.delete(seq);}acked=f.ack;stats.acked=acked;finishWrite();}
    if(f.seq===null)return;if(f.seq<expect||pending.has(f.seq)){stats.duplicates++;return;}
    if(f.seq-expect>=POLICY.window){s.destroy(Error('receive window exceeded'));return;}
    pending.set(f.seq,f.data);drain();
  }
  if(autoTick)timer=setInterval(tick,periodMs);
  return {stream:s,stats,receive,tick};
}
