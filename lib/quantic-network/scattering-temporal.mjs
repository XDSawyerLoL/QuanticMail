// V7.1.5 laboratory: fixed-time session lifecycle, no production wiring.
import { performance } from 'node:perf_hooks';
const check=(ok,msg)=>{if(!ok)throw new Error(msg)};
export const POLICY=Object.freeze({rotationMs:30000,refreshMs:5000,maxLeaseMs:10000,driftMs:250});

// Time source has a wall component for signed timestamps and a monotonically
// advancing component for local deadlines. Any excessive divergence is fatal.
export function guardedClock({wall=Date.now,mono=()=>Math.floor(performance.now()),driftMs=POLICY.driftMs}={}){
  const w0=wall(),m0=mono();
  check(Number.isSafeInteger(w0)&&Number.isSafeInteger(m0)&&Number.isSafeInteger(driftMs)&&driftMs>=0,'invalid clock configuration');
  let last=m0,failed=false;
  return ()=>{try{
    check(!failed,'clock permanently invalidated');
    const w=wall(),m=mono();
    check(Number.isSafeInteger(w)&&Number.isSafeInteger(m)&&m>=last,'monotonic rollback');
    const elapsed=m-m0,now=w0+elapsed;
    check(Number.isSafeInteger(now)&&Math.abs(w-now)<=driftMs,'wall/monotonic divergence');
    last=m;return {now,elapsed};
  }catch(e){failed=true;throw e;}};
}

// tick is the ONLY operation allowed to query witnesses or negotiate a key.
// Call tick on a fixed external timer, even with no user activity. Operations
// never catch up missed intervals and never silently extend an authorization.
// begin is a lab handshake adapter: it MUST negotiate newly generated keys,
// use the supplied cached reader/clock, and return a fully established session.
export function createTemporalSession({readTime,addresses,fetchAuthority,begin,labOnly}){
  check(labOnly===true,'lab opt-in required');
  check(Array.isArray(addresses)&&addresses.length===2&&new Set(addresses).size===2&&addresses.every(a=>typeof a==='string'&&a.length>0),'two addresses required');
  addresses=[...addresses];
  const {rotationMs,refreshMs,maxLeaseMs}=POLICY;
  const high=new Map();
  let active=null,cache=new Map(),rotation=-1,refresh=-1,stopped=false,lastElapsed=-1;
  function clear(){const old=active;active=null;cache.clear();if(old)old.close();}
  function stop(){stopped=true;clear();}
  function time(){try{check(!stopped,'temporal session stopped');const t=readTime();check(Number.isSafeInteger(t.now)&&Number.isSafeInteger(t.elapsed)&&t.elapsed>=0&&t.elapsed>=lastElapsed,'invalid elapsed clock');lastElapsed=t.elapsed;return t;}catch(e){stop();throw e;}}
  function cached(address){const t=time(),v=cache.get(address);check(v&&t.elapsed<v.deadline&&t.now<v.raw.validUntil,'authority expired');return structuredClone(v.raw);}
  function ensure(){try{const t=time();check(active&&Math.floor(t.elapsed/rotationMs)===rotation,'rotation overdue or session unavailable');for(const a of addresses)cached(a);return active;}catch(e){clear();throw e;}}
  function tick(){
    const t=time(),r=Math.floor(t.elapsed/rotationMs),f=Math.floor(t.elapsed/refreshMs);
    const newEpoch=r!==rotation;
    if(newEpoch||[...cache.values()].some(v=>t.elapsed>=v.deadline||t.now>=v.raw.validUntil))clear();
    try{
      if(f!==refresh){
        // One refresh per current slot, never a burst of missed requests.
        refresh=f;
        const prior=cache,next=new Map();
        for(const address of addresses){
          const before=time(),v=fetchAuthority(address),after=time();
          check(v&&Number.isSafeInteger(v.validUntil)&&v.validUntil>after.now&&v.validUntil<=before.now+maxLeaseMs,'invalid or expired authority lease');
          check(typeof v.digest==='string'&&/^[0-9a-f]{64}$/.test(v.digest)&&Number.isSafeInteger(v.sequence)&&v.sequence>=1,'invalid authority snapshot');
          const old=high.get(address);
          if(old)check(v.sequence>=old.sequence&&(v.sequence!==old.sequence||v.digest===old.digest),'authority rollback or conflict');
          high.set(address,{sequence:v.sequence,digest:v.digest});
          next.set(address,{raw:structuredClone(v),deadline:after.elapsed+v.validUntil-after.now});
        }
        if(active&&addresses.some(a=>prior.get(a)?.raw.digest!==next.get(a).raw.digest)){clear();throw Error('manifest changed: session closed');}
        cache=next;
      }
      // Never recreate an invalidated session in the same epoch.
      if(newEpoch){
        rotation=r;
        for(const a of addresses)cached(a);
        const candidate=begin({readAuthority:cached,clock:()=>time().now,rotation:r});
        check(candidate&&typeof candidate.close==='function'&&typeof candidate.seal==='function'&&typeof candidate.open==='function','invalid session adapter');
        active=candidate;
      }
      const end=time();check(Math.floor(end.elapsed/rotationMs)===r&&Math.floor(end.elapsed/refreshMs)===f,'scheduled operation crossed boundary');
      for(const a of addresses)cached(a);
      return {rotation:r,refresh:f,active:!!active};
    }catch(e){rotation=r;clear();throw e;}
  }
  return {tick,stop,seal(data){return ensure().seal(data)},open(frame){return ensure().open(frame)}};
}
