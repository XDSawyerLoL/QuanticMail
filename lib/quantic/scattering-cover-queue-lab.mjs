// Synthetic queue laboratory, no sockets, no real user data. PRNG for reproducibility only, NEVER use for cryptographic scheduling. Ideal service per slot, no ACK, retransmission, network or mixing. Reverse direction counted as coverage only.
export function simulateCover({seconds=600,rate=50,load=20,mode="fixed",seed=1,trafficSeed=2,queueLimit=512,burst=1}={}){
 const check=(x)=>{if(!x)throw Error("invalid cover simulation")};
 check(Number.isInteger(seconds)&&seconds>=10&&seconds<=3600&&[20,50,100,200].includes(rate)&&Number.isFinite(load)&&load>0&&load<=400&&["fixed","poisson"].includes(mode)&&Number.isInteger(queueLimit)&&queueLimit>=1&&queueLimit<=4096&&[1,4].includes(burst));
 function rng(s){let x=s>>>0;return()=>{x=(Math.imul(x,1664525)+1013904223)>>>0;return (x+.5)/4294967296;}}
 const schedule=rng(seed),input=rng(trafficSeed),gap=(r,lambda)=>-Math.log(r())/lambda;
 const q=[],wait=[],counts=new Uint32Array(seconds);
 let head=0,arrivals=0,dropped=0,slots=0,useful=0,maxQueue=0,slot=mode==="fixed"?1/rate:gap(schedule,rate),arrival=gap(input,load/burst);
 while(slot<seconds||arrival<seconds){
  if(arrival<=slot&&arrival<seconds){
   for(let j=0;j<burst;j++){
    arrivals++;if(q.length-head>=queueLimit)dropped++;else q.push(arrival);
   }
   maxQueue=Math.max(maxQueue,q.length-head);
   arrival+=gap(input,load/burst);
  }else if(slot<seconds){
   slots++;counts[Math.floor(slot)]++;
   if(head<q.length){wait.push(slot-q[head++]);useful++;}
   if(head>=4096){q.splice(0,head);head=0;}
   slot=mode==="fixed"?(slots+1)/rate:slot+gap(schedule,rate);
  }else break;
 }
 wait.sort((a,b)=>a-b);
 const quantile=p=>wait.length?Math.round(1000*wait[Math.max(0,Math.ceil(p*wait.length)-1)]*1000)/1000:null;
 return {seconds,rate,load,mode,burst,arrivals,dropped,remaining:q.length-head,slots,useful,maxQueue,p50ms:quantile(.5),p95ms:quantile(.95),p99ms:quantile(.99),coverGoDay:slots/seconds*168*2*86400/1e9,utilization:useful/slots,trace:Array.from(counts)};
}
