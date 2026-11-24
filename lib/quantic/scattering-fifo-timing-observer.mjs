// Passive global observer: reconstruct a FIFO queue from timestamps alone.
// The relay is ASSUMED FIFO. Neither source IDs of output cells nor keys,
// payload bytes, and plaintext are supplied to the attacker.
const check=(condition,msg)=>{if(!condition)throw Error(msg)};
function valid(times){
 return Array.isArray(times)&&times.length<=100000&&times.every((v,i)=>
  Number.isFinite(v)&&(i===0||v>=times[i-1]));
}
export function reconstructFifoTiming({sourceATimes,sourceBTimes,egressTimes,processingSlackMs=5}){
 check(valid(sourceATimes)&&valid(sourceBTimes)&&valid(egressTimes)&&
  Number.isFinite(processingSlackMs)&&processingSlackMs>=0&&processingSlackMs<=40,
  'invalid monotonic FIFO timing trace');
 const entrants=[
  ...sourceATimes.map((time,i)=>({time,source:'A',order:i})),
  ...sourceBTimes.map((time,i)=>({time,source:'B',order:i})),
 ].sort((a,b)=>a.time-b.time||a.source.localeCompare(b.source)||a.order-b.order);
 const guesses=[];
 let next=0,read=0;
 const queue=[];
 for(const time of egressTimes){
  while(next<entrants.length&&entrants[next].time<=time-processingSlackMs)
   queue.push(entrants[next++]);
  guesses.push(read<queue.length?queue[read++].source:null);
 }
 return {guesses,mode:'observed-global-FIFO-queue',processingSlackMs,
  ingressObserved:entrants.length,egressObserved:egressTimes.length,
  predictedCover:guesses.filter(v=>v===null).length,
  residualQueue:queue.length-read};
}
export function scoreAttributionGuesses(guesses,truth){
 check(Array.isArray(guesses)&&Array.isArray(truth)&&guesses.length===truth.length&&
   truth.length>0&&guesses.every(x=>x===null||x==='A'||x==='B')&&
   truth.every(x=>x===null||x==='A'||x==='B'),'invalid prediction scoring');
 let correct=0,wrong=0,noGuess=0,data=0,cover=0,coverFalse=0;
 const sources={A:0,B:0};
 for(let i=0;i<truth.length;i++){
  const actual=truth[i],guess=guesses[i];
  if(actual===null){cover++;if(guess!==null)coverFalse++;continue;}
  data++;sources[actual]++;
  if(guess===null)noGuess++;
  else if(guess===actual)correct++;
  else wrong++;
 }
 check(data>0&&sources.A>0&&sources.B>0,'both data source labels required');
 const rate=(n,d)=>d?+(n/d).toFixed(6):null;
 return {data:{total:data,correct,wrong,noGuess,
   accuracyOverAll:rate(correct,data),
   accuracyOnGuessed:rate(correct,correct+wrong),
   recall:rate(correct,data),
   majorityBaseline:rate(Math.max(sources.A,sources.B),data)},
  cover:{total:cover,wronglyGuessedAsData:coverFalse,
   falseSourceAttributionRate:rate(coverFalse,cover)},
  groundTruth:{A:sources.A,B:sources.B}};
}
