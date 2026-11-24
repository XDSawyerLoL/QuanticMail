// Aggregate independent, synthetic network-laboratory runs.
// These descriptive summaries are NOT confidence intervals or anonymity proofs.
import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
const check=(ok,why)=>{if(!ok)throw Error(why)};
const round=x=>+x.toFixed(6);
const finite=x=>typeof x==='number'&&Number.isFinite(x);
export function summarizeRepeatedRuns(runs,{batchSize,bReal,minRuns=5}){
 check([0,8,20,40].includes(batchSize)&&[20,100].includes(bReal)&&
   Number.isInteger(minRuns)&&minRuns>=2&&minRuns<=30&&
   Array.isArray(runs)&&runs.length===minRuns,'unexpected repeat count/profile');
 const n=100+bReal;
 const rows=runs.map((r,index)=>{
  check(r.releaseReady===false&&r.sharedHostFileSystemAccess===true&&
   r.sourceBRealMessagesRequested===bReal&&
   r.batchSizeRequested===(batchSize||null)&&
   r.native?.planned===550&&r.native?.sent===550&&r.native?.missed===0&&
   r.receiver?.authenticatedE2E===n&&r.receiver?.perSender?.A===100&&
   r.receiver?.perSender?.B===bReal&&r.receiver?.replays===0&&
   r.x?.egress?.matchedUnique===0&&finite(r.measuredFirstSourceOffsetMs),
   'incomplete or mismatched repeat '+(index+1));
  const obs=r.timeOnlyObserver;
  check(obs?.attackerKeysProvided===false&&obs.oracleKeysUsedForScoringOnly===true&&
   obs.truth?.A===100&&obs.truth?.B===bReal,'missing independent truth');
  const delay=obs.authenticatedMessageDelayMs;
  check(delay?.count===n&&delay.truthKeysNeverGivenToAttacker===true&&
   [delay.p50,delay.p95,delay.max].every(finite)&&0<=delay.p50&&
   delay.p50<=delay.p95&&delay.p95<=delay.max,'invalid delay evidence');
  const attacks=obs.fifoQueueTimingAttack?.scenarios;
  check(Array.isArray(attacks)&&attacks.length===3&&
    attacks.map(a=>a.processingSlackMs).join(',')==='0,5,12','missing prespecified attacks');
  const scored=attacks.map(a=>{
   const d=a.data,c=a.cover,m=a.confusion;
   const rowTotal=k=>m[k].A+m[k].B+m[k].abstain;
   check(m&&['A','B','cover'].every(k=>m[k]&&['A','B','abstain'].every(g=>
      Number.isSafeInteger(m[k][g])&&m[k][g]>=0)),
      'missing or invalid confusion matrix');
   check(rowTotal('A')===100&&rowTotal('B')===bReal&&rowTotal('cover')===550-n&&
    d.total===n&&d.correct===m.A.A+m.B.B&&d.wrong===m.A.B+m.B.A&&
    d.noGuess===m.A.abstain+m.B.abstain&&
    c.total===550-n&&c.wronglyGuessedAsData===m.cover.A+m.cover.B,
    'inconsistent attribution counts');
   const guessCount=d.correct+d.wrong;
   return {slackMs:a.processingSlackMs,
    trueDataCorrectFraction:round(d.correct/n),
    conditionalPrecision:guessCount?round(d.correct/guessCount):null,
    guessedDataFraction:round(guessCount/n),
    balancedRecall:round((m.A.A/100+m.B.B/bReal)/2),
    minorityRecall:round(m.B.B/bReal),
    coverFalseFraction:round(c.wronglyGuessedAsData/c.total)};
  });
  return {run:index+1,requestedOffsetMs:r.sourceOffsetRequestedMs,
   measuredOffsetMs:r.measuredFirstSourceOffsetMs,p95Ms:delay.p95,
   maxMs:delay.max,authenticated:n,attacks:scored};
 });
 const offsets=rows.map(r=>r.requestedOffsetMs);
 check(offsets.includes(0)&&offsets.includes(25)&&offsets.every(x=>x===0||x===25),
  'require both prespecified source offsets');
 const attacks=rows.flatMap(r=>r.attacks);
 const p95s=rows.map(r=>r.p95Ms).sort((a,b)=>a-b);
 const max=k=>Math.max(...attacks.map(a=>a[k]??0));
 const worstBalancedRecall=max('balancedRecall');
 const substantial=attacks.filter(a=>a.guessedDataFraction>=.5&&a.conditionalPrecision!==null);
 const worstConditionalPrecision=substantial.length?Math.max(...substantial.map(a=>a.conditionalPrecision)):null;
 // Research screen only, not a statistical test: compare against an explicit
 // reference and use the worst run, not an average which can hide leakage.
 const majorityBaseline=100/n;
 const privacyScreen=worstBalancedRecall<=.60&&
   (worstConditionalPrecision===null||worstConditionalPrecision<=majorityBaseline+.10);
 const latencyScreen=Math.max(...p95s)<=500;
 return {experiment:'repeated isolated virtual network lab',batchSize,bReal,
  runs:rows.length,authenticatedTotal:rows.reduce((n,r)=>n+r.authenticated,0),
  majorityBaseline:round(majorityBaseline),balancedBaseline:.5,
  latency:{medianRunP95Ms:p95s[Math.floor(p95s.length/2)],worstRunP95Ms:Math.max(...p95s)},
  worstAttack:{balancedRecall:worstBalancedRecall,
   minorityRecall:max('minorityRecall'),correctFraction:max('trueDataCorrectFraction'),
   conditionalPrecisionAtLeastHalfGuessed:worstConditionalPrecision,
   maxCoverFalseFraction:max('coverFalseFraction')},
  screening:{privacy:privacyScreen,latency:latencyScreen,
    candidate:batchSize!==0&&privacyScreen&&latencyScreen,
    releaseAuthorized:false,criteria:'descriptive research thresholds only: worst balanced recall <= .60, conditional precision <= majority+.10 at >=50% guessed, worst run p95 <=500ms'},
  evidenceLimit:'One physical host; repeated short runs, not independent WAN trials; only prespecified FIFO timing attack. No statistical security claim.',
  rows};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 const [batch,b,expected,...paths]=process.argv.slice(2);
 try{console.log(JSON.stringify(summarizeRepeatedRuns(paths.map(p=>JSON.parse(readFileSync(p,'utf8'))),
  {batchSize:Number(batch),bReal:Number(b),minRuns:Number(expected)}),null,2));}
 catch(e){console.error(e.message);process.exitCode=1;}
}
