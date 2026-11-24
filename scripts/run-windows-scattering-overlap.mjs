// Hidden GUI child: bounded control pipe, no secrets in arguments.
// EOF/cancel stops the schedule; no restart or automatic retry.
import {runWindowsOverlapSchedule} from '../desktop/native-windows-overlap-schedule.mjs';
const stop=new AbortController();
let control='',valid=true;
process.stdin.setEncoding('utf8');
process.stdin.on('data',chunk=>{
 control+=chunk;
 if(control.length>5||!('STOP\n'.startsWith(control))){valid=false;stop.abort();}
 else if(control==='STOP\n')stop.abort();
});
process.stdin.on('end',()=>stop.abort());
process.stdin.on('error',()=>{valid=false;stop.abort();});
try{
 const [binary,binarySha256,pacerSha256,dir,scheduleSha256]=process.argv.slice(2);
 if(process.platform!=='win32'||process.argv.length!==7||process.stdin.isTTY||process.versions.node.split('.')[0]!=='24')throw Error('Explicit Windows GUI pipe required');
 const result=await runWindowsOverlapSchedule({binary,binarySha256,pacerSha256,dir,scheduleSha256},{signal:stop.signal,onSlot:s=>{
  process.stdout.write(JSON.stringify({status:'scheduled-private-carrier-active',labOnly:true,...s})+'\n');
 }});
 if(!valid)throw Error('Invalid control input');
 process.stdout.write(JSON.stringify(result)+'\n');
}catch{
 process.stderr.write('Liaison Windows non confirmee. Conservez les sessions consommees; aucun renvoi automatique.\n');process.exitCode=1;
}finally{process.stdin.pause();}
