// One-shot two-device UDP diagnostic. No Quantic keys or production email.
// The temporary pairing code is never passed as a command-line argument.
import {startTwoHostReceiver,runTwoHostSender} from '../desktop/native-two-host-network-lab.mjs';
const refuse=x=>{if(!x)throw Error('Synthetic two-host test refused');};
try{
 const a=process.argv.slice(2);
 refuse((a[0]==='receive'&&a.length===3)||(a[0]==='send'&&a.length===4));
 const port=Number(a[a[0]==='receive'?1:2]);
 const seconds=Number(a[a[0]==='receive'?2:3]);
 if(a[0]==='receive'){
  const r=await startTwoHostReceiver({port,seconds});
  process.stdout.write(JSON.stringify({status:r.status,code:r.code,port:r.port,realMailProven:false})+'\n');
  process.stdout.write(JSON.stringify(await r.wait)+'\n');
 }else{
  refuse(!process.stdin.isTTY);
  let bytes=0;const chunks=[];
  for await(const b of process.stdin){
   bytes+=b.length;
   refuse(bytes<=64);
   chunks.push(b);
  }
  const raw=Buffer.concat(chunks);
  for(const chunk of chunks)chunk.fill(0);
  let code;try{code=raw.toString('ascii').trim();}finally{raw.fill(0);}
  process.stdout.write(JSON.stringify(await runTwoHostSender({host:a[1],port,seconds,code}))+'\n');
 }
}catch{
 process.stderr.write('Test reseau authentifie REFUSE. Aucun courrier ni secret de coffre traite.\n');
 process.exitCode=1;
}
