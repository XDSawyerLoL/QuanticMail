// One-way direct link laboratory operator. The only control channel is a
// private GUI pipe. No unattended automatic retry and no secret in argv.
import {startWindowsDirectMail} from '../desktop/native-windows-direct-mail.mjs';
import {setTimeout as delay} from 'node:timers/promises';
let host,stopped=false,busy=false,input='',fault=false;
const emit=o=>process.stdout.write(JSON.stringify(o)+'\n');
const stop=async()=>{stopped=true;if(host)await host.close();};
process.stdin.setEncoding('utf8');
process.stdin.on('end',()=>{void stop();});
process.stdin.on('error',()=>{fault=true;void stop();});
process.stdin.on('data',chunk=>{
 input+=chunk;
 if(input.length>256){fault=true;void stop();return;}
 let i;
 while((i=input.indexOf('\n'))>=0){
  const cmd=input.slice(0,i);input=input.slice(i+1);
  if(cmd==='STOP'){void stop();continue;}
  if(!host||stopped||busy||host.role!=='sender'||!/^SEND [a-f0-9]{32}$/.test(cmd)){fault=true;void stop();return;}
  busy=true;
  void (async()=>{
   try{
    const r=await host.send('wire-'+cmd.slice(5)+'.json');
    if(!stopped)emit({status:r.status,readVerified:false,noAutomaticRetry:true});
   }catch{if(!stopped)emit({status:'deposit-not-confirmed',noAutomaticRetry:true,readVerified:false});}
   finally{busy=false;}
  })();
 }
});
try{
 const [binary,binarySha256,pacerSha256,dir,planSha256]=process.argv.slice(2);
 if(process.platform!=='win32'||process.argv.length!==7||process.stdin.isTTY||process.versions.node.split('.')[0]!=='24')throw Error('Explicit Windows GUI pipe required');
 host=await startWindowsDirectMail({binary,binarySha256,pacerSha256,dir,planSha256});
 if(stopped){await host.close();throw Error('Stopped');}
 emit({status:'direct-listening',role:host.role,hostedRelay:false});
 if(host.role==='sender')emit({status:'outgoing',items:await host.listOutgoing()});
 let seen=false;
 const closed=host.closed.then(r=>{stopped=true;return r;});
 while(!stopped){
  if(!seen&&host.authenticatedPeerSeen()){seen=true;emit({status:'direct-peer-cells-observed',remoteDeliveryVerified:false});}
  await delay(200);
 }
 const result=await closed;
 if(fault||result.failed)throw Error('Direct link failed');
 emit({status:'stopped'});
}catch{process.stderr.write('Liaison directe non confirmee. Conservez les messages originaux. Aucun renvoi automatique.\n');process.exitCode=1;}
finally{await host?.close();process.stdin.pause();}
