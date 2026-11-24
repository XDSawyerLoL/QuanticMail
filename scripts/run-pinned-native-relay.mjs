import {startPinnedNativeRelay} from '../standalone-relay/native-relay-operator.mjs';
let relay,stopRequested=false,closing;
function stop(){
 stopRequested=true;
 if(relay&&!closing)closing=relay.close().catch(()=>{process.stderr.write('Relay shutdown incomplete; preserve lock and durable state.\n');process.exitCode=1;});
}
for(const s of ['SIGINT','SIGTERM'])process.once(s,stop);
try{
 const [file,pin]=process.argv.slice(2);
 if(process.argv.length!==4||Number(process.versions.node.split('.')[0])<24)throw Error('Node 24 and independently pinned relay config required');
 relay=await startPinnedNativeRelay({file,pin});
 if(stopRequested){stop();await closing;}
 else process.stdout.write(JSON.stringify({status:'private-native-relay-listening',labOnly:true,listen:'127.0.0.1',port:relay.port,relayId:relay.relayId,remoteDeliveryVerified:false})+'\n');
}catch{process.stderr.write('Pinned private native relay refused. Do not remove the lock without reconciling state.\n');process.exitCode=1;}
