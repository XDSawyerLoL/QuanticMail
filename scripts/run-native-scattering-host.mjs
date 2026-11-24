// One pinned private-network carrier host. No automatic restart on a used
// epoch. Use an independently prepared fresh epoch on both participants.
import {loadPrivateCarrierPlan,startPrivateCarrierHost} from '../standalone-relay/native-scattering-host.mjs';
let host,stopping=false;
const stop=()=>{stopping=true;if(host)void host.close();};
for(const signal of ['SIGINT','SIGTERM'])process.once(signal,stop);
try{
 const [file,pin]=process.argv.slice(2);
 if(process.argv.length!==4)throw Error('Explicit plan and independent digest required');
 const plan=await loadPrivateCarrierPlan(file,pin);
 if(stopping)throw Error('Stopped before starting');
 host=await startPrivateCarrierHost(plan);
 // Delete credential strings from the local object when no longer required.
 delete plan.carrier.secretHex;delete plan.carrier.epochHex;
 if(stopping)void host.close();
 else process.stdout.write(JSON.stringify({status:'private-carrier-processes-started',labOnly:true,
  role:host.role,httpPort:host.httpPort,recvPort:host.recvPort,listenIP:host.listenIP,listenPort:host.listenPort,
  remoteTransportVerified:false})+'\n');
 const result=await host.closed;
 if(result.failed){process.stderr.write('Carrier stopped; preserve its state and use a newly coordinated epoch. No automatic retry.\n');process.exitCode=1;}
}catch{process.stderr.write('Private carrier startup refused. Preserve any consumed epoch and files.\n');process.exitCode=1;}
finally{await host?.close();}
