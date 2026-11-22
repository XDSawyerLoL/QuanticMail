// Separate OS process to avoid in-process globalThis relay-state sharing.
// SYNTHETIC LOOPBACK TEST ONLY; no production credentials.
import {startRelayServer} from "../../standalone-relay/server.ts";
const dir=process.argv[2];
if(!dir||!process.env.QUANTIC_SYNTHETIC_OPERATOR_SECRET)throw Error("Synthetic fixture only");
const server=await startRelayServer({host:"127.0.0.1",port:0,dataDir:dir,
 migrationSnapshotLab:true,migrationLabOperatorSecret:process.env.QUANTIC_SYNTHETIC_OPERATOR_SECRET});
process.stdout.write(JSON.stringify({url:server.url,relayId:server.relayId})+"\n");
let closing=false;
function close(){
 if(closing)return;closing=true;
 server.close().then(()=>process.exit(0)).catch(()=>process.exit(1));
}
process.on("SIGTERM",close);
process.on("SIGINT",close);
