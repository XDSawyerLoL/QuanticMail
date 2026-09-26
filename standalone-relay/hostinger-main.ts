import { resolve } from "node:path";

import { hostingerRelayConfig } from "./hostinger-config.ts";
import { startRelayServer } from "./server.ts";
import { quanticMailAuraBridge } from "./aura-bridge.ts";

async function main(){
  const config=hostingerRelayConfig(process.env);
  const relay=await startRelayServer(config);
  console.log(`Quantic Relay Hostinger écoute sur ${relay.url} — persistance: PostgreSQL — endpoint public: ${config.publicEndpoint}`);
  quanticMailAuraBridge.startHeartbeat(config.publicEndpoint ?? relay.url);

  let shutdown: Promise<void>|null=null;
  const beginShutdown=()=>{
    if(!shutdown){
      shutdown=relay.close().catch((error:unknown)=>{
        console.error("Échec de l'arrêt propre de Quantic Relay Hostinger.",error);
        process.exitCode=1;
      });
    }
    return shutdown;
  };
  process.once("SIGINT",()=>{ void beginShutdown(); });
  process.once("SIGTERM",()=>{ void beginShutdown(); });
}

main().catch((error:unknown)=>{
  console.error("Impossible de démarrer Quantic Relay sur Hostinger.",error);
  process.exitCode=1;
});
