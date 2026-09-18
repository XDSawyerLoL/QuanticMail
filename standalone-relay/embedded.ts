import type { IncomingMessage, ServerResponse } from "node:http";

import { createDirectSignalingRequestHandler } from "./direct-signaling.ts";
import { bootstrapDiscoveryPeers } from "./discovery-bootstrap.ts";
import { createDiscoveryHandleRequestHandler } from "./discovery-handle-http.ts";
import { createDiscoveryRequestHandler } from "./discovery-http.ts";
import { createDiscoveryResolveRequestHandler } from "./discovery-resolve-http.ts";
import { retryPendingFederationReceipts } from "./federation-retry.ts";
import { createRelayRequestHandler } from "./http.ts";
import type { RelayIdentity } from "./identity.ts";
import { createCompatRegisterRequestHandler } from "./register-compat-http.ts";
import { RelayRuntime } from "./runtime.ts";
import type { RelayStateStore } from "./storage.ts";

export type EmbeddedRelayPersistence={
  stateStore:RelayStateStore;
  loadOrCreateIdentity():Promise<RelayIdentity>;
  close?():Promise<void>;
};

export type EmbeddedRelayOptions={
  persistence:EmbeddedRelayPersistence;
  publicEndpoint:string;
  bootstrapEndpoints?:string[];
};

export type EmbeddedRelay={
  relayId:string;
  handle(request:IncomingMessage,response:ServerResponse):Promise<boolean>;
  close():Promise<void>;
};

export async function createEmbeddedRelay(options:EmbeddedRelayOptions):Promise<EmbeddedRelay>{
  const publicEndpoint=options.publicEndpoint.trim();
  if(!publicEndpoint)throw new Error("Endpoint public Quantic Relay absent.");
  const url=new URL(publicEndpoint);
  if(url.protocol!=="https:"&&url.protocol!=="http:")throw new Error("Endpoint public Quantic Relay invalide.");

  const identity=await options.persistence.loadOrCreateIdentity();
  const runtime=new RelayRuntime(options.persistence.stateStore);
  await runtime.initialize();

  const compatRegisterHandler=createCompatRegisterRequestHandler(runtime);
  const directSignalingHandler=createDirectSignalingRequestHandler();
  const discoveryHandleHandler=createDiscoveryHandleRequestHandler(runtime);
  const discoveryResolveHandler=createDiscoveryResolveRequestHandler(runtime,identity.relayId);
  const discoveryHandler=createDiscoveryRequestHandler(runtime,{localRelayId:identity.relayId});
  const relayHandler=createRelayRequestHandler(runtime,{
    identity,
    getPublicEndpoint:()=>publicEndpoint,
  });

  await bootstrapDiscoveryPeers(
    runtime,
    identity.relayId,
    options.bootstrapEndpoints??[],
  );

  let retryTask:Promise<void>|null=null;
  const runRetry=()=>{
    if(retryTask)return retryTask;
    retryTask=retryPendingFederationReceipts(runtime)
      .catch(()=>undefined)
      .finally(()=>{retryTask=null;});
    return retryTask;
  };
  const retryTimer=setInterval(()=>{void runRetry();},1_000);
  retryTimer.unref();
  void runRetry();

  let closed=false;
  return {
    relayId:identity.relayId,
    async handle(request,response){
      const path=(request.url??"").split("?",1)[0]??"";
      if(!path.startsWith("/api/quantic/"))return false;
      if(await compatRegisterHandler(request,response))return true;
      if(await directSignalingHandler(request,response))return true;
      if(await discoveryHandleHandler(request,response))return true;
      if(await discoveryResolveHandler(request,response))return true;
      if(await discoveryHandler(request,response))return true;
      await relayHandler(request,response);
      return true;
    },
    async close(){
      if(closed)return;
      closed=true;
      clearInterval(retryTimer);
      if(retryTask)await retryTask;
      await runtime.flush();
      await options.persistence.close?.();
    },
  };
}
