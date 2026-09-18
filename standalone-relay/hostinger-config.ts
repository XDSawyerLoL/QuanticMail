import { parseRelayBootstrap } from "./discovery-bootstrap.ts";
type RelayEnv = Record<string,string|undefined>;

function parsePort(value:string){
  const port=Number(value);
  if(!Number.isInteger(port)||port<1||port>65535) throw new Error("Le port Quantic Relay doit être un entier entre 1 et 65535.");
  return port;
}

function required(env: RelayEnv,key: string){
  const value=env[key]?.trim();
  if(!value) throw new Error(`${key} est requis pour le relais Hostinger.`);
  return value;
}

export function hostingerRelayConfig(env: RelayEnv=process.env){
  const databaseUrl=required(env,"QUANTIC_RELAY_DATABASE_URL");
  if(!/^postgres(?:ql)?:\/\//i.test(databaseUrl)){
    throw new Error("QUANTIC_RELAY_DATABASE_URL doit être une URL PostgreSQL.");
  }

  const identitySecret=required(env,"QUANTIC_RELAY_IDENTITY_SECRET");
  if(identitySecret.length<32){
    throw new Error("QUANTIC_RELAY_IDENTITY_SECRET doit contenir au moins 32 caractères.");
  }

  const publicEndpoint=required(env,"QUANTIC_RELAY_PUBLIC_ENDPOINT");
  let endpoint: URL;
  try{ endpoint=new URL(publicEndpoint); }
  catch{ throw new Error("QUANTIC_RELAY_PUBLIC_ENDPOINT invalide."); }
  if(endpoint.protocol!=="https:"){
    throw new Error("QUANTIC_RELAY_PUBLIC_ENDPOINT doit utiliser HTTPS.");
  }

  const bootstrapEndpoints=parseRelayBootstrap(required(env,"QUANTIC_RELAY_BOOTSTRAP"));
  if(!bootstrapEndpoints.length){
    throw new Error("QUANTIC_RELAY_BOOTSTRAP doit contenir au moins un relais HTTPS.");
  }
  for(const value of bootstrapEndpoints){
    let parsed: URL;
    try{ parsed=new URL(value); }
    catch{ throw new Error("QUANTIC_RELAY_BOOTSTRAP contient une URL invalide."); }
    if(parsed.protocol!=="https:"){
      throw new Error("QUANTIC_RELAY_BOOTSTRAP doit utiliser uniquement HTTPS en production.");
    }
  }

  return {
    host:"0.0.0.0",
    port:parsePort(env.PORT ?? env.QUANTIC_RELAY_PORT ?? "8787"),
    dataDir:env.QUANTIC_RELAY_DATA_DIR ?? "./data",
    databaseUrl,
    identitySecret,
    publicEndpoint,
    bootstrapEndpoints,
  };
}
