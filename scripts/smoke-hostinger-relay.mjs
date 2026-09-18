const base=(process.argv[2]||process.env.QUANTIC_RELAY_URL||"").replace(/\/$/,"");
if(!base) throw new Error("Usage: npm run relay:smoke -- https://relay.example.com");
const response=await fetch(`${base}/api/quantic/health`,{headers:{"accept":"application/json"}});
if(!response.ok) throw new Error(`Healthcheck HTTP ${response.status}`);
const payload=await response.json();
if(payload?.ok!==true||payload?.protocol!=="quantic-relay/1"||typeof payload?.relayId!=="string"){
  throw new Error(`Réponse Quantic Relay invalide: ${JSON.stringify(payload)}`);
}
console.log(JSON.stringify({ok:true,url:base,relayId:payload.relayId,protocol:payload.protocol,federation:payload.federation||null}));
