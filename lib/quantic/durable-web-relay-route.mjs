// Security boundary for the legacy Next.js Quantic routes.
// Durable stateful operations must all go to ONE explicitly configured
// standalone relay. Never fall back to process-local Map storage on failure.
// This is routing only: the destination service must own its PostgreSQL
// persistence, device authorization, rate limits, and revocation policy.
const ROUTES=new Set([
 '/api/quantic/challenge','/api/quantic/register','/api/quantic/resolve',
 '/api/quantic/manifest','/api/quantic/devices/register',
 '/api/quantic/devices/revoke','/api/quantic/prekeys/publish',
 '/api/quantic/prekeys/claim','/api/quantic/prekeys/status',
 '/api/quantic/send','/api/quantic/pull','/api/quantic/ack',
 '/api/quantic/receipts'
]);
const valid=(v)=>typeof v==='string'&&v.length>0&&v.length<=512;
function parseBackend(raw,ownOrigin){
 if(!valid(raw))return null;
 try{
  const url=new URL(raw);
  if(url.protocol!=='https:'||url.username||url.password||
    url.pathname!=='/'||url.search||url.hash||url.origin!==raw||
    url.origin===ownOrigin) return null;
  const host=url.hostname.toLowerCase();
  if(host==='localhost'||host.endsWith('.localhost')||
     host==='127.0.0.1'||host==='0.0.0.0'||host==='[::1]')return null;
  return url.origin;
 }catch{return null;}
}
export function decideQuanticDurableRoute(path,ownOrigin,backend,production=true){
 if(!ROUTES.has(path))return Object.freeze({kind:'unmanaged'});
 if(!production)return Object.freeze({kind:'legacy-dev'});
 const origin=parseBackend(backend,ownOrigin);
 if(!origin)return Object.freeze({kind:'refuse',reason:'durable-relay-not-configured'});
 return Object.freeze({kind:'durable',origin});
}
export function allowedRelayHeaders(requestHeaders){
 // Browser cookies, session grants, Host, forwarded IP, and origin headers
 // MUST NOT be delivered as privileged metadata to a different service.
 const headers=new Headers();
 for(const name of ['authorization','accept','content-type']){
  const value=requestHeaders.get(name);
  if(value!==null&&value.length<8192)headers.set(name,value);
 }
 headers.set('accept-encoding','identity');
 return headers;
}
export const STATEFUL_QUANTIC_PATHS=Object.freeze([...ROUTES]);
