import {NextResponse} from "next/server";
import type {NextRequest} from "next/server";
import {corsOrigin} from "./lib/security/cors-origin";
import {allowedRelayHeaders,decideQuanticDurableRoute} from "./lib/quantic/durable-web-relay-route.mjs";

// No process-local memory fallback when a durable backend is unavailable.
export function proxy(request:NextRequest) {
  const origin=request.headers.get("origin");
  const allowed=corsOrigin(origin,request.nextUrl.origin,process.env.QUANTIC_TRUSTED_ORIGINS??"");
  const noStore={"Vary":"Origin","Cache-Control":"no-store"};
  if(origin && !allowed)return NextResponse.json({error:"Origine non autorisée."},{status:403,headers:noStore});
  const preflight=request.method==="OPTIONS";
  const state=decideQuanticDurableRoute(
    request.nextUrl.pathname,request.nextUrl.origin,
    process.env.QUANTIC_WEB_DURABLE_RELAY_ORIGIN,
    process.env.NODE_ENV==="production"
  );
  if(!preflight && state.kind==="refuse"){
    return NextResponse.json({error:"Relais durable indisponible. Aucune identité ou message enregistré en mémoire."},
      {status:503,headers:{...noStore,"Retry-After":"30"}});
  }
  if(!preflight && state.kind==="durable"){
    const length=request.headers.get("content-length");
    if(length!==null && (!/^(0|[1-9][0-9]*)$/.test(length)||Number(length)>512*1024)){
      return NextResponse.json({error:"Requête Quantic trop volumineuse."},
        {status:413,headers:noStore});
    }
    const url=new URL(request.nextUrl.pathname+request.nextUrl.search,state.origin);
    const headers=allowedRelayHeaders(request.headers);
    const result=NextResponse.rewrite(url,{request:{headers}});
    result.headers.set("Vary","Origin");
    result.headers.set("Cache-Control","no-store");
    return result;
  }
  const response=preflight?new NextResponse(null,{status:204}):NextResponse.next();
  response.headers.append("Vary","Origin");
  response.headers.set("Cache-Control","no-store");
  if(allowed){
    response.headers.set("Access-Control-Allow-Origin",allowed);
    response.headers.set("Access-Control-Allow-Methods","GET, POST, OPTIONS");
    response.headers.set("Access-Control-Allow-Headers","Content-Type, Authorization");
    response.headers.set("Access-Control-Max-Age","600");
  }
  return response;
}
export const config={matcher:"/api/quantic/:path*"};
