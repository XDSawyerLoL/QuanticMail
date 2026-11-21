import {NextResponse} from "next/server";
import type {NextRequest} from "next/server";
import {corsOrigin} from "./lib/security/cors-origin";
export function proxy(request:NextRequest) {
  const origin=request.headers.get("origin");
  const allowed=corsOrigin(origin,request.nextUrl.origin,process.env.QUANTIC_TRUSTED_ORIGINS??"");
  if(origin && !allowed) return NextResponse.json({error:"Origine non autorisée."},{status:403,headers:{"Vary":"Origin","Cache-Control":"no-store"}});
  const response=request.method==="OPTIONS"?new NextResponse(null,{status:204}):NextResponse.next();
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
