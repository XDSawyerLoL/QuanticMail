import {cookies} from "next/headers";
import {Pool} from "pg";
import {createSessionStore, type MailSession} from "./session-store";
export type {MailSession};
const COOKIE_NAME="qm_session_v2";
const LEGACY_COOKIE="qm_session";
const MAX_AGE_SECONDS=8*60*60;
let pending:ReturnType<typeof createSessionStore>|undefined;
function sessionStore() {
  if(!pending) {
    const connectionString=process.env.QUANTIC_MAIL_SESSION_DATABASE_URL?.trim();
    const secret=process.env.SESSION_SECRET;
    if(!connectionString||!secret||secret.length<32)throw new Error("Mail session authority not configured");
    const pool=new Pool({connectionString,max:5,connectionTimeoutMillis:3000,statement_timeout:5000});
    // A storage outage never falls back to a locally accepted cookie.
    pool.on("error",()=>{});
    pending=createSessionStore((sql,params)=>pool.query(sql,params),secret).catch(async error=>{
      pending=undefined;await pool.end();throw error;
    });
  }
  return pending;
}
const options={httpOnly:true,secure:process.env.NODE_ENV==="production",sameSite:"strict" as const,path:"/"};
export async function createSession(email:string,authorization:string) {
  const cookiesStore=await cookies();
  const token=await (await sessionStore()).create(email,authorization,cookiesStore.get(COOKIE_NAME)?.value);
  cookiesStore.set(COOKIE_NAME,token,{...options,maxAge:MAX_AGE_SECONDS});
  cookiesStore.set(LEGACY_COOKIE,"",{...options,maxAge:0});
}
export async function readSession():Promise<MailSession|null> {
  const token=(await cookies()).get(COOKIE_NAME)?.value;
  if(!token||!/^[A-Za-z0-9_-]{43}$/.test(token))return null;
  return (await sessionStore()).read(token);
}
export async function destroySession() {
  const cookiesStore=await cookies();
  const token=cookiesStore.get(COOKIE_NAME)?.value;
  if(token&&/^[A-Za-z0-9_-]{43}$/.test(token))await (await sessionStore()).revoke(token);
  cookiesStore.set(COOKIE_NAME,"",{...options,maxAge:0});
  cookiesStore.set(LEGACY_COOKIE,"",{...options,maxAge:0});
}
