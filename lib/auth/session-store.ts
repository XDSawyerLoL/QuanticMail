import {createHash, randomBytes, createCipheriv, createDecipheriv} from "node:crypto";
export type MailSession = {email:string; authorization:string; expiresAt:number};
type Query = (sql:string, params?:unknown[])=>Promise<{rows:Record<string,unknown>[]}>;
const TTL = 8*60*60;
const validToken = (token:string)=>/^[A-Za-z0-9_-]{43}$/.test(token);
const digest = (token:string)=>createHash("sha256").update("quantic-mail-session-v2:"+token).digest("hex");
export async function createSessionStore(query:Query, secret:string) {
  if (typeof secret !== "string" || secret.length < 32) throw new Error("SESSION_SECRET must contain at least 32 characters");
  const key=createHash("sha256").update("quantic-mail-session-encryption-v2\0"+secret).digest();
  await query(`CREATE TABLE IF NOT EXISTS quantic_mail_session_v2 (
    token_hash TEXT PRIMARY KEY, sealed TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL
  )`);
  await query("CREATE INDEX IF NOT EXISTS quantic_mail_session_v2_exp ON quantic_mail_session_v2(expires_at)");
  function seal(hash:string, value:{email:string;authorization:string}) {
    const iv=randomBytes(12);
    const cipher=createCipheriv("aes-256-gcm",key,iv);
    cipher.setAAD(Buffer.from(hash));
    const enc=Buffer.concat([cipher.update(JSON.stringify(value),"utf8"),cipher.final()]);
    return Buffer.concat([iv,cipher.getAuthTag(),enc]).toString("base64url");
  }
  function unseal(hash:string, value:string) {
    const raw=Buffer.from(value,"base64url");
    if(raw.length<29 || raw.length>16384)throw new Error("Invalid stored session");
    const cipher=createDecipheriv("aes-256-gcm",key,raw.subarray(0,12));
    cipher.setAAD(Buffer.from(hash));cipher.setAuthTag(raw.subarray(12,28));
    return JSON.parse(Buffer.concat([cipher.update(raw.subarray(28)),cipher.final()]).toString("utf8"));
  }
  return {
    async create(email:string, authorization:string, previous?:string) {
      if(!email || email.length>320 || !authorization || authorization.length>8192)throw new Error("Invalid session");
      const token=randomBytes(32).toString("base64url"),hash=digest(token);
      // Revoke previous token before issuing another. Failure never grants a session.
      if(previous && validToken(previous))await query("DELETE FROM quantic_mail_session_v2 WHERE token_hash=$1",[digest(previous)]);
      await query("DELETE FROM quantic_mail_session_v2 WHERE token_hash IN (SELECT token_hash FROM quantic_mail_session_v2 WHERE expires_at<=clock_timestamp() LIMIT 1000)");
      await query("INSERT INTO quantic_mail_session_v2(token_hash,sealed,expires_at) VALUES($1,$2,clock_timestamp()+$3*interval '1 second')",[hash,seal(hash,{email,authorization}),TTL]);
      return token;
    },
    async read(token:string):Promise<MailSession|null> {
      if(!validToken(token))return null;
      const hash=digest(token);
      const result=await query("SELECT sealed, extract(epoch FROM expires_at)*1000 AS expires_ms FROM quantic_mail_session_v2 WHERE token_hash=$1 AND expires_at>clock_timestamp()",[hash]);
      if(result.rows.length!==1)return null;
      const row=result.rows[0];
      try {
        const value=unseal(hash,String(row.sealed));
        const expiresAt=Number(row.expires_ms);
        if(!Number.isFinite(expiresAt)||typeof value.email!=="string"||typeof value.authorization!=="string")return null;
        return {email:value.email,authorization:value.authorization,expiresAt};
      } catch {return null;}
    },
    async revoke(token:string) {
      if(validToken(token)) await query("DELETE FROM quantic_mail_session_v2 WHERE token_hash=$1",[digest(token)]);
    }
  };
}
