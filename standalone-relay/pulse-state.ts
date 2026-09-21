import { timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";

type PulseRow={value?:unknown;revision?:number|string};
type QueryResult={rows:PulseRow[]};

const PATH="/api/quantic/internal/pulse-state";
const MAX_BODY_BYTES=6*1024*1024;

function bearer(request:IncomingMessage){
  const match=String(request.headers.authorization??"").match(/^Bearer\s+(.+)$/i);
  return match?.[1]??"";
}
function sameSecret(expected:string,actual:string){
  const a=Buffer.from(expected),b=Buffer.from(actual);
  return a.length===b.length&&timingSafeEqual(a,b);
}
function json(response:ServerResponse,status:number,body:unknown){
  response.statusCode=status;
  response.setHeader("content-type","application/json; charset=utf-8");
  response.setHeader("cache-control","no-store");
  response.end(JSON.stringify(body));
}
async function readJson(request:IncomingMessage){
  const chunks:Buffer[]=[];
  let size=0;
  for await(const chunk of request){
    const buffer=Buffer.isBuffer(chunk)?chunk:Buffer.from(chunk);
    size+=buffer.length;
    if(size>MAX_BODY_BYTES)throw Object.assign(new Error("payload_too_large"),{status:413});
    chunks.push(buffer);
  }
  if(!chunks.length)return{};
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string,unknown>;
}

export async function createPulseStateRequestHandler(databaseUrl:string,token:string){
  const secret=String(token||"").trim();
  if(!databaseUrl.trim()||secret.length<32)return null;
  const {Pool}=await import("pg");
  const pool=new Pool({
    connectionString:databaseUrl,
    max:3,
    idleTimeoutMillis:30_000,
    connectionTimeoutMillis:10_000,
  });
  await pool.query(`
    CREATE TABLE IF NOT EXISTS quantic_pulse_state (
      state_key TEXT PRIMARY KEY,
      value JSONB NOT NULL,
      revision BIGINT NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(
    "INSERT INTO quantic_pulse_state (state_key,value,revision) VALUES ($1,$2::jsonb,0) ON CONFLICT (state_key) DO NOTHING",
    ["pulse",JSON.stringify({version:3,users:{},handles:{},sessions:{},posts:{},follows:{},likes:{},reposts:{},bookmarks:{},circles:{},circleMembers:{},notifications:{},reports:{},blocks:{},conversations:{},messages:{},secureDevices:{},securePreKeys:{},securePreKeyUsed:{}})]
  );

  const handler=async(request:IncomingMessage,response:ServerResponse)=>{
    const url=new URL(request.url??"/","http://quantic-relay.local");
    if(url.pathname!==PATH)return false;
    if(!sameSecret(secret,bearer(request))){
      json(response,401,{error:"unauthorized"});
      return true;
    }
    if(request.method==="GET"){
      const result=await pool.query<QueryResult["rows"][number]>(
        "SELECT value,revision FROM quantic_pulse_state WHERE state_key=$1",
        ["pulse"]
      );
      const row=result.rows[0];
      json(response,200,{payload:row?.value??null,revision:Number(row?.revision??0)});
      return true;
    }
    if(request.method==="PUT"){
      let body:Record<string,unknown>;
      try{body=await readJson(request)}
      catch(error){
        json(response,Number((error as {status?:number})?.status||400),{error:"invalid_json"});
        return true;
      }
      const expectedRevision=Number(body.expectedRevision);
      if(!Number.isSafeInteger(expectedRevision)||expectedRevision<0||!body.payload||typeof body.payload!=="object"||Array.isArray(body.payload)){
        json(response,400,{error:"invalid_state_write"});
        return true;
      }
      const client=await pool.connect();
      try{
        await client.query("BEGIN");
        const current=await client.query("SELECT revision FROM quantic_pulse_state WHERE state_key=$1 FOR UPDATE",["pulse"]);
        const revision=Number(current.rows[0]?.revision??0);
        if(revision!==expectedRevision){
          await client.query("ROLLBACK");
          json(response,409,{error:"revision_conflict",revision});
          return true;
        }
        const updated=await client.query(
          `UPDATE quantic_pulse_state
           SET value=$2::jsonb,revision=revision+1,updated_at=NOW()
           WHERE state_key=$1 AND revision=$3
           RETURNING revision,updated_at`,
          ["pulse",JSON.stringify(body.payload),expectedRevision]
        );
        if(!updated.rows.length){
          await client.query("ROLLBACK");
          json(response,409,{error:"revision_conflict"});
          return true;
        }
        await client.query("COMMIT");
        json(response,200,{ok:true,revision:Number(updated.rows[0].revision),updatedAt:updated.rows[0].updated_at});
        return true;
      }catch(error){
        await client.query("ROLLBACK").catch(()=>undefined);
        throw error;
      }finally{client.release()}
    }
    response.setHeader("allow","GET, PUT");
    json(response,405,{error:"method_not_allowed"});
    return true;
  };

  return{
    handler,
    async close(){await pool.end()}
  };
}
