import test from "node:test";
import assert from "node:assert/strict";
import {corsOrigin} from "../lib/security/cors-origin.ts";
import {createSessionStore} from "../lib/auth/session-store.ts";
const url=process.env.QUANTIC_AUTH_RATE_TEST_DATABASE_URL;
test("exact origins, no wildcard or opaque origins",()=>{
 const own="https://mail.example",config="https://swapp.tv, https://other.example";
 for(const value of ["null","https://swapp.tv.evil.example","http://swapp.tv","https://swapp.tv/path","https://user@swapp.tv","*"])assert.equal(corsOrigin(value,own,config),null);
 assert.equal(corsOrigin("https://swapp.tv",own,config),"https://swapp.tv");
 assert.equal(corsOrigin(own,own,config),own);
 assert.equal(corsOrigin(null,own,config),null);
});
test("shared mail sessions revoke across pools, reject swapped ciphertext and expire",{skip:!url},async()=>{
 const {Pool}=await import("pg");
 const a=new Pool({connectionString:url}),b=new Pool({connectionString:url});
 try{
 const secret="test-secret-only-012345678901234567890";
 const s=await createSessionStore((q,p)=>a.query(q,p),secret),t=await createSessionStore((q,p)=>b.query(q,p),secret);
 const token=await s.create("test@example.invalid","Basic TEST_ONLY"), other=await s.create("other@example.invalid","Basic OTHER_TEST");
 assert.equal((await t.read(token)).authorization,"Basic TEST_ONLY");
 const rows=await a.query("SELECT token_hash,sealed FROM quantic_mail_session_v2");
 assert.ok(rows.rows.every(r=>r.token_hash!==token&&!r.sealed.includes("TEST_ONLY")));
 const {createHash}=await import("node:crypto");
 const hash=x=>createHash("sha256").update("quantic-mail-session-v2:"+x).digest("hex");
 await a.query("UPDATE quantic_mail_session_v2 SET sealed=(SELECT sealed FROM quantic_mail_session_v2 WHERE token_hash=$2) WHERE token_hash=$1",[hash(other),hash(token)]);
 assert.equal(await t.read(other),null);
 await t.revoke(token);assert.equal(await s.read(token),null);
 const fresh=await s.create("test@example.invalid","Basic TEST_ONLY");
 const rotated=await t.create("test@example.invalid","Basic NEW",fresh);
 assert.equal(await s.read(fresh),null);
 await a.query("UPDATE quantic_mail_session_v2 SET expires_at=clock_timestamp()-interval '1 second' WHERE token_hash=$1",[hash(rotated)]);
 assert.equal(await t.read(rotated),null);
 assert.equal(await t.read("legacy-cookie"),null);
 await b.end();await assert.rejects(t.read(rotated));
 }finally{await a.end();if(!b.ended)await b.end();}
});
