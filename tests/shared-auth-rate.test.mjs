import assert from "node:assert/strict";
import test from "node:test";
import { limitedAuthScope, rejectOverAuthBudget, createPostgresAuthRateLimiter } from "../standalone-relay/auth-rate-postgres.ts";

test("shared auth guard covers only six fixed POST scopes, including register compatibility path", () => {
  assert.equal(limitedAuthScope("POST","/api/quantic/register?foo=bar"),"/api/quantic/register");
  assert.equal(limitedAuthScope("POST","/api/quantic/challenge"),"/api/quantic/challenge");
  assert.equal(limitedAuthScope("GET","/api/quantic/register"),null);
  assert.equal(limitedAuthScope("POST","/api/quantic/send"),null);
  assert.equal(limitedAuthScope("POST","/api/quantic/__proto__"),null);
});
test("shared budget exhaustion or failure refuses the request", async () => {
  for (const status of [429,503]) {
    const headers=new Map();
    const response={statusCode:0,shouldKeepAlive:true,setHeader:(key,value)=>headers.set(key,value),end:()=>{}};
    const request={method:"POST",url:"/api/quantic/register"};
    assert.equal(await rejectOverAuthBudget(request,response,{async consume(){if(status===503)throw Error("database unavailable");return false;}}),true);
    assert.equal(response.statusCode,status);
    assert.equal(response.shouldKeepAlive,false);
    assert.equal(headers.get("Retry-After"),status===429?"60":"10");
  }
});
test("shared guard makes one atomic budget query and disallows arbitrary scopes", async () => {
  const calls=[];
  const limiter=await createPostgresAuthRateLimiter(async(sql,params)=>{calls.push([sql,params]);return {rows:params?[{attempts:1}]:[]};});
  assert.equal(await limiter.consume("/api/quantic/challenge"),true);
  assert.equal(calls.length,2);
  assert.deepEqual(calls[1][1],["/api/quantic/challenge",120]);
  await assert.rejects(limiter.consume("arbitrary"));
  assert.equal(calls.length,2);
});
test("actual PostgreSQL: two pools share one 120-request budget; restart cannot reset it", {skip:!process.env.QUANTIC_AUTH_RATE_TEST_DATABASE_URL}, async () => {
  const {Pool}=await import("pg");
  // This option must designate a disposable isolated test database.
  const a=new Pool({connectionString:process.env.QUANTIC_AUTH_RATE_TEST_DATABASE_URL,max:4});
  let b=new Pool({connectionString:process.env.QUANTIC_AUTH_RATE_TEST_DATABASE_URL,max:4});
  try {
    const x=await createPostgresAuthRateLimiter((s,p)=>a.query(s,p));
    let y=await createPostgresAuthRateLimiter((s,p)=>b.query(s,p));
    const {rows}=await a.query("SELECT extract(epoch FROM clock_timestamp()) % 60 AS seconds");
    if(Number(rows[0].seconds)>50)await new Promise(resolve=>setTimeout(resolve,11000));
    await a.query("DELETE FROM quantic_auth_rate_v1 WHERE scope = $1",["/api/quantic/challenge"]);
    const results=await Promise.all(Array.from({length:180},(_,i)=>(i%2?x:y).consume("/api/quantic/challenge")));
    assert.equal(results.filter(Boolean).length,120);
    await b.end();
    b=new Pool({connectionString:process.env.QUANTIC_AUTH_RATE_TEST_DATABASE_URL,max:4});
    y=await createPostgresAuthRateLimiter((s,p)=>b.query(s,p));
    assert.equal(await y.consume("/api/quantic/challenge"),false);
    assert.equal(await y.consume("/api/quantic/register"),true);
  } finally {await Promise.all([a.end(),b.end()]);}
});
