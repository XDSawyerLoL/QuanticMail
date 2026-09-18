import test from "node:test";
import assert from "node:assert/strict";
import { hostingerRelayConfig } from "../standalone-relay/hostinger-config.ts";

const base: Record<string,string>={
  PORT:"8080",
  QUANTIC_RELAY_DATABASE_URL:"postgresql://user:pass@example.invalid/db",
  QUANTIC_RELAY_IDENTITY_SECRET:"x".repeat(48),
  QUANTIC_RELAY_PUBLIC_ENDPOINT:"https://relay.example.com",
  QUANTIC_RELAY_BOOTSTRAP:"https://quanticmail-network-relay.onrender.com,https://quantic-network-relay-backup-production.up.railway.app",
};

test("Hostinger relay config binds publicly and requires durable production inputs",()=>{
  const cfg=hostingerRelayConfig(base);
  assert.equal(cfg.host,"0.0.0.0");
  assert.equal(cfg.port,8080);
  assert.equal(cfg.databaseUrl,base.QUANTIC_RELAY_DATABASE_URL);
  assert.equal(cfg.identitySecret,base.QUANTIC_RELAY_IDENTITY_SECRET);
  assert.equal(cfg.publicEndpoint,base.QUANTIC_RELAY_PUBLIC_ENDPOINT);
  assert.deepEqual(cfg.bootstrapEndpoints,[
    "https://quanticmail-network-relay.onrender.com",
    "https://quantic-network-relay-backup-production.up.railway.app",
  ]);
});

test("Hostinger relay refuses missing PostgreSQL persistence",()=>{
  const env={...base};
  delete env.QUANTIC_RELAY_DATABASE_URL;
  assert.throws(()=>hostingerRelayConfig(env),/QUANTIC_RELAY_DATABASE_URL/);
});

test("Hostinger relay refuses weak identity secrets",()=>{
  assert.throws(()=>hostingerRelayConfig({...base,QUANTIC_RELAY_IDENTITY_SECRET:"short"}),/32/);
});

test("Hostinger relay requires an HTTPS public endpoint",()=>{
  assert.throws(()=>hostingerRelayConfig({...base,QUANTIC_RELAY_PUBLIC_ENDPOINT:"http://relay.example.com"}),/HTTPS/);
});
