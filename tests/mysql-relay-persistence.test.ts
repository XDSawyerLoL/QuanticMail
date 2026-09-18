import test from "node:test";
import assert from "node:assert/strict";

import {
  createMySqlRelayPersistence,
  MySqlRelayStateConflictError,
} from "../standalone-relay/mysql-storage.ts";

type StoredRow={value:unknown;revision:number};
type ResultInfo={affectedRows?:number};

class FakeMySqlClient{
  readonly rows=new Map<string,StoredRow>();

  async execute(sql:string,params:unknown[]=[]):Promise<[unknown[],ResultInfo]>{
    const compact=sql.replace(/\s+/g," ").trim().toLowerCase();
    if(compact.startsWith("create table")) return [[],{affectedRows:0}];

    if(compact.startsWith("select value, revision from quantic_relay_kv")){
      const key=String(params[0]??"");
      const row=this.rows.get(key);
      return [row?[{value:JSON.stringify(row.value),revision:row.revision}]:[],{}];
    }

    if(compact.startsWith("select value from quantic_relay_kv")){
      const key=String(params[0]??"");
      const row=this.rows.get(key);
      return [row?[{value:JSON.stringify(row.value)}]:[],{}];
    }

    if(compact.startsWith("update quantic_relay_kv")){
      const value=JSON.parse(String(params[0]??"null"));
      const key=String(params[1]??"");
      const expected=Number(params[2]);
      const row=this.rows.get(key);
      if(!row||row.revision!==expected)return [[],{affectedRows:0}];
      row.value=value;
      row.revision+=1;
      return [[],{affectedRows:1}];
    }

    if(compact.startsWith("insert ignore into quantic_relay_kv")){
      const key=String(params[0]??"");
      const value=JSON.parse(String(params[1]??"null"));
      if(this.rows.has(key))return [[],{affectedRows:0}];
      const revision=Number(params[2]??0);
      this.rows.set(key,{value,revision});
      return [[],{affectedRows:1}];
    }

    if(compact.startsWith("insert into quantic_relay_kv")&&compact.includes("on duplicate key update")){
      const key=String(params[0]??"");
      const value=JSON.parse(String(params[1]??"null"));
      const current=this.rows.get(key);
      this.rows.set(key,{value,revision:current?.revision??0});
      return [[],{affectedRows:1}];
    }

    throw new Error(`Unexpected SQL: ${compact}`);
  }
}

function snapshot(marker="base"){
  return {
    format:"quantic-relay-state",
    version:3,
    savedAt:"2026-09-18T00:00:00.000Z",
    identities:[],aliases:[],challenges:[],devices:[],queues:[],receipts:[],sendWindows:[],
    manifests:[],preKeyPools:[],consumedPreKeys:[],routeManifests:[],cryptoProfiles:[],
    federation:{seen:[],inbound:[],outbound:[],pendingReceipts:[]},
    discoveryPeers:[],marker,
  } as never;
}

test("MySQL relay state survives a fresh persistence adapter",async()=>{
  const client=new FakeMySqlClient();
  const first=createMySqlRelayPersistence(client);
  await first.stateStore.save(snapshot());
  const second=createMySqlRelayPersistence(client);
  assert.deepEqual(await second.stateStore.load(),snapshot());
});

test("MySQL relay keeps one stable encrypted identity",async()=>{
  const client=new FakeMySqlClient();
  const secret="mysql-hostinger-quantic-relay-secret-that-is-long-enough-2026";
  const first=createMySqlRelayPersistence(client,{identitySecret:secret});
  const identity=await first.loadOrCreateIdentity();
  const stored=JSON.stringify(client.rows.get("relay-identity")?.value);
  assert.ok(stored.includes("quantic-relay-identity-encrypted"));
  assert.equal(stored.includes("BEGIN PRIVATE KEY"),false);

  const second=createMySqlRelayPersistence(client,{identitySecret:secret});
  assert.equal((await second.loadOrCreateIdentity()).relayId,identity.relayId);
});

test("MySQL relay rejects stale writers",async()=>{
  const client=new FakeMySqlClient();
  const first=createMySqlRelayPersistence(client);
  await first.stateStore.save(snapshot("initial"));

  const a=createMySqlRelayPersistence(client);
  const b=createMySqlRelayPersistence(client);
  await a.stateStore.load();
  await b.stateStore.load();
  await a.stateStore.save(snapshot("a"));
  await assert.rejects(b.stateStore.save(snapshot("b")),err=>err instanceof MySqlRelayStateConflictError);
});

test("MySQL relay rejects the wrong identity secret",async()=>{
  const client=new FakeMySqlClient();
  const secret="mysql-hostinger-quantic-relay-secret-that-is-long-enough-2026";
  await createMySqlRelayPersistence(client,{identitySecret:secret}).loadOrCreateIdentity();
  await assert.rejects(
    createMySqlRelayPersistence(client,{identitySecret:"wrong-secret-that-is-still-definitely-long-enough-2026"}).loadOrCreateIdentity(),
    /secret|déchiffr|authent/i
  );
});
