import test from 'node:test';
import assert from 'node:assert/strict';
import {startRelayServer} from '../standalone-relay/server.ts';

test('production-designated standalone relay refuses missing PostgreSQL without writing volatile state',async()=>{
 await assert.rejects(startRelayServer({
  host:'127.0.0.1',port:0,dataDir:'./unused-test-relay-storage',
  requirePostgres:true,sharedAuthRateLimit:false
 }),/requires PostgreSQL/);
});
