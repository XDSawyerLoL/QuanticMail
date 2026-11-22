// Synthetic Linux-only durable shard replica. Round zero only.
// An intact private DB is a trust assumption: rollback of the entire DB by
// its owner is NOT prevented. Wallet and authority private keys live outside DB.
// A vote lock is committed before a signature may leave the replica.
// Cold start and externally modified DBs replay certified blocks from genesis.
// Warm state remains a verified volatile cache, not a trusted disk checkpoint.
import {DatabaseSync} from 'node:sqlite';
import {openSync,closeSync,mkdirSync,lstatSync,realpathSync} from 'node:fs';
import {dirname,isAbsolute,join} from 'node:path';
import {createHash} from 'node:crypto';
import {openShardedPayLab} from './pay-sharded-lab.mjs';
import {createPayRoundLab} from './pay-round-lab.mjs';
const check=v=>{if(!v)throw Error('Durable shard refused');};
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const hash=b=>createHash('sha256').update(b).digest('hex');
const MAX=256,MAX_BLOCK_BYTES=16*1024*1024;
function encode(v){const b=JSON.stringify(v);check(typeof b==='string'&&Buffer.byteLength(b)<=MAX_BLOCK_BYTES);return b;}
export function openDurableShard({config,shard,directory,credentials=null,createNew=false,reservationsEnabled=false,crossShardAtomicEnabled=false,inboundPreparationEnabled=false}){
 check(process.platform==='linux'&&typeof directory==='string'&&isAbsolute(directory)&&realpathSync(dirname(directory))===dirname(directory)&&typeof createNew==='boolean');
 const cfg=structuredClone(config),labOptions={reservationsEnabled,crossShardAtomicEnabled,inboundPreparationEnabled},network=openShardedPayLab(cfg,labOptions).network,binding=credentials?.authorityPin??'observer';
 check(binding==='observer'||hex(binding));
 if(binding!=='observer')check(cfg.shards.find(s=>s.id===shard)?.authorities.some(a=>a.pin===binding));
 const authorities=cfg.shards.find(s=>s.id===shard)?.authorities;check(authorities);
 const path=join(directory,'shard.sqlite');
 if(createNew){mkdirSync(directory,{mode:0o700});closeSync(openSync(path,'wx',0o600));}
 for(const [p,dir] of [[directory,true],[path,false]]){const s=lstatSync(p);check(realpathSync(p)===p&&s.uid===process.getuid()&&(s.mode&0o077)===0&&(dir?s.isDirectory():s.isFile()&&s.nlink===1));}
 const db=new DatabaseSync(path);let closed=false,halted=false,cache=null;
 const metrics={fullReplays:0,replayedBlocks:0,cacheHits:0,externalInvalidations:0,incrementalBlocks:0};
 try{
  db.exec('PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA busy_timeout=2000; PRAGMA trusted_schema=OFF;');
  if(createNew){
   const root=openShardedPayLab(cfg,labOptions).openShard(shard).snapshot().root;
   db.exec('BEGIN IMMEDIATE; CREATE TABLE meta(id INTEGER PRIMARY KEY CHECK(id=1),network TEXT NOT NULL,shard TEXT NOT NULL,binding TEXT NOT NULL,height INTEGER NOT NULL,root TEXT NOT NULL); CREATE TABLE blocks(height INTEGER PRIMARY KEY,body TEXT NOT NULL,digest TEXT NOT NULL); CREATE TABLE locks(height INTEGER PRIMARY KEY,value TEXT NOT NULL,body TEXT NOT NULL);');
   db.prepare('INSERT INTO meta VALUES(1,?,?,?,0,?)').run(network,shard,binding,root);db.exec('COMMIT');
  }
  function tx(fn){
   check(!closed&&!halted);db.exec('BEGIN IMMEDIATE');
   let out;try{out=fn();}catch(e){cache=null;try{db.exec('ROLLBACK');}catch{halted=true;}throw e;}
   try{db.exec('COMMIT');}catch(e){cache=null;halted=true;try{db.exec('ROLLBACK');}catch{}throw e;}return out;
  }
  function replay(){
   const m=db.prepare('SELECT * FROM meta LIMIT 2').all(),s=m[0];
   check(m.length===1&&s.id===1&&s.network===network&&s.shard===shard&&s.binding===binding&&Number.isInteger(s.height)&&s.height>=0&&s.height<=MAX&&hex(s.root));
   const version=db.prepare('PRAGMA data_version').get().data_version;
   let chain,receipts;
   if(cache&&cache.version===version&&cache.height===s.height&&cache.root===s.root){
    ({chain,receipts}=cache);metrics.cacheHits++;
   }else{
   if(cache)metrics.externalInvalidations++;
   metrics.fullReplays++;chain=openShardedPayLab(cfg,labOptions).openShard(shard);const rows=db.prepare('SELECT height,body,digest FROM blocks ORDER BY height LIMIT 257').all();
   check(rows.length===s.height);receipts=[];
   for(let i=0;i<rows.length;i++){
    const r=rows[i];check(r.height===i+1&&typeof r.body==='string'&&Buffer.byteLength(r.body)<=MAX_BLOCK_BYTES&&hash(r.body)===r.digest);
    const b=JSON.parse(r.body);check(encode(b)===r.body&&b.certificate.prepared.round===0&&b.certificate.commit.round===0);
    receipts=chain.finalize(b.operations,b.certificate);metrics.replayedBlocks++;
   }
   check(chain.snapshot().root===s.root&&chain.snapshot().height===s.height);
   cache={version,height:s.height,root:s.root,chain,receipts};
   }
   const locks=db.prepare('SELECT height,value,body FROM locks LIMIT 2').all();check(locks.length<=1);
   const lock=locks[0]??null;
   if(lock){check(binding!=='observer'&&lock.height===s.height+1&&hex(lock.value)&&typeof lock.body==='string'&&Buffer.byteLength(lock.body)<=MAX_BLOCK_BYTES);const ops=JSON.parse(lock.body);check(encode(ops)===lock.body&&chain.proposal(ops).value===lock.value);}
   return {chain,lock,receipts};
  }
  // Sign in a fresh round instance, never reuse the volatile authority guard.
  // The durable lock, including the complete candidate, precedes every vote.
  function lockedAuthority(p){
   const h=p.header,round=createPayRoundLab({network:hash(JSON.stringify(['quantic-shard-round/v1',network,shard])),height:h.height,previousRoot:h.previous,authorities,admissionRound:true,committeeMode:true});
   check(round.scope===p.scope);return round.openAuthority(credentials);
  }
  tx(replay);
  return Object.freeze({
   metrics:()=>Object.freeze({...metrics}),
   snapshot(){return tx(()=>replay().chain.snapshot());},
   checkpoint(){return tx(()=>replay().chain.checkpoint());},
   proposal(ops){return tx(()=>replay().chain.proposal(ops));},
   prepare(ops){
    check(credentials&&binding!=='observer');const body=encode(ops);
    const staged=tx(()=>{const {chain,lock}=replay(),input=JSON.parse(body),p=chain.proposal(input);
     if(lock)check(lock.value===p.value&&lock.body===body);
     else check(db.prepare('INSERT INTO locks VALUES(?,?,?)').run(p.header.height,p.value,body).changes===1);
     return p;});
    // Signature returned only after SQLite commit. Every retry is locked to
    // the exact candidate. Another process may advance the chain meanwhile;
    // the old vote is still scoped to its original certified height.
    return lockedAuthority(staged).prepare({round:0,value:staged.value});
   },
   commit(qc){
    check(credentials&&binding!=='observer'&&qc?.round===0);
    const staged=tx(()=>{const {chain,lock}=replay();check(lock&&lock.value===qc.value);return chain.proposal(JSON.parse(lock.body));});
    const a=lockedAuthority(staged);a.prepare({round:0,value:staged.value});return a.commit(qc);
   },
   finalize(operations,certificate){
    check(certificate?.prepared?.round===0&&certificate?.commit?.round===0);
    const body=encode({operations,certificate}),block=JSON.parse(body);
    return tx(()=>{const {chain}=replay(),p=chain.proposal(block.operations),receipts=chain.finalize(block.operations,block.certificate);
     check(db.prepare('INSERT INTO blocks VALUES(?,?,?)').run(p.header.height,body,hash(body)).changes===1);
     check(db.prepare('UPDATE meta SET height=?,root=? WHERE id=1 AND height=?').run(p.header.height,p.value,p.header.height-1).changes===1);
     db.prepare('DELETE FROM locks WHERE height=?').run(p.header.height);
     cache={version:cache.version,height:p.header.height,root:p.value,chain,receipts:structuredClone(receipts)};metrics.incrementalBlocks++;
     return receipts;
    });
   },
   recoverReceipts(height){
    return tx(()=>{const {chain,receipts:latest}=replay();check(Number.isInteger(height)&&height>=1&&height<=chain.snapshot().height);
     if(height===chain.snapshot().height)return structuredClone(latest);
     const fresh=openShardedPayLab(cfg,labOptions).openShard(shard);let receipts=[];
     for(const r of db.prepare('SELECT body FROM blocks WHERE height<=? ORDER BY height').all(height)){const b=JSON.parse(r.body);receipts=fresh.finalize(b.operations,b.certificate);}
     return receipts;
    });
   },
   close(){if(!closed){closed=true;cache=null;db.close();}}
  });
 }catch(e){db.close();throw e;}
}
