// Experimental non-rollback witness, NOT distributed consensus or production
// custody. This DB must be independently administered and non-restorable by
// the validator. No offline authorization or cached leases. Round zero only.
// Calls are synchronous in this lab: a remote attested implementation is absent.
import {DatabaseSync} from 'node:sqlite';
import {mkdirSync,openSync,closeSync,lstatSync,realpathSync} from 'node:fs';
import {dirname,isAbsolute,join} from 'node:path';
import {createHash} from 'node:crypto';
const check=x=>{if(!x)throw Error('External fence refused');};
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const id=x=>typeof x==='string'&&/^demo-[a-z0-9]{1,24}$/.test(x);
const int=(x,a,b)=>Number.isSafeInteger(x)&&x>=a&&x<=b;
const exact=(o,k)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===k.length&&k.every(x=>Object.hasOwn(o,x));
const hash=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const ZERO='0'.repeat(64);
export function openExternalVoteFence({directory,network,shard,initialCommittee,genesisRoot,createNew=false}){
 check(process.platform==='linux'&&isAbsolute(directory)&&realpathSync(dirname(directory))===dirname(directory)&&hex(network)&&id(shard)&&hex(initialCommittee)&&hex(genesisRoot)&&typeof createNew==='boolean');
 const path=join(directory,'fence.sqlite');
 if(createNew){mkdirSync(directory,{mode:0o700});closeSync(openSync(path,'wx',0o600));}
 for(const [p,dir] of [[directory,true],[path,false]]){const s=lstatSync(p);check(realpathSync(p)===p&&s.uid===process.getuid()&&(s.mode&0o077)===0&&(dir?s.isDirectory():s.isFile()&&s.nlink===1));}
 const db=new DatabaseSync(path);let closed=false,halted=false;
 try{
  db.exec('PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA busy_timeout=2000; PRAGMA trusted_schema=OFF;');
  if(createNew){
   db.exec('BEGIN IMMEDIATE; CREATE TABLE fence(id INTEGER PRIMARY KEY CHECK(id=1),binding TEXT NOT NULL,epoch INTEGER NOT NULL,height INTEGER NOT NULL,root TEXT NOT NULL,committee TEXT NOT NULL,tip TEXT NOT NULL,mode TEXT NOT NULL,pending TEXT);');
   db.prepare("INSERT INTO fence VALUES(1,?,0,0,?,?,?,'idle',NULL)").run(hash([network,shard,initialCommittee,genesisRoot]),genesisRoot,initialCommittee,ZERO);db.exec('COMMIT');
  }
  const binding=hash([network,shard,initialCommittee,genesisRoot]);
  function state(){
   const rows=db.prepare('SELECT * FROM fence LIMIT 2').all(),s=rows[0];
   check(rows.length===1&&s.id===1&&s.binding===binding&&int(s.epoch,0,65535)&&int(s.height,0,256)&&hex(s.root)&&hex(s.committee)&&hex(s.tip)&&['idle','vote','handoff'].includes(s.mode)&&(s.mode==='idle'?s.pending===null:hex(s.pending)));
   return s;
  }
  function tx(fn){check(!closed&&!halted);db.exec('BEGIN IMMEDIATE');let out;try{out=fn(state());}catch(e){try{db.exec('ROLLBACK');}catch{halted=true;}throw e;}try{db.exec('COMMIT');}catch(e){halted=true;try{db.exec('ROLLBACK');}catch{}throw e;}return out;}
  function match(s,a){check(exact(a,['epoch','height','root','committee','tip'])&&a.epoch===s.epoch&&a.height===s.height&&a.root===s.root&&a.committee===s.committee&&a.tip===s.tip);}
  function status(s){return Object.freeze({epoch:s.epoch,height:s.height,root:s.root,committee:s.committee,tip:s.tip,mode:s.mode,pending:s.pending});}
  function lock(s,mode,digest){check(hex(digest)&&(s.mode==='idle'||s.mode===mode&&s.pending===digest));if(s.mode==='idle')check(db.prepare('UPDATE fence SET mode=?,pending=? WHERE id=1').run(mode,digest).changes===1);}
  tx(status);
  return Object.freeze({
   status(){return tx(status);},
   // A certificate verifier belongs to the trusted service, not its caller.
   // This API is a local state-machine building block; callers must verify
   // final certificates before advanceBlock/activate. Never expose it as RPC.
   lockVote(anchor,value){return tx(s=>{match(s,anchor);check(s.height<256);lock(s,'vote',value);return true;});},
   advanceBlock(anchor,value){return tx(s=>{match(s,anchor);check(s.mode==='vote'&&s.pending===value&&s.height<256);check(db.prepare("UPDATE fence SET height=height+1,root=?,mode='idle',pending=NULL WHERE id=1").run(value).changes===1);return {height:s.height+1,root:value};});},
   lockHandoff(anchor,transition){return tx(s=>{match(s,anchor);check(s.height>=1&&s.height<256&&s.epoch<65535);lock(s,'handoff',transition);return true;});},
   activate(anchor,{transition,nextCommittee}){
    return tx(s=>{match(s,anchor);check(s.mode==='handoff'&&s.pending===transition&&hex(nextCommittee)&&nextCommittee!==s.committee&&s.epoch<65535);
     check(db.prepare("UPDATE fence SET epoch=epoch+1,committee=?,tip=?,mode='idle',pending=NULL WHERE id=1").run(nextCommittee,transition).changes===1);
     return {epoch:s.epoch+1,height:s.height,root:s.root,committee:nextCommittee,tip:transition};
    });
   },
   close(){if(!closed){closed=true;db.close();}}
  });
 }catch(e){db.close();throw e;}
}
