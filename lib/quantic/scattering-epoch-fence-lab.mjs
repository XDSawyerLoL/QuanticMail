// Linux synthetic durable local epoch fence. Assumes private, non-rolled-back
// storage; no distributed atomicity, key storage, or recovery by resetting state.
import {DatabaseSync} from 'node:sqlite';
import {mkdirSync,realpathSync,lstatSync,openSync,closeSync} from 'node:fs';
import {join,dirname,isAbsolute} from 'node:path';
import {randomBytes} from 'node:crypto';
const check=x=>{if(!x)throw Error('Epoch fence refused');};
const hex=(s,n)=>typeof s==='string'&&s.length===n&&/^[0-9a-f]+$/.test(s),ZERO='0'.repeat(96);
export function openEpochFence({directory,channel,binding,createNew=false}){
 check(process.platform==='linux'&&typeof directory==='string'&&isAbsolute(directory)&&realpathSync(dirname(directory))===dirname(directory)&&hex(channel,96)&&hex(binding,96)&&typeof createNew==='boolean');
 const path=join(directory,'epoch.sqlite');
 if(createNew){mkdirSync(directory,{mode:0o700});closeSync(openSync(path,'wx',0o600));}
 for(const [p,dir] of [[directory,true],[path,false]]){const s=lstatSync(p);check(realpathSync(p)===p&&s.uid===process.getuid()&&(s.mode&0o077)===0&&(dir?s.isDirectory():s.isFile()&&s.nlink===1));}
 const db=new DatabaseSync(path);let closed=false,halted=false;
 try{
  db.exec('PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA busy_timeout=2000; PRAGMA trusted_schema=OFF;');
  if(createNew){db.exec('BEGIN IMMEDIATE; CREATE TABLE epoch(id INTEGER PRIMARY KEY CHECK(id=1),channel TEXT NOT NULL,binding TEXT NOT NULL,generation INTEGER NOT NULL,transcript TEXT NOT NULL,pending TEXT);');db.prepare('INSERT INTO epoch VALUES(1,?,?,-1,?,NULL)').run(channel,binding,ZERO);db.exec('COMMIT');}
  function state(){const rows=db.prepare('SELECT * FROM epoch LIMIT 2').all(),s=rows[0];check(rows.length===1&&s.id===1&&s.channel===channel&&s.binding===binding&&Number.isInteger(s.generation)&&s.generation>=-1&&s.generation<=65535&&hex(s.transcript,96)&&(s.generation===-1)===(s.transcript===ZERO)&&(s.pending===null||hex(s.pending,64)));return s;}
  function tx(fn){check(!closed&&!halted);db.exec('BEGIN IMMEDIATE');let out;try{out=fn();}catch(e){try{db.exec('ROLLBACK');}catch{halted=true;}throw e;}try{db.exec('COMMIT');}catch(e){halted=true;try{db.exec('ROLLBACK');}catch{}throw e;}return out;}
  tx(state);
  return Object.freeze({
   reserve(){return tx(()=>{const s=state();check(s.pending===null&&s.generation<65535);const token=randomBytes(32).toString('hex');check(db.prepare('UPDATE epoch SET pending=? WHERE id=1 AND pending IS NULL').run(token).changes===1);return Object.freeze({context:Object.freeze({channel,generation:s.generation+1,previous:s.transcript}),token});});},
   commit(reservation,session){return tx(()=>{const s=state();check(s.pending!==null&&reservation?.token===s.pending&&reservation.context?.channel===channel&&reservation.context.generation===s.generation+1&&reservation.context.previous===s.transcript&&session?.generation===reservation.context.generation&&hex(session.transcript,96)&&session.transcript!==ZERO&&session.transcript!==s.transcript);check(db.prepare('UPDATE epoch SET generation=?,transcript=?,pending=NULL WHERE id=1 AND pending=?').run(session.generation,session.transcript,s.pending).changes===1);return Object.freeze({generation:session.generation,transcript:session.transcript});});},
   status(){return tx(()=>{const s=state();return Object.freeze({generation:s.generation,transcript:s.transcript,pending:s.pending!==null});});},
   close(){if(!closed){closed=true;db.close();}}
  });
 }catch(e){db.close();throw e;}
}
