// Conventional independent checkpoint storage, experimental only.
// No protection against rollback of this database itself or stolen anchor credentials.
import {DatabaseSync} from 'node:sqlite';
import {mkdirSync,lstatSync,realpathSync,openSync,closeSync} from 'node:fs';
import {dirname,join,isAbsolute} from 'node:path';
import {assertExternalPayCheckpoint} from './pay-external-checkpoint.mjs';
const check=v=>{if(!v)throw Error('Pay anchor refused');};
const bound=(a,b)=>a.network===b.network&&a.authorityPin===b.authorityPin;
const valid=c=>assertExternalPayCheckpoint(c,c);
function advance(a,b){
 valid(a);valid(b);check(bound(a,b)&&b.sequence>=a.sequence&&b.sequence<=a.sequence+1);
 if(b.sequence===a.sequence){
  check(b.root===a.root);
  for(const k of ['admission','financial']){
   if(a[k]!==null){
    check(b[k]!==null&&b[k].scope===a[k].scope&&b[k].count>=a[k].count);
    if(b[k].count===a[k].count)check(b[k].root===a[k].root);
   }
  }
 }else check(b.root!==a.root&&b.admission===null&&b.financial===null);
}
export function openPayAnchorStore({directory,initial,createNew=false}){
 check(process.platform==='linux'&&isAbsolute(directory)&&realpathSync(dirname(directory))===dirname(directory));
 valid(initial);check(initial.sequence===0&&initial.admission===null&&initial.financial===null);
 const path=join(directory,'anchor.sqlite');
 if(createNew){mkdirSync(directory,{mode:0o700});closeSync(openSync(path,'wx',0o600));}
 for(const [p,isDir] of [[directory,true],[path,false]]){
  const st=lstatSync(p);check(realpathSync(p)===p&&st.uid===process.getuid()&&(st.mode&0o077)===0&&(isDir?st.isDirectory():st.isFile()&&st.nlink===1));
 }
 const db=new DatabaseSync(path);let closed=false,halted=false;
 try{
  db.exec('PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA busy_timeout=2500; PRAGMA trusted_schema=OFF;');
  if(createNew){
   db.exec('BEGIN IMMEDIATE; CREATE TABLE anchor(id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL, revision INTEGER NOT NULL);');
   db.prepare('INSERT INTO anchor VALUES(1,?,0)').run(JSON.stringify(initial));
   db.exec('COMMIT');
  }
  function current(){
   check(!closed&&!halted);
   const rows=db.prepare('SELECT body,revision FROM anchor LIMIT 2').all();check(rows.length===1);
   const row=rows[0];check(typeof row.body==='string'&&Buffer.byteLength(row.body)<=4096&&Number.isSafeInteger(row.revision)&&row.revision>=0);
   const body=JSON.parse(row.body);valid(body);check(bound(body,initial));return {body,revision:row.revision};
  }
  current();
  return Object.freeze({
   read:()=>current().body,
   compareAndSwap(before,after){
    valid(before);valid(after);advance(before,after);
    db.exec('BEGIN IMMEDIATE');
    try{
     const c=current();assertExternalPayCheckpoint(c.body,before);
     check(c.revision<Number.MAX_SAFE_INTEGER);
     check(db.prepare('UPDATE anchor SET body=?,revision=? WHERE id=1 AND revision=?').run(JSON.stringify(after),c.revision+1,c.revision).changes===1);
    }catch(e){try{db.exec('ROLLBACK');}catch{halted=true;}throw e;}
    try{db.exec('COMMIT');}catch(e){halted=true;throw e;}
    return true;
   },
   close(){if(!closed){closed=true;db.close();}}
  });
 }catch(e){db.close();throw e;}
}
