// Dedicated native laboratory state file. No legacy relay-state.json access.
// One owning native process, private local POSIX directory, atomic replacement.
import {open,rename,unlink,lstat} from 'node:fs/promises';
import {constants} from 'node:fs';
import {randomBytes} from 'node:crypto';
import {join} from 'node:path';
const MAX=32*1024*1024;
const check=x=>{if(!x)throw Error('Native mailbox private state refused');};
export function createNativeMailboxStore(dir){
 const path=join(dir,'native-mailbox-state.json');
 let poisoned=false;
 const healthy=()=>check(!poisoned);
 return {
  healthy,
  async load(){
   healthy();
   let f;
   try{f=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);}
   catch(e){if(e.code==='ENOENT')return null;throw e;}
   try{
    const st=await f.stat();check(st.isFile()&&st.nlink===1&&st.uid===process.getuid()&&(st.mode&0o077)===0&&st.size>0&&st.size<=MAX);
    const raw=await f.readFile();check(raw.length===st.size);
    const state=JSON.parse(raw.toString('utf8'));
    check(state?.format==='quantic-relay-state'&&state.version===3&&Array.isArray(state.nativeEnrollments));
    return state;
   }finally{await f.close();}
  },
  async save(state){
   healthy();
   check(state?.format==='quantic-relay-state'&&state.version===3&&Array.isArray(state.nativeEnrollments));
   // Never put legacy account, authentication or routing records in the dedicated file.
   for(const k of ['identities','aliases','challenges','devices','queues','receipts','sendWindows','routeManifests','discoveryPeers','preKeyPools','consumedPreKeys']){
    check(Array.isArray(state[k])&&state[k].length===0);
   }
   const raw=Buffer.from(JSON.stringify(state));
   check(raw.length>0&&raw.length<=MAX);
   const tmp=join(dir,'.native-state-'+randomBytes(16).toString('hex')+'.tmp');
   let f,replaced=false;
   try{
    try{
     const st=await lstat(path);
     check(st.isFile()&&!st.isSymbolicLink()&&st.nlink===1&&st.uid===process.getuid()&&(st.mode&0o077)===0);
    }catch(e){if(e.code!=='ENOENT')throw e;}
    f=await open(tmp,'wx',0o600);
    await f.writeFile(raw);await f.sync();await f.close();f=undefined;
    await rename(tmp,path);replaced=true;
    const parent=await open(dir,'r');try{await parent.sync();}finally{await parent.close();}
   }catch(e){
    if(replaced)poisoned=true; // ambiguous durability: refuse ALL further access
    await f?.close().catch(()=>{});await unlink(tmp).catch(()=>{});throw e;
   }
  }
 };
}
