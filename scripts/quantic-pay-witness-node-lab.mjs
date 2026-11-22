#!/usr/bin/env node
// Independently launched Quantic Pay witness laboratory process.
// All witness signing keys and the SQLite fence stay in THIS process.
// The orchestrator has TLS client credentials only. Configuration is explicit
// and owner-private; no administrative API or remote private-key fetch exists.
import {readFileSync,realpathSync,statSync} from 'node:fs';
import {isAbsolute} from 'node:path';
import {createPrivateKey,createHash} from 'node:crypto';
import {openShardWitnessBridgeLab} from '../lib/quantic/pay-shard-witness-bridge-lab.mjs';
import {startPayWitnessMtlsServerLab} from '../lib/quantic/pay-witness-mtls-lab.mjs';

const fail=()=>{throw Error('Quantic Pay remote witness node refused configuration');};
function privatePath(path){
 if(typeof path!=='string'||!isAbsolute(path)||realpathSync(path)!==path)fail();
 const st=statSync(path);
 if(!st.isFile()||(process.platform!=='win32'
   &&(st.uid!==process.getuid()||(st.mode&0o077)!==0)))fail();
 return readFileSync(path);
}
const cfgPath=process.env.QUANTIC_PAY_WITNESS_CONFIG;
let server=null,witness=null,closing=false;
async function close(code=0){
 if(closing)return;closing=true;
 try{await server?.close();}catch{code=1;}
 try{witness?.close();}catch{code=1;}
 process.exitCode=code;
}
process.on('SIGINT',()=>{void close(0);});
process.on('SIGTERM',()=>{void close(0);});
try{
 const raw=privatePath(cfgPath),data=JSON.parse(raw.toString('utf8'));
 if(!data||typeof data!=='object'||Array.isArray(data))fail();
 const {config,options,shard,witnesses,credentials,identity,
  allowedClientCertPins,directory,createNew,host,port}=data;
 if(!credentials||!identity||typeof directory!=='string'||!isAbsolute(directory)
   ||!Number.isSafeInteger(port)||port<0||port>65535)fail();
 const bridge=openShardWitnessBridgeLab({config,options,shard,witnesses});
 witness=bridge.openWitness({directory,createNew,credentials:{
  pin:credentials.pin,
  classicalPrivateKey:createPrivateKey(privatePath(credentials.classicalKeyPath)),
  pqPrivateKey:createPrivateKey(privatePath(credentials.pqKeyPath))
 }});
 server=await startPayWitnessMtlsServerLab({
  witness,host:host??'127.0.0.1',port,
  tls:{key:privatePath(identity.keyPath),cert:privatePath(identity.certPath),
   ca:privatePath(identity.caPath)},
  allowedClientCertPins
 });
 process.stdout.write(JSON.stringify({event:'ready',host:server.host,port:server.port,
  witnessPin:credentials.pin,scope:bridge.scope,simulationOnly:true})+'\n');
}catch(e){
 process.stderr.write('Quantic Pay witness startup refused: '+String(e?.message??e)+'\n');
 await close(1);
}
