#!/usr/bin/env node
// Independently launched Quantic Pay witness laboratory process.
// All witness signing keys and the SQLite fence stay in THIS process.
// The orchestrator has TLS client credentials only. Configuration is explicit
// and owner-private; no administrative API or remote private-key fetch exists.
import {openShardWitnessBridgeLab} from '../lib/quantic/pay-shard-witness-bridge-lab.mjs';
import {startPayWitnessMtlsServerLab} from '../lib/quantic/pay-witness-mtls-lab.mjs';
import {readWitnessPrivateFileLab,loadWitnessPrivateKeyLab} from '../lib/quantic/pay-witness-private-file-lab.mjs';
import {isAbsolute} from 'node:path';

const fail=()=>{throw Error('Quantic Pay remote witness node refused configuration');};
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
 const raw=readWitnessPrivateFileLab(cfgPath);
 let data;
 try{data=JSON.parse(raw.toString('utf8'));}finally{raw.fill(0);}
 if(!data||typeof data!=='object'||Array.isArray(data))fail();
 const {config,options,shard,witnesses,credentials,identity,
  allowedClientCertPins,directory,createNew,host,port}=data;
 if(!credentials||!identity||typeof directory!=='string'||!isAbsolute(directory)
   ||!Number.isSafeInteger(port)||port<0||port>65535)fail();
 const bridge=openShardWitnessBridgeLab({config,options,shard,witnesses});
 witness=bridge.openWitness({directory,createNew,credentials:{
  pin:credentials.pin,
  classicalPrivateKey:loadWitnessPrivateKeyLab(credentials.classicalKeyPath),
  pqPrivateKey:loadWitnessPrivateKeyLab(credentials.pqKeyPath)
 }});
 // The TLS engine installs the keys into its native secure context before
 // these temporary JS buffers are wiped. This is NOT hardware key custody.
 const tlsKey=readWitnessPrivateFileLab(identity.keyPath,{maxBytes:65536});
 const tlsCert=readWitnessPrivateFileLab(identity.certPath,{maxBytes:65536});
 const tlsCA=readWitnessPrivateFileLab(identity.caPath,{maxBytes:65536});
 try{
  server=await startPayWitnessMtlsServerLab({
   witness,host:host??'127.0.0.1',port,
   tls:{key:tlsKey,cert:tlsCert,ca:tlsCA},allowedClientCertPins
  });
 }finally{tlsKey.fill(0);tlsCert.fill(0);tlsCA.fill(0);}
 process.stdout.write(JSON.stringify({event:'ready',host:server.host,port:server.port,
  witnessPin:credentials.pin,scope:bridge.scope,simulationOnly:true})+'\n');
}catch(e){
 process.stderr.write('Quantic Pay witness startup refused: '+String(e?.message??e)+'\n');
 await close(1);
}
