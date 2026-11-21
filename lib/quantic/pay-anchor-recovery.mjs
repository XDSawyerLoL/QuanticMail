// Conventional OFFLINE replacement procedure, not a live recovery protocol.
// Quiesce the replica and old anchor; use an independently trusted current
// checkpoint, three authenticated surviving sources and fresh TLS custody.
// No rollback defense if the independent checkpoint and surviving custody
// are compromised. No payment, vote, remote repair or in-place overwrite.
import {X509Certificate,createHash,createPrivateKey,createPublicKey,timingSafeEqual} from 'node:crypto';
import {isAbsolute,dirname} from 'node:path';
import {lstatSync,realpathSync,openSync,writeFileSync,fsyncSync,closeSync} from 'node:fs';
import {config,check,exact,hex,port,privateRead} from './pay-anchor-config.mjs';
import {assertExternalPayCheckpoint} from './pay-external-checkpoint.mjs';
import {createPayAnchorClient} from './pay-anchor-client.mjs';
import {openPayAnchorStore} from './pay-anchor-store.mjs';
const spki=k=>k.export({format:'der',type:'spki'});
function identity(c){
 const cert=new X509Certificate(privateRead(c.certFile,16384));
 check(cert.checkIP('127.0.0.1')==='127.0.0.1'&&Date.now()>=Date.parse(cert.validFrom)&&Date.now()<Date.parse(cert.validTo));
 return {fingerprint:cert.fingerprint256,key:spki(cert.publicKey),keyHash:createHash('sha256').update(spki(cert.publicKey)).digest('hex')};
}
function absent(p){
 check(typeof p==='string'&&isAbsolute(p)&&realpathSync(dirname(p))===dirname(p));
 try{lstatSync(p);}catch(e){if(e.code==='ENOENT')return;throw e;}
 throw Error('Replacement destination already exists');
}
function clientConfig(path,network,authorityPin){
 const c=config(path);
 check(exact(c,['simulationOnly','network','authorityPin','port','token','certFile'])&&c.simulationOnly===true&&c.network===network&&c.authorityPin===authorityPin&&port(c.port)&&hex(c.token));
 return {...c,...identity(c)};
}
export function preparePayAnchorReplacement({quorumFile,replaceIndex,expectedCheckpointFile,replacementServerFile,replacementClientFile,outputQuorumFile,offlineConfirmed}){
 check(offlineConfirmed===true&&Number.isInteger(replaceIndex)&&replaceIndex>=0&&replaceIndex<4);
 const q=config(quorumFile);
 check(exact(q,['simulationOnly','network','authorityPin','members'])&&q.simulationOnly===true&&hex(q.network)&&hex(q.authorityPin)&&Array.isArray(q.members)&&q.members.length===4&&new Set(q.members).size===4);
 const {network,authorityPin}=q,expected=config(expectedCheckpointFile);
 assertExternalPayCheckpoint(expected,expected);
 check(expected.network===network&&expected.authorityPin===authorityPin);
 const old=q.members.map(path=>clientConfig(path,network,authorityPin)),replacement=clientConfig(replacementClientFile,network,authorityPin);
 for(const k of ['port','token','keyHash','fingerprint'])check(new Set([...old,replacement].map(m=>m[k])).size===5);
 const server=config(replacementServerFile);
 check(exact(server,['simulationOnly','directory','initial','port','token','keyFile','certFile'])&&server.simulationOnly===true&&server.port===replacement.port&&server.token===replacement.token&&server.certFile===replacement.certFile);
 assertExternalPayCheckpoint(server.initial,server.initial);
 check(server.initial.sequence===0&&server.initial.admission===null&&server.initial.financial===null&&server.initial.network===network&&server.initial.authorityPin===authorityPin&&server.initial.root===network);
 const secret=privateRead(server.keyFile,16384);
 try{const actual=spki(createPublicKey(createPrivateKey(secret)));check(actual.length===replacement.key.length&&timingSafeEqual(actual,replacement.key));}finally{secret.fill(0);}
 absent(server.directory);absent(outputQuorumFile);
 const survivors=q.members.filter((_,i)=>i!==replaceIndex).map(configFile=>createPayAnchorClient({configFile,network,authorityPin}));
 function verifySurvivors(){for(const client of survivors)assertExternalPayCheckpoint(client.read(),expected);}
 // All three must be online, distinct and exactly current. An older three-way
 // match is not enough unless it equals the independently retained reference.
 verifySurvivors();
 const store=openPayAnchorStore({directory:server.directory,initial:server.initial,createNew:true,recovered:expected});
 try{assertExternalPayCheckpoint(store.read(),expected);}finally{store.close();}
 verifySurvivors();
 const next={...q,members:q.members.map((p,i)=>i===replaceIndex?replacementClientFile:p)};
 // Write a NEW configuration; never replace the old file or allow old
 // credentials to serve as the replacement. A failed ceremony is quarantined.
 const fd=openSync(outputQuorumFile,'wx',0o600);
 try{writeFileSync(fd,JSON.stringify(next));fsyncSync(fd);}finally{closeSync(fd);}
 const dirfd=openSync(dirname(outputQuorumFile),'r');try{fsyncSync(dirfd);}finally{closeSync(dirfd);}
 return Object.freeze({simulationOnly:true,state:'prepared-offline-replacement',sequence:expected.sequence,root:expected.root,requiresFourWayReadback:true});
}
