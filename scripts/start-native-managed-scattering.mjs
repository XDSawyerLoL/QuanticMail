// Private dashboard child; parent pipe EOF stops both UDP processes.
import {createHash} from 'node:crypto';
import {readFile,readdir} from 'node:fs/promises';
import {win32} from 'node:path';
import {createWindowsNativeStorage} from '../desktop/native-windows-storage.mjs';
import {bindWindowsDesktopConfig} from '../desktop/native-windows-desktop.mjs';
import {windowsScatteringScope} from '../desktop/native-windows-mail-flow.mjs';
import {startManagedCarrier,validateManagedCarrier} from '../desktop/native-managed-scattering.mjs';
const check=x=>{if(!x)throw Error('Managed carrier refused');};
const pin=/^[a-f0-9]{64}$/;const hash=x=>createHash('sha256').update(x).digest('hex');
let session,stopped=false;
function shutdown(){stopped=true;void session?.close();}
process.stdin.on('end',shutdown);process.stdin.on('error',shutdown);process.stdin.on('data',shutdown);process.stdin.resume();
try{
 const [binary,binarySha256,parent,manifestPin]=process.argv.slice(2);
 check(process.platform==='win32'&&process.argv.length===6&&pin.test(binarySha256)&&pin.test(manifestPin)&&win32.isAbsolute(parent)&&win32.normalize(parent)===parent&&!process.stdin.isTTY);
 const root=win32.dirname(win32.dirname(binary)),pacer=win32.join(root,'bin','Scattering-Pacer.exe');
 const manifest=await readFile(win32.join(root,'SHA256SUMS.txt'));check(manifest.length<=262144&&hash(manifest)===manifestPin);
 const rows=manifest.toString('utf8').split(/\r?\n/).filter(x=>x.endsWith(' *./bin/Scattering-Pacer.exe'));
 check(rows.length===1&&pin.test(rows[0].slice(0,64))&&rows[0]===(rows[0].slice(0,64)+' *./bin/Scattering-Pacer.exe'));
 const entries=await readdir(parent,{withFileTypes:true});check(entries.length<=4096);
 const names=entries.filter(e=>e.isDirectory()&&!e.isSymbolicLink()&&/^quantic-enroll-[0-9a-f]{16}$/.test(e.name));check(names.length<=32);
 const configured=[];
 for(const n of names){
  const dir=win32.join(parent,n.name),boot={binary,binarySha256,dir},storage=await createWindowsNativeStorage(boot);
  let raw;try{raw=await storage.read(win32.join(dir,'desktop.json'));}catch{continue;}
  let cfg;try{cfg=bindWindowsDesktopConfig(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw)),boot);}finally{raw.fill(0);}
  if(cfg.managedScattering!==undefined||cfg.managedHybridScattering!==undefined)configured.push({dir,cfg});
 }
 if(configured.length===0){process.stdout.write(JSON.stringify({status:'not-configured'})+'\n');}
 else if(configured.length!==1){process.stdout.write(JSON.stringify({status:'multiple-identities-no-start'})+'\n');}
 else{
  check(!stopped);
  const {dir,cfg}=configured[0],scope=windowsScatteringScope(cfg),carrierDir=win32.join(dir,'carrier');
  if(cfg.managedHybridScattering!==undefined){
   check(cfg.managedScattering===undefined);
   process.stdout.write(JSON.stringify({status:'hybrid-session-required',directory:dir})+'\n');
  }else{
  check(scope.credentialMode==='vault-sealed-v1');
  const boot={binary,binarySha256,dir:carrierDir},storage=await createWindowsNativeStorage(boot);
  const raw=await storage.read(win32.join(carrierDir,'scattering.json'));
  let config;try{config=validateManagedCarrier(cfg.managedScattering,raw,scope,{queueDir:win32.join(carrierDir,'queue'),stateDir:win32.join(carrierDir,'state')});}finally{raw.fill(0);}
  check(!stopped);
  session=await startManagedCarrier({binary:pacer,binaryPin:rows[0].slice(0,64),config,listen:cfg.managedScattering.listen,target:cfg.managedScattering.target,windowsBootstrap:boot,env:storage.env});
  delete config.secretHex;delete config.epochHex;
  if(stopped){await session.close();throw Error('Parent closed');}
  process.stdout.write(JSON.stringify({status:'local-carrier-ready-not-remote-verified',directory:dir})+'\n');
  await session.closed;
  }
 }
}catch{process.stdout.write(JSON.stringify({status:'carrier-unavailable-no-retry'})+'\n');process.exitCode=1;}
finally{await session?.close();process.stdin.pause();}
