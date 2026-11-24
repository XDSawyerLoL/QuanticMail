// Windows counterpart of the pre-authorized overlap schedule. Read all
// configuration through the ACL/reparse-checked native helper; pins are
// obtained independently, and the packaged binaries cannot be substituted
// by the schedule. No credentials on a command line or in the report.
import {createHash} from 'node:crypto';
import {win32} from 'node:path';
import {createWindowsNativeStorage} from './native-windows-storage.mjs';
import {validateOverlapSchedule,runOverlapSchedule} from '../standalone-relay/native-scattering-overlap.mjs';
import {startPrivateCarrierHost} from '../standalone-relay/native-scattering-host.mjs';
const check=x=>{if(!x)throw Error('Windows overlap schedule refused');};
const hex=/^[a-f0-9]{64}$/;
const hash=b=>createHash('sha256').update(b).digest('hex');
const pathOK=p=>typeof p==='string'&&/^[A-Za-z]:\\/.test(p)&&win32.normalize(p)===p&&p.length<=160;
export async function loadWindowsOverlapSchedule({binary,binarySha256,pacerSha256,dir,scheduleSha256},{
 storageFactory=createWindowsNativeStorage
}={}){
 check(process.platform==='win32'&&pathOK(binary)&&pathOK(dir)&&[binarySha256,pacerSha256,scheduleSha256].every(x=>hex.test(x)));
 const pacer=win32.join(win32.dirname(binary),'Scattering-Pacer.exe');
 const store=await storageFactory({binary,binarySha256,dir});
 async function readJSON(storage,path,pin,max){
  const bytes=await storage.read(path);
  try{check(Buffer.isBuffer(bytes)&&bytes.length>=2&&bytes.length<=max&&hash(bytes)===pin);
   return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}
  finally{bytes.fill(0);}
 }
 const spec=await readJSON(store,win32.join(dir,'scattering.json'),scheduleSha256,32768);
 check(spec?.format==='quantic-private-scattering-overlap/v1'&&spec.labOnly===true&&Array.isArray(spec.slots)&&spec.slots.length>=2&&spec.slots.length<=24);
 const plans=[],boots=[];
 for(const slot of spec.slots){
  check(slot&&pathOK(slot.file)&&hex.test(slot.pin));
  const lane=win32.dirname(slot.file);
  check(win32.dirname(lane)===dir&&/^lane-[a-z0-9]{1,24}$/.test(win32.basename(lane))&&slot.file===win32.join(lane,'scattering.json'));
  const boot={binary,binarySha256,dir:lane,ledgerDir:dir};
  const laneStore=await storageFactory(boot);
  const p=await readJSON(laneStore,slot.file,slot.pin,16384);
  check(p.pacerBinary===pacer&&p.pacerSha256===pacerSha256
   &&p.carrier?.queueDir===win32.join(lane,'queue')&&p.carrier?.stateDir===win32.join(dir,'state'));
  plans.push(p);boots.push(boot);
 }
 validateOverlapSchedule(spec,plans);
 return {spec,plans,boots};
}
export async function runWindowsOverlapSchedule(args,{signal,onSlot}={}){
 const {spec,plans,boots}=await loadWindowsOverlapSchedule(args);
 const byPlan=new Map(plans.map((p,i)=>[p,boots[i]]));
 return runOverlapSchedule({spec,plans},{signal,onSlot,
  startHost:(p,opts)=>startPrivateCarrierHost(p,{...opts,windowsBootstrap:byPlan.get(p)})});
}
