// Native Windows direct mail lab. Private carrier plans must be prepared and
// independently pinned out of band; the receiving PC never starts an HTTP
// listener or a hosted relay. The sender retains the exact wire locally.
import {createHash} from 'node:crypto';
import {win32} from 'node:path';
import {createWindowsNativeStorage} from './native-windows-storage.mjs';
import {validatePrivateCarrierPlan,startPrivateCarrierHost} from '../standalone-relay/native-scattering-host.mjs';
import {startScatteringMailboxEndpoint} from '../standalone-relay/native-scattering-mailbox.mjs';
import {validateDirectTrust,createDirectRecipient,sendStoredDirectWire} from './native-direct-mail.mjs';
import {approveWindowsGUIPrompt} from './native-windows-gui-send.mjs';
import {listWindowsMailAttempts} from './native-windows-mail-status.mjs';
import {verifyLocalDirectIdentity} from './native-windows-local-direct.mjs';
const check=x=>{if(!x)throw Error('Windows direct mail refused');};
const hex=/^[a-f0-9]{64}$/;
const exact=(v,ks)=>v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).length===ks.length&&ks.every(k=>Object.hasOwn(v,k));
const pathOK=p=>typeof p==='string'&&/^[A-Za-z]:\\/.test(p)&&win32.normalize(p)===p&&!p.includes('~')&&p.length<=160;
export async function loadWindowsDirectMail({binary,binarySha256,pacerSha256,dir,planSha256},{storageFactory=createWindowsNativeStorage}={}){
 check(process.platform==='win32'&&pathOK(binary)&&pathOK(dir)&&[binarySha256,pacerSha256,planSha256].every(p=>hex.test(p)&&!/^0+$/.test(p)));
 const base={binary,binarySha256,dir};
 const storage=await storageFactory(base),raw=await storage.read(win32.join(dir,'scattering.json'));
 let p;
 try{
  check(Buffer.isBuffer(raw)&&raw.length>=2&&raw.length<=16384&&createHash('sha256').update(raw).digest('hex')===planSha256);
  p=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
 }finally{raw.fill(0);}
 check(exact(p,['format','labOnly','vaultDir','trust','plan'])&&['quantic-windows-direct-mail/v1','quantic-windows-direct-mail/v2'].includes(p.format)&&p.labOnly===true&&pathOK(p.vaultDir)&&p.vaultDir!==dir&&win32.dirname(p.vaultDir)!==dir);
 validateDirectTrust(p.trust);validatePrivateCarrierPlan(p.plan);
 check(p.plan.pacerBinary===win32.join(win32.dirname(binary),'Scattering-Pacer.exe')&&p.plan.pacerSha256===pacerSha256);
 const c=p.plan.carrier;
 const lane=win32.dirname(c.queueDir);
 check(win32.dirname(lane)===dir&&/^lane-[a-z0-9]{1,24}$/.test(win32.basename(lane))&&c.queueDir===win32.join(lane,'queue')&&c.stateDir===win32.join(dir,'state'));
 const boot={binary,binarySha256,dir:p.vaultDir};
 const vaultStorage=await storageFactory(boot);
 // Require a previously provisioned vault and bind its actual local public
 // identity to the pinned plan. No remote authority is queried for deposit.
 const local=p.format==='quantic-windows-direct-mail/v2';
 const cfgRaw=await vaultStorage.read(win32.join(boot.dir,local?'direct-identity.json':'desktop.json'));
 try{
  const cfg=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(cfgRaw));
  if(local){const own=verifyLocalDirectIdentity(cfg);check(own.address===p.trust.self.address&&own.deviceId===p.trust.self.deviceId);}
  else check(cfg.labOnly===true&&cfg.windowsLab?.dir===boot.dir&&cfg.windowsLab.enabled===true&&cfg.binary===binary&&cfg.binarySha256===binarySha256&&cfg.pqMode?.enabled===true&&cfg.pqMode.address===p.trust.self.address&&cfg.pqMode.deviceId===p.trust.self.deviceId);
 }finally{cfgRaw.fill(0);}
 return {plan:p.plan,trust:p.trust,boot,storage:vaultStorage,carrierBoot:{...base,dir:lane,ledgerDir:dir}};
}
export async function startWindowsDirectMail(args){
 const {plan,trust,boot,storage,carrierBoot}=await loadWindowsDirectMail(args);
 const isReceiver=plan.carrier.role==='relay';
 const directReceive=isReceiver?await createDirectRecipient({trust,storage,dir:boot.dir}):undefined;
 const host=await startPrivateCarrierHost(plan,{windowsBootstrap:carrierBoot,
  startEndpoint:(c,opts)=>startScatteringMailboxEndpoint(c,{...opts,profile:'direct-mail',directReceive})});
 // Never leak transport secrets in the result returned to the GUI.
 delete plan.carrier.secretHex;delete plan.carrier.epochHex;
 return Object.freeze({role:isReceiver?'recipient':'sender',closed:host.closed,close:host.close,
  authenticatedPeerSeen:host.authenticatedPeerSeen,
  async listOutgoing(){check(!isReceiver);const x=await listWindowsMailAttempts(boot);return x.items.filter(i=>i.wire).map(i=>i.id);},
  async send(file){
   check(!isReceiver&&host.authenticatedPeerSeen());
   return sendStoredDirectWire({trust,storage,dir:boot.dir,file,endpoint:'http://127.0.0.1:'+host.httpPort+'/',
    approve:text=>approveWindowsGUIPrompt(boot,storage,text)});
  }
 });
}
