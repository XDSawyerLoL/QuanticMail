// Isolated Windows desktop lab: file-based encrypted mail only.
// No legacy Web fallback, relay acknowledgement or production login.
import {win32} from 'node:path';
import {createWindowsNativeStorage,windowsLabPath} from './native-windows-storage.mjs';
import {connectNativeVault} from './native-vault-controller.mjs';
import {safeMailDisplay} from './native-vault-desktop.mjs';
export function bindWindowsDesktopConfig(config,bootstrap){
 if(config?.labOnly!==true||config.pqMode?.enabled!==true||config.nativeRelay!==undefined||config.binary!==bootstrap.binary||config.binarySha256!==bootstrap.binarySha256||config.windowsLab?.enabled!==true||config.windowsLab.dir!==bootstrap.dir)throw Error('Windows configuration mismatch');
 return config;
}
export async function runWindowsNativeDesktop(dialog,bootstrap,{makeStorage=createWindowsNativeStorage,connect=connectNativeVault}={}){
 let controller;
 const box=o=>dialog.showMessageBox({title:'QuanticMail · Windows PQ expérimental',noLink:true,...o});
 try{
  const storage=await makeStorage(bootstrap);
  const cfg=bindWindowsDesktopConfig(JSON.parse((await storage.read(win32.join(bootstrap.dir,'desktop.json'))).toString('utf8')),bootstrap);
  const r=await box({type:'info',message:'Coffre natif Windows — laboratoire',detail:'Échange local par fichiers. Identités de test uniquement. Aucun accès Web ou accusé de réception distant.',buttons:['Ouvrir un message','Préparer un message','Quitter'],defaultId:2,cancelId:2});
  if(r.response!==0&&r.response!==1)return 'cancelled';
  const outgoing=r.response===1;
  const chosen=await dialog.showOpenDialog({title:outgoing?'Brouillon privé draft-*.json':'Enveloppe privée wire-*.json',defaultPath:bootstrap.dir,properties:['openFile']});
  if(chosen.canceled||chosen.filePaths.length!==1)return 'cancelled';
  const path=chosen.filePaths[0],n=windowsLabPath(bootstrap.dir,path);
  if(!(outgoing?/^draft-/:/^wire-/).test(n))throw Error('wrong input');
  const b=await storage.read(path);let record;
  try{record=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(b));}finally{b.fill(0);}
  const c=record.context,addr=outgoing?c?.to:c?.from;
  if(!/^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$/.test(addr))throw Error('invalid peer');
  const approve=await box({type:'warning',message:outgoing?'Préparer le message pour '+addr:'Ouvrir le message de '+addr,detail:outgoing?safeMailDisplay(record.payload):'Les signatures et attestations seront vérifiées avant affichage.',buttons:['Annuler','Continuer','Récupérer le résultat exact'],defaultId:0,cancelId:0});
  if(approve.response!==1&&approve.response!==2)return 'cancelled';
  let destination;
  if(outgoing){
   const save=await dialog.showSaveDialog({title:'Nouvelle enveloppe wire-*.json',defaultPath:win32.join(bootstrap.dir,'wire-message.json')});
   if(save.canceled||!save.filePath)return 'cancelled';
   destination=save.filePath;
   if(!/^wire-/.test(windowsLabPath(bootstrap.dir,destination)))throw Error('wrong output');
  }
  controller=await connect(cfg);
  if(outgoing){
   const sealed=await controller.sealHybrid(c,record.payload,{recover:approve.response===2});
   await storage.writeWire(destination,Buffer.from(JSON.stringify(sealed)+'\n'));
   await box({type:'info',message:'Enveloppe chiffrée enregistrée',detail:'Non envoyée. Seul le fichier chiffré a été écrit. Conservez le brouillon.',buttons:['Fermer']});
  }else{
   const payload=await controller.openHybrid(record,{recover:approve.response===2});
   await box({type:'info',message:'Message authentifié',detail:safeMailDisplay(payload),buttons:['Fermer']});
  }
  return 'completed';
 }catch{
  await box({type:'error',message:'Opération non confirmée',detail:'Aucun repli Web. Conservez les données d’origine ; un résultat peut nécessiter une récupération exacte.',buttons:['Fermer']});
  return 'failed';
 }finally{controller?.close();}
}
