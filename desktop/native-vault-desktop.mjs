// Local Electron dialog workflow: no HTTP, remote renderer or renderer IPC.
import {open,constants} from 'node:fs/promises';
import {isAbsolute} from 'node:path';
import {connectNativeVault,normalizeClassicalEnvelope} from './native-vault-controller.mjs';

async function readLocal(path,privateFile=false){
  if(typeof path!=='string'||!isAbsolute(path))throw Error('absolute file required');
  const f=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{
    const s=await f.stat();
    if(!s.isFile()||s.size>32768||privateFile&&(s.uid!==process.getuid()||(s.mode&0o077)!==0))throw Error('invalid local file');
    const b=Buffer.alloc(32769);let n=0;
    while(n<b.length){const r=await f.read(b,n,b.length-n,null);if(!r.bytesRead)break;n+=r.bytesRead;}
    if(n>32768)throw Error('file too large');
    return new TextDecoder('utf-8',{fatal:true}).decode(b.subarray(0,n));
  }finally{await f.close();}
}
export function safeMailDisplay(payload){
  if(!payload||typeof payload!=='object'||typeof payload.subject!=='string'||typeof payload.body!=='string'||Buffer.byteLength(payload.subject)+Buffer.byteLength(payload.body)>8192)throw Error('unsupported mail payload');
  // Plain text only; render invisible direction/control characters visibly.
  const safe=s=>s.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu,c=>'<U+'+c.codePointAt(0).toString(16).toUpperCase().padStart(4,'0')+'>');
  return 'Objet : '+safe(payload.subject)+'\n\n'+safe(payload.body);
}
async function choose(dialog,title){
  const r=await dialog.showOpenDialog({title,properties:['openFile']});
  return !r.canceled&&r.filePaths.length===1?r.filePaths[0]:null;
}
const message=(dialog,options)=>dialog.showMessageBox({title:'QuanticMail · Coffre natif local',noLink:true,...options});
export async function runNativeDesktop(dialog,{connect=connectNativeVault}={}){
  let controller,output;
  try{
    const action=await message(dialog,{type:'info',message:'Mode local expérimental',detail:'Identités de test uniquement. Aucune connexion à la page Web. Le terminal du coffre demandera le mot de passe et le consentement. Les anciennes clés restent intactes.',buttons:['Lire une enveloppe','Signer une inscription','Quitter'],defaultId:2,cancelId:2});
    if(action.response!==0&&action.response!==1)return 'cancelled';
    const configPath=await choose(dialog,'Configuration privée du coffre');
    if(!configPath)return 'cancelled';
    const config=JSON.parse(await readLocal(configPath,true));
    if(config?.labOnly!==true)throw Error('lab only');
    if(config.pqMode!==undefined){
      if(config.pqMode.enabled!==true)throw Error('invalid PQ mode');
      const choice=await message(dialog,{type:'info',message:'QuanticMail · mode hybride authentifié',detail:'Utilise les attestations de deux identités et le coffre natif. Échange par fichiers uniquement ; aucun envoi réseau du message.',buttons:['Ouvrir un message signé','Préparer un message chiffré','Annuler'],defaultId:2,cancelId:2});
      if(choice.response!==0&&choice.response!==1)return 'cancelled';
      const path=await choose(dialog,choice.response===0?'Enveloppe native signée':'Brouillon privé (JSON : context, payload)');
      if(!path)return 'cancelled';
      const record=JSON.parse(await readLocal(path,choice.response===1));
      if(choice.response===1){
        const preview=safeMailDisplay(record.payload);
        const c=record.context;
        if(!/^[a-z0-9][a-z0-9._-]{2,31}~[a-f0-9]{32}@quantic$/.test(c?.to)||!/^d-[a-f0-9]{32}$/.test(c?.toDeviceId))throw Error('invalid recipient');
        const approval=await message(dialog,{type:'warning',message:'Confirmer le brouillon vers '+c.to,detail:c.toDeviceId+'\n\n'+preview,buttons:['Annuler','Continuer'],defaultId:0,cancelId:0});
        if(approval.response!==1)return 'cancelled';
        const save=await dialog.showSaveDialog({title:'Enveloppe native chiffrée et signée'});
        if(save.canceled||!save.filePath)return 'cancelled';
        if(!isAbsolute(save.filePath))throw Error('absolute output required');
        output=await open(save.filePath,'wx',0o600);
      }
      controller=await connect(config);
      if(choice.response===0){
        const payload=await controller.openHybrid(record);
        const detail=safeMailDisplay(payload);
        await message(dialog,{type:'info',message:'Message déchiffré — signatures et attestations vérifiées',detail,buttons:['Fermer']});
      }else{
        const sealed=await controller.sealHybrid(record.context,record.payload);
        await output.writeFile(JSON.stringify(sealed)+'\n','utf8');await output.sync();
        await message(dialog,{type:'info',message:'Enveloppe native enregistrée',detail:'Chiffrée et signée. Non envoyée ; conservez le brouillon.',buttons:['Fermer']});
      }
      return 'completed';
    }
    const inputPath=await choose(dialog,action.response===0?'Enveloppe classique chiffrée':'Défi exact d’inscription');
    if(!inputPath)return 'cancelled';
    const input=await readLocal(inputPath);
    const envelope=action.response===0?JSON.parse(input):null;
    if(envelope)normalizeClassicalEnvelope(envelope);
    const confirm=await message(dialog,{type:'warning',message:action.response===0?'Ouvrir cette enveloppe ?':'Signer ce défi d’inscription ?',detail:'L’autorisation finale dépend du terminal et du quorum. Une interruption après validation peut consommer le droit de rejeu. Ne supprimez pas les données d’origine. La provenance d’un message classique n’est pas authentifiée.',buttons:['Annuler','Continuer'],defaultId:0,cancelId:0});
    if(confirm.response!==1)return 'cancelled';
    if(action.response===1){
      const save=await dialog.showSaveDialog({title:'Nouveau fichier privé de preuve'});
      if(save.canceled||!save.filePath)return 'cancelled';
      if(!isAbsolute(save.filePath))throw Error('absolute output required');
      output=await open(save.filePath,'wx',0o600);
    }
    controller=await connect(config);
    if(action.response===0){
      const result=await controller.openStatic(envelope);
      const detail=safeMailDisplay(result);
      controller.close();controller=undefined;
      await message(dialog,{type:'info',message:'Message déchiffré — expéditeur non vérifié',detail,buttons:['Fermer'],defaultId:0,cancelId:0});
    }else{
      const proof=await controller.signEnrollment(input);
      if(typeof proof!=='string'||!(/^[0-9a-f]{128}$/).test(proof))throw Error('invalid proof');
      await output.writeFile(JSON.stringify(proof)+'\n','utf8');await output.sync();
      controller.close();controller=undefined;
      await message(dialog,{type:'info',message:'Preuve d’inscription enregistrée',detail:'Ce résultat ne constitue pas une inscription publiée ni une migration de compte.',buttons:['Fermer']});
    }
    return 'completed';
  }catch{
    await message(dialog,{type:'error',message:'Opération non confirmée',detail:'Le coffre a refusé l’opération ou est indisponible. Aucun repli vers les clés Web. Conservez les entrées ; un résultat de signature vide ou incomplet peut subsister. Ne relancez pas automatiquement.',buttons:['Fermer']});
    return 'failed';
  }finally{controller?.close();await output?.close();}
}
