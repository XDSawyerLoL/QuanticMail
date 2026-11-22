// Copy-once staging with explicit resume after interruption. All writes
// are to a newly created synthetic lab directory through the trusted native
// Windows NTFS helper. Existing ciphertext is READ, authenticated and
// reconciled, NEVER overwritten. There is no live migration/cutover.
import {sealChunkedMigrationSnapshot,openChunkedMigrationSnapshot,migrationChunkFileName} from './migration-chunked-lab.mjs';
import {reconcileHistoricalCollections} from './migration-reconcile.mjs';
const check=ok=>{if(!ok)throw Error('Resumable migration stage refused');};
export async function stageChunkedMigrationSnapshot(collections,key,info,storage,{maxNewChunks=Infinity}={}){
 check(storage&&typeof storage.probe==='function'&&typeof storage.read==='function'&&typeof storage.write==='function'
  &&(maxNewChunks===Infinity||Number.isSafeInteger(maxNewChunks)&&maxNewChunks>=0));
 const fresh=sealChunkedMigrationSnapshot(collections,key,info);
 const chunks=[];let newCount=0,reused=0;
 for(let i=0;i<fresh.chunks.length;i++){
  const name=migrationChunkFileName(info.transactionId,info.role,i);
  const exists=await storage.probe(name);
  check(exists==='present'||exists==='absent');
  if(exists==='present'){
   chunks.push(await storage.read(name));reused++;
  }else{
   if(newCount===maxNewChunks)return Object.freeze({
    complete:false,role:info.role,total: fresh.chunks.length,
    staged:chunks.length,reused,labOnly:true,liveRestoreAuthorized:false,legacyDeletionAuthorized:false
   });
   // Creation is exclusive on the native side, racing writers fail closed.
   await storage.write(name,fresh.chunks[i]);chunks.push(fresh.chunks[i]);newCount++;
  }
 }
 const manifestName=migrationChunkFileName(info.transactionId,info.role,'manifest');
 const status=await storage.probe(manifestName);
 check(status==='absent'||status==='present');
 const manifest=status==='present'?await storage.read(manifestName):fresh.manifest;
 // Authenticate all chunk content against the pinned manifest and expected
 // exact records BEFORE writing a terminal role-manifest for this phase.
 const recovered=openChunkedMigrationSnapshot({manifest:status==='present'?manifest:fresh.manifest,chunks},key,info);
 const report=reconcileHistoricalCollections(collections,recovered);
 check(report.historicalCollectionsMatch);
 if(status==='absent')await storage.write(manifestName,fresh.manifest);
 // An independent new process must still re-read both roles for completion.
 return Object.freeze({complete:true,role:info.role,total:chunks.length,staged:chunks.length,reused,
  byteLength:fresh.plainBytes,labOnly:true,liveRestoreAuthorized:false,legacyDeletionAuthorized:false,
  durableTargetVerified:false,remoteQueueReconciled:false});
}
