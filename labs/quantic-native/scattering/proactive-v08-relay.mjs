/** Isolated local-process relay. LAB ONLY: the recover command discloses synthetic shares. */
import {
 N, T, mod, scalarEncode, scalarDecode, sha256, newIdentity, newTransport,
 publicDer, importPublic, signJson, verifyJson, createContribution,
 evalPoly, addCommitments, validateManifest, validateRoundProof,
 encryptShare, decryptShare, verifyShare,
} from './proactive-v08-core.mjs';

if(process.env.QS_V08_LAB_ONLY!=='1'||!process.send)throw new Error('This module only runs as an isolated test subprocess');
let localId=0, identity=null, registry=null;
let epoch=0, share=null, blind=null, commitments=null;
let nextTransport=null, nextManifest=null, peerManifests=null, pending=null;

function requireIdentity(){if(!localId||!identity)throw new Error('not initialized');}
function checkSetup(nextEpoch){
  requireIdentity();
  if(!registry||registry.size!==N)throw new Error('no verified identity registry');
  if(!Number.isSafeInteger(nextEpoch)||nextEpoch!==epoch+1)throw new Error('epoch out of sequence');
  if(!nextTransport||!nextManifest||!peerManifests)throw new Error('signed transport manifests required');
}
function msg(cmd,args={}){
  switch(cmd){
    case 'init':{
      if(localId!==0||!Number.isInteger(args.id)||args.id<1||args.id>N)throw new Error('invalid init');
      localId=args.id;identity=newIdentity();
      return {id:localId,identityPub:publicDer(identity.publicKey)};
    }
    case 'registry':{
      requireIdentity();
      if(!Array.isArray(args.entries)||args.entries.length!==N)throw new Error('invalid identity registry');
      const next=new Map();
      for(const row of args.entries){if(!Number.isInteger(row.id)||row.id<1||row.id>N||next.has(row.id))throw new Error('duplicate identity');
        const pub=importPublic(row.identityPub);if(pub.asymmetricKeyType!=='ed25519')throw new Error('wrong signing key type');
        next.set(row.id,pub);
      }
      if(publicDer(next.get(localId))!==publicDer(identity.publicKey))throw new Error('identity mismatch');
      registry=next;return {installed:true};
    }
    case 'begin':{
      requireIdentity();
      if(args.epoch!==epoch+1||nextTransport||pending)throw new Error('invalid transition begin');
      nextTransport=newTransport();
      const body={id:localId,epoch:args.epoch,transportPub:publicDer(nextTransport.publicKey)};
      nextManifest={...body,signature:signJson(body,identity.privateKey)};
      return {manifest:nextManifest};
    }
    case 'manifests':{
      if(!registry||!nextManifest||args.epoch!==epoch+1||!Array.isArray(args.manifests)||args.manifests.length!==N)throw new Error('invalid manifest set');
      const next=new Map();
      for(const manifest of args.manifests){
        if(next.has(manifest.id))throw new Error('duplicate recipient manifest');
        validateManifest(manifest,registry.get(manifest.id),args.epoch);next.set(manifest.id,manifest);
      }
      if(JSON.stringify(next.get(localId))!==JSON.stringify(nextManifest))throw new Error('local transport substituted');
      peerManifests=next;
      return {accepted:true};
    }
    case 'contribute':{
      checkSetup(args.epoch);
      if(!['dkg','refresh'].includes(args.mode)||(epoch===0)!==(args.mode==='dkg'))throw new Error('wrong contribution mode');
      const contribution=createContribution(args.mode);
      const body={dealer:localId,epoch:args.epoch,mode:args.mode,
        commitments:contribution.commitments,zeroBlind:contribution.zeroBlind};
      const proof={...body,signature:signJson(body,identity.privateKey)};
      const proofDigest=sha256(proof);
      const manifestDigest=sha256([...peerManifests.values()].sort((a,b)=>a.id-b.id));
      const packets=[];
      for(let to=1;to<=N;to++){
        const ad={protocol:'QS-V08-LAB',epoch:args.epoch,mode:args.mode,from:localId,to,proofDigest,manifestDigest};
        const a=evalPoly(contribution.a,to), b=evalPoly(contribution.b,to);
        const envelope=encryptShare({a,b,ad,recipientPub:peerManifests.get(to).transportPub});
        const bodyPacket={ad,envelope};
        packets.push({...bodyPacket,signature:signJson(bodyPacket,identity.privateKey)});
      }
      // The unencrypted coefficients never leave this process. No sender state needed after this.
      contribution.a.fill(0n);contribution.b.fill(0n);
      return {proof,packets};
    }
    case 'stage':{
      checkSetup(args.epoch);
      if(pending||!Array.isArray(args.proofs)||args.proofs.length!==N||!Array.isArray(args.packets)||args.packets.length!==N)throw new Error('invalid round size');
      if((epoch===0)!==(args.mode==='dkg'))throw new Error('wrong round mode');
      const proofs=new Map();
      for(const p of args.proofs){
        if(proofs.has(p.dealer))throw new Error('duplicate dealer proof');
        validateRoundProof(p,registry.get(p.dealer),args.epoch,args.mode);proofs.set(p.dealer,p);
      }
      const expectedManifestDigest=sha256([...peerManifests.values()].sort((a,b)=>a.id-b.id));
      const seen=new Set();let sumShare=0n,sumBlind=0n;
      for(const packet of args.packets){
        if(!packet||Object.keys(packet).sort().join(',')!=='ad,envelope,signature')throw new Error('malformed packet');
        const {signature,...body}=packet,{ad}=body;
        if(!ad||Object.keys(ad).sort().join(',')!=='epoch,from,manifestDigest,mode,proofDigest,protocol,to'||
          ad.protocol!=='QS-V08-LAB'||ad.epoch!==args.epoch||ad.mode!==args.mode||ad.to!==localId||
          !Number.isInteger(ad.from)||!proofs.has(ad.from)||seen.has(ad.from)||
          ad.manifestDigest!==expectedManifestDigest||ad.proofDigest!==sha256(proofs.get(ad.from)))throw new Error('replayed/duplicate/invalid packet context');
        if(!verifyJson(body,signature,registry.get(ad.from)))throw new Error('invalid signed packet');
        seen.add(ad.from);
        const {a,b}=decryptShare({envelope:packet.envelope,ad,receiverPriv:nextTransport.privateKey});
        if(!verifyShare(proofs.get(ad.from).commitments,localId,a,b))throw new Error('unverifiable dealer share');
        sumShare=mod(sumShare+a);sumBlind=mod(sumBlind+b);
      }
      if(seen.size!==N)throw new Error('missing dealer');
      const aggregate=addCommitments([...proofs.values()].map(p=>p.commitments));
      const newShare=mod((share??0n)+sumShare),newBlind=mod((blind??0n)+sumBlind);
      const combinedCommitments=commitments?addCommitments([commitments,aggregate]):aggregate;
      if(!verifyShare(combinedCommitments,localId,newShare,newBlind))throw new Error('combined commitment mismatch');
      const sorted=[...proofs.values()].sort((a,b)=>a.dealer-b.dealer);
      const roundDigest=sha256({epoch:args.epoch,mode:args.mode,manifestsDigest:expectedManifestDigest,proofs:sorted});
      pending={epoch:args.epoch,mode:args.mode,share:newShare,blind:newBlind,commitments:combinedCommitments,roundDigest};
      const ack={id:localId,epoch:args.epoch,roundDigest};
      return {ack:{...ack,signature:signJson(ack,identity.privateKey)}};
    }
    case 'commit':{
      if(!pending||!Array.isArray(args.acks)||args.acks.length!==N)throw new Error('commit requires five signed approvals');
      const seen=new Set();
      for(const ack of args.acks){
        if(!ack||Object.keys(ack).sort().join(',')!=='epoch,id,roundDigest,signature'||
          seen.has(ack.id)||ack.epoch!==pending.epoch||ack.roundDigest!==pending.roundDigest)throw new Error('invalid/different approval');
        const {signature,...body}=ack;
        if(!verifyJson(body,signature,registry.get(ack.id)))throw new Error('bad approval signature');
        seen.add(ack.id);
      }
      if(seen.size!==N)throw new Error('missing approval');
      share=pending.share;blind=pending.blind;commitments=pending.commitments;epoch=pending.epoch;
      pending=null;nextTransport=null;nextManifest=null;peerManifests=null;
      return {epoch,commitmentFingerprint:sha256(commitments),ready:true};
    }
    case 'abort':{
      pending=null;nextTransport=null;nextManifest=null;peerManifests=null;
      return {epoch,aborted:true};
    }
    case 'state':{
      return {epoch,ready:share!==null,commitmentFingerprint:commitments?sha256(commitments):null,pending:!!pending};
    }
    case 'recover-for-test':{
      if(process.env.QS_V08_LAB_ONLY!=='1'||share===null)throw new Error('test-only recovery forbidden');
      return {epoch,x:localId,y:scalarEncode(share),blind:scalarEncode(blind),commitments};
    }
    default:throw new Error('unknown lab command');
  }
}
process.on('message',({id,cmd,args})=>{
  try {process.send?.({id,ok:true,result:msg(cmd,args)});}
  catch(e){process.send?.({id,ok:false,error:String(e.message).slice(0,240)});}
});
