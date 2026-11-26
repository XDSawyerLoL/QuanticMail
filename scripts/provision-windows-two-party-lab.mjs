// Terminal-only two-participant rehearsal; no account enrollment or network.
// Requires the independently verified SHA256 of the native binary and two
// independently obtained quorum pins. Uses TWO isolated directories.
import {twoPartyWindowsPlan,provisionTwoWindowsLab} from '../desktop/windows-two-party-provision-lab.mjs';
let stage='preflight';
try{
 const [binary,binarySha256,root,firstAddress,firstQuorumPin,secondAddress,secondQuorumPin,flag]=process.argv.slice(2);
 if(process.platform!=='win32'||process.argv.length!==10||!process.stdin.isTTY
  ||!process.stderr.isTTY||flag!=='--synthetic-only')
  throw Error('Explicit Windows terminal and synthetic-only switch required');
 const plan=twoPartyWindowsPlan({
  binary,binarySha256,root,
  first:{address:firstAddress,quorumPin:firstQuorumPin},
  second:{address:secondAddress,quorumPin:secondQuorumPin}
 });
 process.stderr.write('DEMONSTRATION FICTIVE : deux nouveaux coffres locaux, sans inscription distante.\n');
 process.stderr.write('Chaque coffre demande son consentement et deux phrases secretes distinctes via le programme natif.\n');
 process.stderr.write('Ne jamais fournir de cles, comptes ou archives Web existants.\n');
 const result=await provisionTwoWindowsLab(plan,{afterEach:async(index,publicRecord)=>{
  stage=index===1?'participant-a-provisioned':'participant-b-provisioned';
  process.stderr.write('Coffre '+index+' local cree et empreintes publiques verifiees : '+publicRecord.address+'\n');
 }});
 stage='completed';
 process.stdout.write(JSON.stringify(result)+'\n');
}catch{
 process.stderr.write('Provisionnement Windows de laboratoire REFUSE a l etape '+stage+
 '. Conserver les repertoires partiels ; ne jamais les ecraser ou les reinitialiser automatiquement.\n');
 process.exitCode=1;
}
