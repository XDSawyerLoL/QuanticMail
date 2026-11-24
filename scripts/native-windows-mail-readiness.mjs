// Trusted Windows console only. Public trust-file SHA256 must be supplied
// independently; private vault configs are read exclusively by the native
// pinned Windows NTFS helper. No approval, no mutation, no network fallback.
import {runWindowsTwoHostReadiness} from '../desktop/native-windows-mail-readiness.mjs';
try{
 const [binary,binarySha256,dir,carrierDir,trustFile,trustSha256,mode]=process.argv.slice(2);
 if(process.platform!=='win32'||Number(process.versions.node.split('.')[0])<24
  ||process.argv.length!==9||!process.stdin.isTTY||!process.stderr.isTTY
  ||!['offline','live'].includes(mode))throw Error('Local Windows console required');
 const report=await runWindowsTwoHostReadiness({
  binary,binarySha256,dir,carrierDir,trustFile,
  trustSha256,live:mode==='live'
 });
 process.stdout.write(JSON.stringify(report)+'\n');
}catch{
 process.stderr.write('Precontrole Windows REFUSE : empreintes de confiance, contacts, autorites ou relais invalides ou indisponibles. Aucune migration, emission ni suppression effectuee.\n');
 process.exitCode=1;
}
