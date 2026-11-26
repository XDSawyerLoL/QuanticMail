// Explicit offline operator action, no HTTP endpoint and no key export.
// A separate externally approved previousHash is MANDATORY.
// Never run with a real user account or copy a signing key into an
// authority service directory.
import {approveNativeAuthorityRenewalLab} from '../standalone-relay/native-authority-approval-lab.mjs';
try{
 const [directory,configPin,operatorKeyFile,sequenceText,previousHash,flag]=process.argv.slice(2);
 if(process.platform!=='linux'||process.argv.length!==8||flag!=='--synthetic-only'
  ||!/^([1-9][0-9]{0,5})$/.test(sequenceText))
  throw Error('Explicit synthetic Linux operator invocation required');
 const result=await approveNativeAuthorityRenewalLab({
  directory,configPin,operatorKeyFile,sequence:Number(sequenceText),previousHash
 });
 process.stdout.write(JSON.stringify(result)+'\n');
}catch{
 process.stderr.write('Operator approval REFUSED: a separate public trust pin, monotonic generation and recent real snapshot are required. No keys or snapshots modified.\n');
 process.exitCode=1;
}
