// Offline operator command; do not run while the replica or old anchor
// is active. Expected checkpoint must be from independent current custody.
import {preparePayAnchorReplacement} from '../lib/quantic/pay-anchor-recovery.mjs';
import {config,exact,check} from '../lib/quantic/pay-anchor-config.mjs';
try{
 check(process.argv.length===3);
 const c=config(process.argv[2]);
 check(exact(c,['quorumFile','replaceIndex','expectedCheckpointFile','replacementServerFile','replacementClientFile','outputQuorumFile','offlineConfirmed']));
 const result=preparePayAnchorReplacement(c);
 console.log(JSON.stringify(result));
}catch{console.error('Pay anchor recovery refused; no automatic retry or quorum downgrade');process.exitCode=1;}
