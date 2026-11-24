// Only a trusted local operator may invoke this function. No request route.
import {exportRelayState,restoreRelayState} from '../lib/quantic/relay-state.ts';
import {prepareNativeEnrollmentPublication,publicNativeEnrollmentSnapshot} from '../lib/quantic/native-enrollment-registry.mjs';
export async function publishNativeEnrollment(runtime,{request,votes,credential,options}){
 return runtime.mutate(()=>{
  const before=exportRelayState();
  const result=prepareNativeEnrollmentPublication(before,request,votes,credential,options);
  try{restoreRelayState(result.state);}catch(e){restoreRelayState(before);throw e;}
  return result.report;
 });
}
export async function exportNativeAuthoritySnapshot(runtime){
 return runtime.read(()=>publicNativeEnrollmentSnapshot(exportRelayState()));
}
