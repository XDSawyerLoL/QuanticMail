/**
 * QuanticMail publication posture guard.
 * This is a release *declaration* check, not a cryptographic audit, code
 * attestation, or protection against someone with write access to the workflow.
 *
 * A sensitive artifact must never be enabled by this local, mutable JSON.
 * Only a future separate, protected and independently validated approval chain
 * may authorize real identity cutover or real payments.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

const CAPABILITIES = [
  'realNativeIdentityCutover',
  'deletionOfLegacyPrivateKeys',
  'postCompromiseSecurityGuarantee',
  'endToEndAnonymityGuarantee',
  'realMoneyAuthorization',
  'digitalEuroCompatibilityGuarantee',
];
const CHANNELS = ['--assert-web', '--assert-desktop', '--assert-sensitive', '--check'];

function sameKeys(record, keys) {
  return record !== null && typeof record === 'object' && !Array.isArray(record) &&
    JSON.stringify(Object.keys(record).sort()) === JSON.stringify([...keys].sort());
}
export function inspectReleaseBoundary(document, mode) {
  if (!CHANNELS.includes(mode)) throw new Error('Unknown release mode');
  if (!sameKeys(document, ['schema','format','reviewedAt','releaseClass','product','capabilities','labels','securityAudit','independentAssurance']) ||
    document.schema !== 1 || document.format !== 'quantic-release-boundary/1' ||
    !/^\d{4}-\d\d-\d\d$/.test(document.reviewedAt) ||
    document.product !== 'QuanticMail' || document.releaseClass !== 'legacy-experimental' ||
    document.securityAudit !== 'NOT_COMPLETED' ||
    document.independentAssurance !== 'NOT_APPROVED' ||
    !sameKeys(document.capabilities,CAPABILITIES) ||
    !sameKeys(document.labels,['web','desktop']) ||
    Object.values(document.labels).some(x=>typeof x!=='string'||x.length<12||x.length>300)) {
    throw new Error('Invalid or unsupported release boundary document');
  }
  if (CAPABILITIES.some(k=>document.capabilities[k] !== false)) {
    throw new Error('Unverified production capabilities/claims must remain disabled');
  }
  const digest=createHash('sha256').update(JSON.stringify(document)).digest('hex');
  if(mode === '--assert-sensitive') {
    throw new Error('Sensitive Quantic release forbidden without protected independent proof chain');
  }
  // Prevent accidental activation through common build switches. This list is
  // supplemental only: it cannot certify all possible runtime code paths.
  for(const [key,value] of Object.entries(process.env)){
    if(/^QUANTIC_(?:ENABLE_REAL_PAYMENTS|ENABLE_LIVE_CUTOVER|CLAIM_ANONYMITY|CLAIM_POSTCOMPROMISE|CERTIFIED_RELEASE)$/.test(key) &&
       /^(1|true|on|yes)$/i.test(value)) {
       throw new Error('Sensitive build environment switch forbidden: '+key);
    }
  }
  return {
    accepted:true,channel:mode,releaseClass:document.releaseClass,
    policySha256:digest,declaredSensitiveCapabilities:false,
    auditStatus:'UNVERIFIED',
    note:'Declaration guard only; requires protected branch rules and runtime enforcement.',
  };
}
function cli() {
  const args=process.argv.slice(2);
  if(args.length !== 1 || !CHANNELS.includes(args[0])) {
    throw new Error('Usage: node scripts/assert-release-boundary.mjs --assert-web|--assert-desktop|--assert-sensitive|--check');
  }
  const target=fileURLToPath(new URL('../security/release-boundary.json', import.meta.url));
  const doc=JSON.parse(readFileSync(target,'utf8'));
  console.log(JSON.stringify(inspectReleaseBoundary(doc,args[0]),null,2));
}
if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try {cli();} catch(error) {
    console.error('Quantic publication refused: '+error.message);
    process.exitCode=2;
  }
}
