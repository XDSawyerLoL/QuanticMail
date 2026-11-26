/* eslint-disable @typescript-eslint/no-require-imports */
/* Retired hosted-Web navigation contract, kept only to reject older imports.
 * Never reintroduce remote renderer origins or openExternal fallbacks.
 */
function navigationTarget(_raw) { return 'deny'; }
module.exports=Object.freeze({
  MAIL_ORIGIN:null,
  PORTAL_ORIGIN:null,
  navigationTarget
});
