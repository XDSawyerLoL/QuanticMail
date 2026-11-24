/* eslint-disable @typescript-eslint/no-require-imports */
const MAIL_ORIGIN = "https://quanticmail.onrender.com";
const PORTAL_ORIGIN = "https://mediumorchid-badger-314305.hostingersite.com";
function trustedOrigin(raw, expected) {
  try {
    const url = new URL(raw);
    return url.protocol === "https:" && !url.username && !url.password && url.origin === expected;
  } catch { return false; }
}
function navigationTarget(raw) {
  if (trustedOrigin(raw, MAIL_ORIGIN)) return "mail";
  if (trustedOrigin(raw, PORTAL_ORIGIN)) return "portal";
  return "deny";
}
module.exports = { MAIL_ORIGIN, PORTAL_ORIGIN, navigationTarget };
