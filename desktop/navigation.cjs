"use strict";

const MAIL_URL = "http://127.0.0.1:18787/mail/";

function isMailUrl(raw) {
  try {
    const url = new URL(raw);
    return url.origin === new URL(MAIL_URL).origin &&
      (url.pathname === "/mail" || url.pathname.startsWith("/mail/")) &&
      !url.username && !url.password;
  } catch {
    return false;
  }
}

function isSafeExternal(raw) {
  try {
    const url = new URL(raw);
    return ((url.protocol === "https:" && !url.username && !url.password) ||
      url.protocol === "mailto:");
  } catch {
    return false;
  }
}

module.exports = { MAIL_URL, isMailUrl, isSafeExternal };
