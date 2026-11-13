"use strict";

const MAIL_URL = "https://mediumorchid-badger-314305.hostingersite.com/mail/";

function isMailUrl(raw) {
  try {
    const url = new URL(raw);
    return (
      url.protocol === "https:" &&
      url.origin === new URL(MAIL_URL).origin &&
      (url.pathname === "/mail" || url.pathname.startsWith("/mail/")) &&
      !url.username &&
      !url.password
    );
  } catch {
    return false;
  }
}

function isSafeExternal(raw) {
  try {
    const url = new URL(raw);
    return (
      (url.protocol === "https:" && !url.username && !url.password) ||
      url.protocol === "mailto:"
    );
  } catch {
    return false;
  }
}

module.exports = { MAIL_URL, isMailUrl, isSafeExternal };
