/* eslint-disable @typescript-eslint/no-require-imports */
const { app, BrowserWindow, shell } = require("electron");

const { MAIL_ORIGIN, navigationTarget } = require("./navigation-policy.cjs");

function target(raw) {
  return navigationTarget(typeof raw === "string" ? raw : raw?.url);
}

function openPortal(raw) {
  if (target(raw) === "portal") {
    const url = typeof raw === "string" ? raw : raw.url;
    void shell.openExternal(url).catch(() => {});
  }
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1380,
    height: 900,
    minWidth: 980,
    minHeight: 680,
    backgroundColor: "#02050b",
    title: "QuanticMail",
    autoHideMenuBar: true,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      webviewTag: false,
      spellcheck: true
    }
  });

  const ses = win.webContents.session;
  ses.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));
  ses.setPermissionCheckHandler(() => false);
  win.webContents.on("will-attach-webview", (event) => event.preventDefault());
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (target(url) === "portal") openPortal(url);
    return { action: "deny" };
  });
  win.webContents.on("will-navigate", (event, url) => {
    if (target(url) === "mail") return;
    event.preventDefault();
    if (target(url) === "portal") openPortal(url);
  });
  win.webContents.on("will-redirect", (event, url) => {
    if (target(url) === "mail") return;
    event.preventDefault();
    // Never launch external handlers from a server-controlled redirect.
  });

  win.loadURL(MAIL_ORIGIN);
}

app.whenReady().then(() => {
  app.setAppUserModelId("com.quanticsillage.quanticmail");
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
