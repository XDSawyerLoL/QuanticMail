/* eslint-disable @typescript-eslint/no-require-imports */
"use strict";
const { join } = require("node:path");
const { app, BrowserWindow, shell, utilityProcess } = require("electron");
const { MAIL_URL, isMailUrl, isSafeExternal } = require("./navigation.cjs");
const { startLocalServer, RELAY_PORT } = require("./local-server.cjs");

let relayProcess = null;
let localServer = null;
let mainWindow = null;

function openExternalIfSafe(url) {
  if (!isSafeExternal(url)) return;
  void shell.openExternal(url).catch((error) => {
    console.warn("Lien externe inaccessible :", error);
  });
}

function waitForLocalRelay() {
  return new Promise((resolve, reject) => {
    const workerPath = join(__dirname, "bundle", "relay-worker.cjs");
    const child = utilityProcess.fork(workerPath, [], {
      serviceName: "Quantic local relay",
      env: {
        ...process.env,
        QUANTIC_RELAY_DATA_DIR: join(app.getPath("userData"), "relay"),
        QUANTIC_LOCAL_RELAY_PORT: String(RELAY_PORT),
        AURA_CLOUD_URL: "",
        AURA_ALLOW_LEGACY_PRODUCT_ADMIN_TOKEN: "false",
        AURA_QUANTIC_MAIL_TOKEN: "",
        AURA_IDENTITY_VAULT_TOKEN: ""
      }
    });
    relayProcess = child;
    let settled = false;
    const timeout = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new Error("Délai de démarrage du relais local dépassé."));
    }, 25000);
    child.on("message", (message) => {
      const payload = message?.data ?? message;
      if (settled) return;
      if (payload?.type === "ready") {
        settled = true; clearTimeout(timeout); resolve(child);
      } else if (payload?.type === "error") {
        settled = true; clearTimeout(timeout);
        reject(new Error(payload.message || "Le relais local a échoué."));
      }
    });
    child.on("exit", (code) => {
      if (settled) return;
      settled = true; clearTimeout(timeout);
      reject(new Error("Le relais local s'est arrêté (code " + code + ")."));
    });
  });
}

function createWindow(url = MAIL_URL) {
  const win = new BrowserWindow({
    width: 1380,
    height: 900,
    minWidth: 980,
    minHeight: 680,
    backgroundColor: "#07111d",
    title: "Quantic Mail",
    autoHideMenuBar: true,
    webPreferences: {
      partition: "persist:quanticmail",
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      spellcheck: true
    }
  });
  mainWindow = win;
  win.webContents.session.setPermissionRequestHandler((_wc, _permission, callback) => callback(false));
  win.webContents.setWindowOpenHandler(({ url: target }) => {
    if (isMailUrl(target)) {
      void win.loadURL(target).catch(() => {});
    } else {
      openExternalIfSafe(target);
    }
    return { action: "deny" };
  });
  win.webContents.on("will-navigate", (event, target) => {
    if (isMailUrl(target)) return;
    event.preventDefault();
    openExternalIfSafe(target);
  });
  win.webContents.on("will-attach-webview", (event) => event.preventDefault());
  void win.loadURL(url).catch((error) => console.error("Interface Quantic locale indisponible :", error));
}

app.whenReady().then(async () => {
  app.setAppUserModelId("com.quanticsillage.quanticmail");
  try {
    await waitForLocalRelay();
    const local = await startLocalServer({ staticRoot: join(__dirname, "bundle", "mail") });
    localServer = local.server;
    createWindow(local.url);
  } catch (error) {
    console.error("Démarrage de Quantic Mail impossible :", error);
    const { dialog } = require("electron");
    dialog.showErrorBox("Quantic Mail — erreur de démarrage",
      (error?.message || String(error)) + "\n\nVérifiez notamment que les ports locaux 18787 et 18788 ne sont pas déjà utilisés.");
    app.quit();
  }
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0 && localServer) createWindow();
  });
});

app.on("before-quit", () => {
  if (localServer) {
    localServer.close();
    localServer = null;
  }
  if (relayProcess) {
    relayProcess.postMessage({ type: "shutdown" });
    relayProcess = null;
  }
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
