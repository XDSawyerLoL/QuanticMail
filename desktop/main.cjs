/* eslint-disable @typescript-eslint/no-require-imports */
const { app, BrowserWindow, shell, dialog } = require("electron");

const MAIL_ORIGIN = "https://quanticmail.onrender.com";
const ALLOWED_EXTERNAL_ORIGINS = new Set([
  "https://mediumorchid-badger-314305.hostingersite.com"
]);

function parseUrl(raw) {
  try { return new URL(raw); } catch { return null; }
}

function isMailUrl(raw) {
  const url = parseUrl(raw);
  return Boolean(url && url.protocol === "https:" && url.origin === MAIL_ORIGIN);
}

function isAllowedExternal(raw) {
  const url = parseUrl(raw);
  return Boolean(url && url.protocol === "https:" && ALLOWED_EXTERNAL_ORIGINS.has(url.origin));
}

function openAllowedExternal(raw) {
  if (!isAllowedExternal(raw)) return;
  void shell.openExternal(raw).catch(() => {});
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
      spellcheck: true
    }
  });

  // A remote page must never be able to spawn a privileged window.
  win.webContents.setWindowOpenHandler(({ url }) => {
    openAllowedExternal(url);
    return { action: "deny" };
  });

  const guardNavigation = (event, url) => {
    if (isMailUrl(url)) return;
    event.preventDefault();
    openAllowedExternal(url);
  };
  win.webContents.on("will-navigate", guardNavigation);
  win.webContents.on("will-redirect", guardNavigation);

  // Prevent permission prompts and privileged capabilities from remote content.
  const session = win.webContents.session;
  session.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));
  session.setPermissionCheckHandler(() => false);

  win.webContents.on("did-fail-load", (_event, code, description, validatedURL, isMainFrame) => {
    if (!isMainFrame || code === -3 || !isMailUrl(validatedURL)) return;
    void dialog.showMessageBox(win, {
      type: "warning",
      title: "Connexion indisponible",
      message: "QuanticMail ne peut pas charger son service.",
      detail: "Vérifiez votre connexion Internet, puis relancez l'application. Aucun terminal n'est nécessaire.",
      buttons: ["Réessayer", "Fermer"],
      defaultId: 0,
      cancelId: 1
    }).then(({ response }) => {
      if (win.isDestroyed()) return;
      if (response === 0) void win.loadURL(MAIL_ORIGIN).catch(() => {});
      else win.close();
    }).catch(() => {});
  });

  void win.loadURL(MAIL_ORIGIN).catch(() => {});
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
