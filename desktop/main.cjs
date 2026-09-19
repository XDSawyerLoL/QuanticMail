const { app, BrowserWindow, shell } = require("electron");

const MAIL_ORIGIN = "https://quanticmail.onrender.com";
const PORTAL_ORIGIN = "https://mediumorchid-badger-314305.hostingersite.com";

function isMailUrl(raw) {
  try {
    const url = new URL(raw);
    return url.origin === MAIL_ORIGIN;
  } catch {
    return false;
  }
}

function isSafeExternal(raw) {
  try {
    const url = new URL(raw);
    return url.protocol === "https:" || url.protocol === "mailto:";
  } catch {
    return false;
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
      spellcheck: true
    }
  });

  win.webContents.setWindowOpenHandler(({ url }) => {
    if (isMailUrl(url)) return { action: "allow" };
    if (isSafeExternal(url)) shell.openExternal(url);
    return { action: "deny" };
  });

  win.webContents.on("will-navigate", (event, url) => {
    if (isMailUrl(url)) return;
    event.preventDefault();
    if (isSafeExternal(url)) shell.openExternal(url);
  });

  win.webContents.on("will-redirect", (event, url) => {
    if (isMailUrl(url)) return;
    if (url.startsWith(PORTAL_ORIGIN)) {
      event.preventDefault();
      shell.openExternal(url);
    }
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
