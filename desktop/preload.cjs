"use strict";
// Minimal sandbox-compatible renderer bridge: no filesystem, no arbitrary IPC.
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("quanticNativeProtection", Object.freeze({
  seal: (plaintext) => ipcRenderer.invoke("quantic-native:seal", plaintext),
  unseal: (ciphertext) => ipcRenderer.invoke("quantic-native:unseal", ciphertext),
}));
