// Legacy entry points are deliberately disabled; never start a server or publish a bundle.
console.error("Quantic Sillage: legacy Web/Electron/HTTP relay retired. Use the native installer. Existing data must be preserved for verified migration.");
process.exitCode = 1;
