export function registryCheckpointMessage(path, sequence) {
  if (typeof path !== "string" || !path) throw new Error("Chemin de registre invalide.");
  if (!Number.isSafeInteger(sequence) || sequence < 1) throw new Error("Séquence de registre invalide.");
  const match = /\/([0-9a-f]{16,64})\.json$/i.exec(path);
  if (!match) throw new Error("Chemin de registre non canonique.");
  return `registry: checkpoint ${match[1].slice(0, 16).toLowerCase()} #${sequence}`;
}
