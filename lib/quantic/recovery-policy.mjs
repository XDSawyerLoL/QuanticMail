export function shouldBootstrapRootManifest(role, remoteStatus) {
  return role !== "secondary" && remoteStatus === 404;
}

export function shouldUseStaticFallbackForPreKeyError(status, message = "") {
  if (status === 404) return true;
  return (
    status === 409 &&
    String(message).includes("one-time prekeys") &&
    String(message).includes("manifeste V1 actif")
  );
}
