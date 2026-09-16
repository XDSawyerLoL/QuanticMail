function toHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function assertP256PublicKey(publicJwk) {
  if (
    !publicJwk ||
    publicJwk.kty !== "EC" ||
    publicJwk.crv !== "P-256" ||
    typeof publicJwk.x !== "string" ||
    typeof publicJwk.y !== "string" ||
    !publicJwk.x ||
    !publicJwk.y
  ) {
    throw new Error("Clé publique d’identité invalide.");
  }
}

async function digestHex(publicJwk) {
  assertP256PublicKey(publicJwk);
  const canonical = `P-256:${publicJwk.x}:${publicJwk.y}`;
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(canonical),
  );
  return toHex(new Uint8Array(digest));
}

export async function fingerprintPublicKeyStrong(publicJwk) {
  return (await digestHex(publicJwk)).slice(0, 32);
}
