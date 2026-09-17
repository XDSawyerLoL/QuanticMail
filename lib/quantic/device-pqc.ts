export type LocalPqcKeyMaterial = {
  version: 1;
  mlKemPublicKeySpki: string;
  mlKemPrivateKeyPkcs8: string;
  mlDsaPublicKeySpki: string;
  mlDsaPrivateKeyPkcs8: string;
  createdAt: string;
};

export type PqcDeviceProposalContext = {
  canonicalAddress: string;
  deviceId: string;
  createdAt: string;
};

export type PublicPqcDeviceProposal = {
  version: 1;
  mlKemAlgorithm: "ML-KEM-768";
  mlKemPublicKeySpki: string;
  mlDsaAlgorithm: "ML-DSA-65";
  mlDsaPublicKeySpki: string;
  mlDsaSelfSignature: string;
};

export type BrowserPqcCapabilities = {
  runtime: string;
  mlKem768: boolean;
  mlDsa65: boolean;
  available: boolean;
};

type ModernSubtleCrypto = SubtleCrypto & {
  encapsulateBits?: (algorithm: AlgorithmIdentifier, key: CryptoKey) => Promise<{
    sharedKey: ArrayBuffer;
    ciphertext: ArrayBuffer;
  }>;
  decapsulateBits?: (
    algorithm: AlgorithmIdentifier,
    key: CryptoKey,
    ciphertext: BufferSource,
  ) => Promise<ArrayBuffer>;
};

function subtle(): ModernSubtleCrypto | null {
  return (globalThis.crypto?.subtle as ModernSubtleCrypto | undefined) ?? null;
}

function bytesToBase64url(value: ArrayBuffer | ArrayBufferView) {
  const bytes = value instanceof ArrayBuffer
    ? new Uint8Array(value)
    : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  if (typeof Buffer !== "undefined") return Buffer.from(bytes).toString("base64url");
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64urlToBytes(value: string) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("Valeur base64url PQ invalide.");
  if (typeof Buffer !== "undefined") return new Uint8Array(Buffer.from(value, "base64url"));
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function runtimeLabel() {
  const node = typeof process !== "undefined" ? process.versions?.node : undefined;
  if (node) return `node-webcrypto-${node}`;
  const navigatorName = typeof navigator !== "undefined" ? navigator.userAgent : "browser";
  return navigatorName;
}

async function canGenerate(name: "ML-KEM-768" | "ML-DSA-65", usages: string[]) {
  const api = subtle();
  if (!api) return false;
  try {
    await api.generateKey({ name } as Algorithm, false, usages as KeyUsage[]);
    return true;
  } catch {
    return false;
  }
}

let cachedCapabilities: Promise<BrowserPqcCapabilities> | null = null;

export function detectBrowserPqcCapabilities(): Promise<BrowserPqcCapabilities> {
  if (cachedCapabilities) return cachedCapabilities;
  cachedCapabilities = (async () => {
    const api = subtle();
    if (!api) {
      return { runtime: runtimeLabel(), mlKem768: false, mlDsa65: false, available: false };
    }
    const [mlKem768, mlDsa65] = await Promise.all([
      canGenerate("ML-KEM-768", ["encapsulateBits", "decapsulateBits"]),
      canGenerate("ML-DSA-65", ["sign", "verify"]),
    ]);
    return {
      runtime: runtimeLabel(),
      mlKem768,
      mlDsa65,
      available: mlKem768 && mlDsa65,
    };
  })();
  return cachedCapabilities;
}

async function exportPair(pair: CryptoKeyPair) {
  const api = subtle();
  if (!api) throw new Error("WebCrypto indisponible.");
  const [publicSpki, privatePkcs8] = await Promise.all([
    api.exportKey("spki", pair.publicKey),
    api.exportKey("pkcs8", pair.privateKey),
  ]);
  return {
    publicKeySpki: bytesToBase64url(publicSpki),
    privateKeyPkcs8: bytesToBase64url(privatePkcs8),
  };
}

export async function generateLocalPqcKeyMaterial(): Promise<LocalPqcKeyMaterial | null> {
  const capabilities = await detectBrowserPqcCapabilities();
  if (!capabilities.available) return null;
  const api = subtle();
  if (!api) return null;

  const [kemPair, dsaPair] = await Promise.all([
    api.generateKey(
      { name: "ML-KEM-768" } as Algorithm,
      true,
      ["encapsulateBits", "decapsulateBits"] as KeyUsage[],
    ) as Promise<CryptoKeyPair>,
    api.generateKey(
      { name: "ML-DSA-65" } as Algorithm,
      true,
      ["sign", "verify"],
    ) as Promise<CryptoKeyPair>,
  ]);
  const [kem, dsa] = await Promise.all([exportPair(kemPair), exportPair(dsaPair)]);
  return {
    version: 1,
    mlKemPublicKeySpki: kem.publicKeySpki,
    mlKemPrivateKeyPkcs8: kem.privateKeyPkcs8,
    mlDsaPublicKeySpki: dsa.publicKeySpki,
    mlDsaPrivateKeyPkcs8: dsa.privateKeyPkcs8,
    createdAt: new Date().toISOString(),
  };
}

function normalizeContext(context: PqcDeviceProposalContext) {
  const canonicalAddress = context.canonicalAddress.trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9._-]{2,31}~(?:[0-9a-f]{10}|[0-9a-f]{32})@quantic$/.test(canonicalAddress)) {
    throw new Error("Adresse canonique de proposition PQ invalide.");
  }
  if (!/^d-[0-9a-f]{10}$/.test(context.deviceId)) {
    throw new Error("deviceId de proposition PQ invalide.");
  }
  if (Number.isNaN(Date.parse(context.createdAt))) {
    throw new Error("Date de proposition PQ invalide.");
  }
  return { canonicalAddress, deviceId: context.deviceId, createdAt: context.createdAt };
}

export function canonicalPqcDeviceProposalText(
  proposal: Omit<PublicPqcDeviceProposal, "mlDsaSelfSignature"> | PublicPqcDeviceProposal,
  context: PqcDeviceProposalContext,
) {
  const normalized = normalizeContext(context);
  if (proposal.version !== 1) throw new Error("Version de proposition PQ invalide.");
  if (proposal.mlKemAlgorithm !== "ML-KEM-768" || proposal.mlDsaAlgorithm !== "ML-DSA-65") {
    throw new Error("Algorithmes de proposition PQ invalides.");
  }
  if (!/^[A-Za-z0-9_-]+$/.test(proposal.mlKemPublicKeySpki) || !/^[A-Za-z0-9_-]+$/.test(proposal.mlDsaPublicKeySpki)) {
    throw new Error("Clés publiques de proposition PQ invalides.");
  }
  return [
    "quantic-device-pqc-proposal-v1",
    normalized.canonicalAddress,
    normalized.deviceId,
    normalized.createdAt,
    "ML-KEM-768",
    proposal.mlKemPublicKeySpki,
    "ML-DSA-65",
    proposal.mlDsaPublicKeySpki,
  ].join("\n");
}

export async function publicPqcDeviceProposal(
  material: LocalPqcKeyMaterial,
  context: PqcDeviceProposalContext,
): Promise<PublicPqcDeviceProposal> {
  const api = subtle();
  if (!api) throw new Error("WebCrypto indisponible.");
  const unsigned = {
    version: 1 as const,
    mlKemAlgorithm: "ML-KEM-768" as const,
    mlKemPublicKeySpki: material.mlKemPublicKeySpki,
    mlDsaAlgorithm: "ML-DSA-65" as const,
    mlDsaPublicKeySpki: material.mlDsaPublicKeySpki,
  };
  const privateKey = await api.importKey(
    "pkcs8",
    base64urlToBytes(material.mlDsaPrivateKeyPkcs8),
    { name: "ML-DSA-65" } as Algorithm,
    false,
    ["sign"],
  );
  const signature = await api.sign(
    { name: "ML-DSA-65" } as Algorithm,
    privateKey,
    new TextEncoder().encode(canonicalPqcDeviceProposalText(unsigned, context)),
  );
  return { ...unsigned, mlDsaSelfSignature: bytesToBase64url(signature) };
}

export async function verifyPqcDeviceProposal(
  proposal: PublicPqcDeviceProposal,
  context: PqcDeviceProposalContext,
) {
  const api = subtle();
  if (!api) return false;
  try {
    const publicKey = await api.importKey(
      "spki",
      base64urlToBytes(proposal.mlDsaPublicKeySpki),
      { name: "ML-DSA-65" } as Algorithm,
      false,
      ["verify"],
    );
    return api.verify(
      { name: "ML-DSA-65" } as Algorithm,
      publicKey,
      base64urlToBytes(proposal.mlDsaSelfSignature),
      new TextEncoder().encode(canonicalPqcDeviceProposalText(proposal, context)),
    );
  } catch {
    return false;
  }
}
