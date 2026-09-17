import {
  generateLocalPqcKeyMaterial,
  type LocalPqcKeyMaterial,
} from "@/lib/quantic/device-pqc";
import type { QuanticIdentityManifest } from "@/lib/quantic/manifest-types";

export type DeviceCertificatePayload = {
  version: 1;
  canonicalAddress: string;
  handle: string;
  fingerprint: string;
  identityPublicKey: JsonWebKey;
  identitySigningPublicKey: JsonWebKey;
  deviceId: string;
  deviceLabel: string;
  devicePublicKey: JsonWebKey;
  deviceSigningPublicKey: JsonWebKey;
  issuedAt: string;
};

export type DeviceCertificate = {
  format: "quantic-device-certificate";
  version: 1;
  payload: DeviceCertificatePayload;
  signature: string;
};

export type LocalIdentity = {
  handle: string;
  address: string;
  canonicalAddress?: string;
  fingerprint?: string;
  publicKey: JsonWebKey;
  privateKey: JsonWebKey;
  signingPublicKey?: JsonWebKey;
  signingPrivateKey?: JsonWebKey;
  deviceId?: string;
  deviceLabel?: string;
  deviceSigningPublicKey?: JsonWebKey;
  deviceSigningPrivateKey?: JsonWebKey;
  deviceCertificate?: DeviceCertificate;
  manifest?: QuanticIdentityManifest;
  role?: "root" | "secondary";
  pqc?: LocalPqcKeyMaterial;
  authToken: string;
  createdAt: string;
};

export type LocalMessage = {
  id: string;
  direction: "in" | "out";
  from: string;
  to: string;
  subject: string;
  body: string;
  createdAt: string;
};

export type LocalContactDevice = {
  deviceId: string;
  label: string;
  publicKey: JsonWebKey;
  deviceSigningPublicKey?: JsonWebKey;
  kind?: "root" | "linked";
};

export type LocalContact = {
  handle: string;
  address: string;
  canonicalAddress?: string;
  fingerprint?: string;
  publicKey: JsonWebKey;
  signingPublicKey?: JsonWebKey;
  manifestSequence?: number;
  devices?: LocalContactDevice[];
  firstSeenAt: string;
  lastSeenAt: string;
};

export type LocalOutboxItem = {
  id: string;
  from: string;
  to: string;
  recipientDeviceId?: string;
  ciphertext: string;
  iv: string;
  ephemeralPublicKey: JsonWebKey;
  keyMode?: "one-time-prekey" | "static-fallback";
  preKeyId?: string;
  logicalMessageId?: string;
  syncCopy?: boolean;
  createdAt: string;
  lastAttemptAt?: string;
};

export type LocalPendingDevice = {
  canonicalAddress: string;
  deviceId: string;
  deviceLabel: string;
  publicKey: JsonWebKey;
  privateKey: JsonWebKey;
  deviceSigningPublicKey: JsonWebKey;
  deviceSigningPrivateKey: JsonWebKey;
  pqc?: LocalPqcKeyMaterial;
  authToken: string;
  createdAt: string;
};

export type LocalPreKey = {
  version: 1;
  canonicalAddress: string;
  deviceId: string;
  preKeyId: string;
  publicKey: JsonWebKey;
  privateKey: JsonWebKey;
  createdAt: string;
  expiresAt: string;
  signature: string;
  state: "unused" | "claimed";
};

const DB_NAME = "quanticmail-local";
const DB_VERSION = 6;

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains("identity")) db.createObjectStore("identity");
      if (!db.objectStoreNames.contains("messages")) {
        const store = db.createObjectStore("messages", { keyPath: "id" });
        store.createIndex("createdAt", "createdAt");
      }
      if (!db.objectStoreNames.contains("contacts")) {
        db.createObjectStore("contacts", { keyPath: "handle" });
      }
      if (!db.objectStoreNames.contains("outbox")) {
        const store = db.createObjectStore("outbox", { keyPath: "id" });
        store.createIndex("createdAt", "createdAt");
      }
      if (!db.objectStoreNames.contains("pairing")) db.createObjectStore("pairing");
      if (!db.objectStoreNames.contains("prekeys")) {
        const store = db.createObjectStore("prekeys", { keyPath: "preKeyId" });
        store.createIndex("expiresAt", "expiresAt");
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

export async function getLocalIdentity(): Promise<LocalIdentity | null> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("identity", "readonly");
    const request = tx.objectStore("identity").get("current");
    request.onsuccess = () => resolve((request.result as LocalIdentity | undefined) ?? null);
    request.onerror = () => reject(request.error);
  });
}

export async function saveLocalIdentity(identity: LocalIdentity) {
  const pqc = identity.pqc ?? (await generateLocalPqcKeyMaterial());
  const next: LocalIdentity = {
    ...identity,
    pqc: pqc ?? undefined,
  };
  const db = await openDb();
  return new Promise<void>((resolve, reject) => {
    const tx = db.transaction("identity", "readwrite");
    tx.objectStore("identity").put(next, "current");
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function saveLocalMessage(message: LocalMessage) {
  const db = await openDb();
  return new Promise<void>((resolve, reject) => {
    const tx = db.transaction("messages", "readwrite");
    tx.objectStore("messages").put(message);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function importLocalMessages(messages: LocalMessage[]) {
  const db = await openDb();
  return new Promise<{ imported: number; existing: number }>((resolve, reject) => {
    const tx = db.transaction("messages", "readwrite");
    const store = tx.objectStore("messages");
    const request = store.getAllKeys();
    let imported = 0;
    let existing = 0;
    request.onsuccess = () => {
      const known = new Set(request.result.map(String));
      for (const message of messages) {
        if (known.has(message.id)) {
          existing += 1;
          continue;
        }
        known.add(message.id);
        store.put(message);
        imported += 1;
      }
    };
    request.onerror = () => reject(request.error);
    tx.oncomplete = () => resolve({ imported, existing });
    tx.onerror = () => reject(tx.error);
  });
}

export async function listLocalMessages(): Promise<LocalMessage[]> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("messages", "readonly");
    const request = tx.objectStore("messages").getAll();
    request.onsuccess = () => {
      const rows = (request.result as LocalMessage[]).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
      resolve(rows);
    };
    request.onerror = () => reject(request.error);
  });
}

export async function getLocalContact(handle: string): Promise<LocalContact | null> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("contacts", "readonly");
    const request = tx.objectStore("contacts").get(handle);
    request.onsuccess = () => resolve((request.result as LocalContact | undefined) ?? null);
    request.onerror = () => reject(request.error);
  });
}

export async function saveLocalContact(contact: LocalContact) {
  const db = await openDb();
  return new Promise<void>((resolve, reject) => {
    const tx = db.transaction("contacts", "readwrite");
    tx.objectStore("contacts").put(contact);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function saveOutboxItem(item: LocalOutboxItem) {
  const db = await openDb();
  return new Promise<void>((resolve, reject) => {
    const tx = db.transaction("outbox", "readwrite");
    tx.objectStore("outbox").put(item);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function listOutboxItems(): Promise<LocalOutboxItem[]> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("outbox", "readonly");
    const request = tx.objectStore("outbox").getAll();
    request.onsuccess = () => {
      const rows = (request.result as LocalOutboxItem[]).sort((a, b) => a.createdAt.localeCompare(b.createdAt));
      resolve(rows);
    };
    request.onerror = () => reject(request.error);
  });
}

export async function deleteOutboxItem(id: string) {
  const db = await openDb();
  return new Promise<void>((resolve, reject) => {
    const tx = db.transaction("outbox", "readwrite");
    tx.objectStore("outbox").delete(id);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function getPendingDevice(): Promise<LocalPendingDevice | null> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("pairing", "readonly");
    const request = tx.objectStore("pairing").get("pending-device");
    request.onsuccess = () => resolve((request.result as LocalPendingDevice | undefined) ?? null);
    request.onerror = () => reject(request.error);
  });
}

export async function savePendingDevice(device: LocalPendingDevice) {
  const db = await openDb();
  return new Promise<void>((resolve, reject) => {
    const tx = db.transaction("pairing", "readwrite");
    tx.objectStore("pairing").put(device, "pending-device");
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function clearPendingDevice() {
  const db = await openDb();
  return new Promise<void>((resolve, reject) => {
    const tx = db.transaction("pairing", "readwrite");
    tx.objectStore("pairing").delete("pending-device");
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function saveLocalPreKeys(prekeys: LocalPreKey[]) {
  if (!prekeys.length) return;
  const db = await openDb();
  return new Promise<void>((resolve, reject) => {
    const tx = db.transaction("prekeys", "readwrite");
    const store = tx.objectStore("prekeys");
    for (const prekey of prekeys) store.put(prekey);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function getLocalPreKey(preKeyId: string): Promise<LocalPreKey | null> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("prekeys", "readonly");
    const request = tx.objectStore("prekeys").get(preKeyId);
    request.onsuccess = () => resolve((request.result as LocalPreKey | undefined) ?? null);
    request.onerror = () => reject(request.error);
  });
}

export async function listAvailableLocalPreKeys(now = Date.now()): Promise<LocalPreKey[]> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("prekeys", "readonly");
    const request = tx.objectStore("prekeys").getAll();
    request.onsuccess = () => {
      resolve((request.result as LocalPreKey[]).filter(
        (item) => item.state === "unused" && Date.parse(item.expiresAt) > now,
      ));
    };
    request.onerror = () => reject(request.error);
  });
}

export async function countAvailableLocalPreKeys(now = Date.now()) {
  return (await listAvailableLocalPreKeys(now)).length;
}

export async function deleteLocalPreKey(preKeyId: string) {
  const db = await openDb();
  return new Promise<void>((resolve, reject) => {
    const tx = db.transaction("prekeys", "readwrite");
    tx.objectStore("prekeys").delete(preKeyId);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}
