export type LocalIdentity = {
  handle: string;
  address: string;
  publicKey: JsonWebKey;
  privateKey: JsonWebKey;
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

const DB_NAME = "quanticmail-local";
const DB_VERSION = 1;

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
  const db = await openDb();
  return new Promise<void>((resolve, reject) => {
    const tx = db.transaction("identity", "readwrite");
    tx.objectStore("identity").put(identity, "current");
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

export async function listLocalMessages(): Promise<LocalMessage[]> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("messages", "readonly");
    const request = tx.objectStore("messages").getAll();
    request.onsuccess = () => {
      const rows = (request.result as LocalMessage[]).sort((a, b) =>
        b.createdAt.localeCompare(a.createdAt),
      );
      resolve(rows);
    };
    request.onerror = () => reject(request.error);
  });
}
