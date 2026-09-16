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

export type LocalContact = {
  handle: string;
  address: string;
  publicKey: JsonWebKey;
  firstSeenAt: string;
  lastSeenAt: string;
};

export type LocalOutboxItem = {
  id: string;
  from: string;
  to: string;
  ciphertext: string;
  iv: string;
  ephemeralPublicKey: JsonWebKey;
  createdAt: string;
  lastAttemptAt?: string;
};

const DB_NAME = "quanticmail-local";
const DB_VERSION = 3;

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
      const rows = (request.result as LocalOutboxItem[]).sort((a, b) =>
        a.createdAt.localeCompare(b.createdAt),
      );
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
