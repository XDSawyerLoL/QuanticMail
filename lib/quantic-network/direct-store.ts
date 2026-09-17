import type { DeliveryReceipt, RelayEnvelope } from "@/lib/quantic/relay";

const DB_NAME = "quantic-network-direct";
const DB_VERSION = 1;
const memoryInbox = new Map<string, RelayEnvelope>();
const memoryReceipts = new Map<string, DeliveryReceipt>();

function hasIndexedDb() {
  return typeof indexedDB !== "undefined";
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains("inbox")) db.createObjectStore("inbox", { keyPath: "id" });
      if (!db.objectStoreNames.contains("receipts")) db.createObjectStore("receipts", { keyPath: "id" });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function put(storeName: "inbox" | "receipts", value: RelayEnvelope | DeliveryReceipt) {
  if (!hasIndexedDb()) {
    (storeName === "inbox" ? memoryInbox : memoryReceipts).set(value.id, value as never);
    return;
  }
  const db = await openDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(storeName, "readwrite");
    tx.objectStore(storeName).put(value);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  db.close();
}

async function list<T>(storeName: "inbox" | "receipts", memory: Map<string, T>): Promise<T[]> {
  if (!hasIndexedDb()) return [...memory.values()];
  const db = await openDb();
  const result = await new Promise<T[]>((resolve, reject) => {
    const request = db.transaction(storeName, "readonly").objectStore(storeName).getAll();
    request.onsuccess = () => resolve(request.result as T[]);
    request.onerror = () => reject(request.error);
  });
  db.close();
  return result;
}

async function remove(storeName: "inbox" | "receipts", ids: string[], memory: Map<string, unknown>) {
  if (!ids.length) return;
  if (!hasIndexedDb()) {
    for (const id of ids) memory.delete(id);
    return;
  }
  const db = await openDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(storeName, "readwrite");
    const store = tx.objectStore(storeName);
    for (const id of ids) store.delete(id);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  db.close();
}

export function putDirectEnvelope(envelope: RelayEnvelope) {
  return put("inbox", envelope);
}

export function listDirectEnvelopes() {
  return list("inbox", memoryInbox);
}

export function deleteDirectEnvelopes(ids: string[]) {
  return remove("inbox", ids, memoryInbox);
}

export function putDirectReceipt(receipt: DeliveryReceipt) {
  return put("receipts", receipt);
}

export function listDirectReceipts() {
  return list("receipts", memoryReceipts);
}

export function deleteDirectReceipts(ids: string[]) {
  return remove("receipts", ids, memoryReceipts);
}
