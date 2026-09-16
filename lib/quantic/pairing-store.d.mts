export type PairingStore = { invites: Map<string, unknown> };
export type PairingRoot = { canonicalAddress: string; rootDeviceId: string };
export function createPairingStore(): PairingStore;
export function createInvite(
  store: PairingStore,
  root: PairingRoot,
  secret: string,
  now?: number,
  ttlMs?: number,
): { inviteId: string; expiresAt: number };
export function submitPairingRequest(store: PairingStore, inviteId: string, secret: string, request: unknown, now?: number): { accepted: true; expiresAt: number };
export function getPairingRequest(store: PairingStore, inviteId: string, secret: string, now?: number): unknown | null;
export function attachPairingPackage(store: PairingStore, inviteId: string, secret: string, encryptedPackage: unknown, now?: number): { stored: true; bytes: number; expiresAt: number };
export function takePairingPackage(store: PairingStore, inviteId: string, secret: string, now?: number): unknown;
export function pairingStatus(store: PairingStore, inviteId: string, secret: string, now?: number): {
  inviteId: string;
  canonicalAddress: string;
  rootDeviceId: string;
  expiresAt: number;
  hasRequest: boolean;
  hasPackage: boolean;
};
