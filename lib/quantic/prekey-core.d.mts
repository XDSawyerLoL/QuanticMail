export type SignedPreKeyRecord = {
  version: 1;
  canonicalAddress: string;
  deviceId: string;
  preKeyId: string;
  publicKey: JsonWebKey;
  createdAt: string;
  expiresAt: string;
  signature: string;
};

export function validatePreKeyRecord(record: SignedPreKeyRecord, requireSignature?: boolean): SignedPreKeyRecord;
export function canonicalPreKeyText(record: SignedPreKeyRecord): string;
export function isPreKeyExpired(record: SignedPreKeyRecord, now?: number): boolean;
export function verifyPreKeySignature(record: SignedPreKeyRecord, deviceSigningPublicKey: JsonWebKey): Promise<boolean>;
