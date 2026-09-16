export type UnsignedPreKeyRecord = {
  version: 1;
  canonicalAddress: string;
  deviceId: string;
  preKeyId: string;
  publicKey: JsonWebKey;
  createdAt: string;
  expiresAt: string;
};

export type SignedPreKeyRecord = UnsignedPreKeyRecord & {
  signature: string;
};

export function validatePreKeyRecord(record: UnsignedPreKeyRecord | SignedPreKeyRecord, requireSignature?: boolean): UnsignedPreKeyRecord | SignedPreKeyRecord;
export function canonicalPreKeyText(record: UnsignedPreKeyRecord | SignedPreKeyRecord): string;
export function isPreKeyExpired(record: UnsignedPreKeyRecord | SignedPreKeyRecord, now?: number): boolean;
export function verifyPreKeySignature(record: SignedPreKeyRecord, deviceSigningPublicKey: JsonWebKey): Promise<boolean>;
