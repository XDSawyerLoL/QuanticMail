export type EncryptedPairingPackage = {
  version: 1;
  iv: string;
  ciphertext: string;
};

export function randomPairingSecret(): string;
export function encryptPairingPackage(
  secret: string,
  inviteId: string,
  payload: unknown,
): Promise<EncryptedPairingPackage>;
export function decryptPairingPackage<T = unknown>(
  secret: string,
  inviteId: string,
  encrypted: EncryptedPairingPackage,
): Promise<T>;
