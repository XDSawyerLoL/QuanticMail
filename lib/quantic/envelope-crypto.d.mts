export type EncryptedEnvelopeCore = {
  ciphertext: string;
  iv: string;
  ephemeralPublicKey: JsonWebKey;
};

export function encryptForRecipientCore(
  recipientPublicJwk: JsonWebKey,
  payload: unknown,
): Promise<EncryptedEnvelopeCore>;

export function decryptEnvelopeCore<T>(
  privateJwk: JsonWebKey,
  envelope: EncryptedEnvelopeCore,
): Promise<T>;
