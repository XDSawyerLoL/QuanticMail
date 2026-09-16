export type EnvelopeKeyMode = "one-time-prekey" | "static-fallback";

export type EnvelopeKeyMetadata = {
  keyMode?: EnvelopeKeyMode;
  preKeyId?: string;
};

export type LocalPreKeySelection = {
  preKeyId: string;
  privateKey: JsonWebKey;
  state: "unused" | "claimed";
};

export function selectEnvelopePrivateKey(
  envelope: EnvelopeKeyMetadata,
  staticPrivateKey: JsonWebKey,
  localPreKey: LocalPreKeySelection | null,
): { privateKey: JsonWebKey; consumePreKeyId: string | null };
