import type { QuanticPortableEnvelope } from "./federation-types";
import type { QuanticIdentityManifest } from "./manifest-types";

export function verifyPortableEnvelope(
  envelope: QuanticPortableEnvelope,
  senderIdentityManifest: QuanticIdentityManifest,
  senderCryptoProfile?: unknown,
  nowMs?: number,
): QuanticPortableEnvelope;
