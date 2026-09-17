import type { QuanticIdentityManifest } from "./manifest-types.ts";
import type { QuanticCryptoProfileV2 } from "./crypto-profile-core.mjs";

export function verifyCryptoProfile(
  profile: QuanticCryptoProfileV2,
  identityManifest: QuanticIdentityManifest,
  previousProfile?: QuanticCryptoProfileV2 | null,
): QuanticCryptoProfileV2;
