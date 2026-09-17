import { createHash } from "node:crypto";

import {
  canonicalCryptoProfileText,
  type QuanticCryptoProfileV2,
} from "./crypto-profile-core.mjs";
import { verifyCryptoProfile } from "./crypto-profile-node.mjs";
import type { QuanticIdentityManifest } from "./manifest-types.ts";

export function verifyDiscoveryCryptoProfile(
  profile: QuanticCryptoProfileV2,
  identityManifest: QuanticIdentityManifest,
  previousProfile: QuanticCryptoProfileV2 | null = null,
) {
  const verified = verifyCryptoProfile(profile, identityManifest, previousProfile);
  const digest = createHash("sha256")
    .update(canonicalCryptoProfileText(verified.payload), "utf8")
    .digest("hex");
  return { profile: verified, digest };
}
