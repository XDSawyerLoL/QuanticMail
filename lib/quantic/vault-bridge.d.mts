export declare const VAULT_BRIDGE_URL: string;
export declare const VAULT_AUDIENCE: string;

export interface QuanticIdStatus {
  available: boolean;
  keyId: string | null;
  label: string;
  algorithm: string;
  publicKey: string | null;
  hardwareMode: boolean;
}

export interface VerifiedQuanticId {
  keyId: string;
  label: string;
}

export declare function validateVaultStatus(status: unknown): QuanticIdStatus;
export declare function readVaultStatus(fetchImpl?: typeof fetch): Promise<QuanticIdStatus>;
export declare function verifyVaultProof(
  status: QuanticIdStatus,
  proof: unknown,
  challenge: string,
  cryptoImpl?: Crypto,
  now?: number,
): Promise<VerifiedQuanticId>;
export declare function verifyUnlockedVault(
  status: QuanticIdStatus,
  fetchImpl?: typeof fetch,
  cryptoImpl?: Crypto,
): Promise<VerifiedQuanticId>;
