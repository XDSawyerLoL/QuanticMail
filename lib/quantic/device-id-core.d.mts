export function publicDevicePoint(key: JsonWebKey): string;
export function deviceDigestHex(key: JsonWebKey): Promise<string>;
export function deviceIdFromDigestHex(digestHex: string, length?: 10 | 32): string;
export function deviceIdForPublicKey(key: JsonWebKey, length?: 10 | 32): Promise<string>;
export function isValidDeviceId(value: unknown): value is string;
export function assertDeviceIdMatchesDigest(deviceId: string, digestHex: string): string;
export function assertDeviceIdMatchesKey(deviceId: string, key: JsonWebKey): Promise<string>;
