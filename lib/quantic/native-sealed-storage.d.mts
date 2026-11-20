export type WindowsProtectionBridge = {
  seal(plaintext: string): Promise<string>;
  unseal(ciphertext: string): Promise<string>;
};
export declare const NATIVE_SEALED_FORMAT: "quantic-windows-dpapi";
export declare const NATIVE_SEALED_VERSION: 1;
export declare function isNativeSealedRecord(value: unknown): boolean;
export declare function sealNativeRecord<T extends object>(
  value: T, bridge: WindowsProtectionBridge | null, index?: Record<string, unknown>,
): Promise<T | Record<string, unknown>>;
export declare function unsealNativeRecord<T = unknown>(
  value: unknown, bridge: WindowsProtectionBridge | null,
): Promise<T>;
