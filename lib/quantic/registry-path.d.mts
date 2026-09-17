export function normalizeCanonicalAddress(value: string): string;
export function normalizeRegistryHandle(value: string): string;
export function filterRegistryManifestsByHandle<T extends {
  payload?: {
    handle?: string;
    canonicalAddress?: string;
  };
}>(locator: string, manifests: T[]): T[];
export function registryFilePath(canonicalAddress: string): string;
