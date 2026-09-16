export {};

declare global {
  interface JsonWebKey {
    // DOM's JsonWebKey lacks Node's index signature although the runtime JWK object is compatible.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    [key: string]: any;
  }
}
