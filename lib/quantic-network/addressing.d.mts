export type QuanticLocator =
  | { kind: "canonical"; value: string; handle: string }
  | { kind: "handle"; value: string; handle: string };

export function isCanonicalQuanticAddress(value: unknown): boolean;
export function normalizeQuanticLocator(value: unknown): QuanticLocator;
