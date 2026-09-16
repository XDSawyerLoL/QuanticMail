export type PlainMessagePayload = {
  id: string;
  from: string;
  to: string;
  subject: string;
  body: string;
  createdAt: string;
  syncCopy?: boolean;
};

export type TransportEnvelopeMeta = {
  from: string;
  to: string;
  createdAt: string;
};

export type NormalizedLocalMessage = {
  id: string;
  direction: "in" | "out";
  from: string;
  to: string;
  subject: string;
  body: string;
  createdAt: string;
};

export function localMessageFromEnvelope(
  payload: PlainMessagePayload,
  envelope: TransportEnvelopeMeta,
): NormalizedLocalMessage;
