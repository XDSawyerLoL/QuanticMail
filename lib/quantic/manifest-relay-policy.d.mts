import type { RelayEndpoint } from "./relay-client";
export declare function manifestRelayPolicy(input: {
  desktop: boolean;
  configured?: RelayEndpoint[];
}): {
  relays: RelayEndpoint[];
  retryStatuses: number[];
};
