export type DurableRouteDecision=
 |Readonly<{kind:"unmanaged"}>
 |Readonly<{kind:"legacy-dev"}>
 |Readonly<{kind:"refuse";reason:string}>
 |Readonly<{kind:"durable";origin:string}>;
export function decideQuanticDurableRoute(
 path:string,ownOrigin:string,backend:string|undefined,
 production?:boolean,ready?:boolean
):DurableRouteDecision;
export function allowedRelayHeaders(requestHeaders:Headers):Headers;
export const STATEFUL_QUANTIC_PATHS:readonly string[];
