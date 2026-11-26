export type DemoPayee={readonly id:string;readonly label:string};
export type DemoIntent={readonly id:string;readonly payeeId:string;readonly cents:number;readonly currency:"EUR";readonly createdAt:number;readonly expiresAt:number;readonly status:"prepared"|"simulated"|"cancelled"|"expired";readonly realPayment:false;readonly settledAt?:number;readonly balanceAfterCents?:number};
export type DemoSnapshot={readonly mode:"simulation";readonly currency:"EUR";readonly redeemable:false;readonly balanceCents:number;readonly pending:DemoIntent|null;readonly history:readonly DemoIntent[]};
export type DemoSandbox={snapshot():DemoSnapshot;prepare(input:{payeeId:string;amount:string}):DemoIntent;confirm(id:string):DemoIntent;cancel(id:string):DemoIntent};
export const PAYEES:readonly DemoPayee[];
export const START_CENTS:number;
export function parseDemoAmount(text:string):number;
export function formatDemoAmount(cents:number):string;
export function createPaySandbox(options?:{clock?:()=>number}):DemoSandbox;
