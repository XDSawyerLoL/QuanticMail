export type PublicIdentityView=Readonly<{
 handle:string;
 address:string;
 canonicalAddress:string|undefined;
 fingerprint:string|undefined;
}>;
export function publicIdentityView(identity:{
 handle:string;address:string;canonicalAddress?:string;fingerprint?:string;
}):PublicIdentityView;
