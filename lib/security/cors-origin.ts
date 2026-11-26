// Exact-origin CORS for the Next API. Native clients without Origin remain supported.
export function corsOrigin(origin:string|null, ownOrigin:string, configured:string):string|null {
  if(!origin) return null;
  try {
    const url=new URL(origin);
    if(url.origin!==origin || url.username || url.password) return null;
    if(origin===ownOrigin && ["http:","https:"].includes(url.protocol))return origin;
    if(url.protocol!=="https:")return null;
    return configured.split(",").map(x=>x.trim()).includes(origin)?origin:null;
  } catch {return null;}
}
