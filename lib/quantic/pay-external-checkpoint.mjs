// Conventional external checkpoint equality guard, laboratory only.
// The caller must obtain the expected value from an independently protected
// trusted source. A file restored with the replica is NOT such a source.
const check=v=>{if(!v)throw Error('External Pay checkpoint mismatch; refuse to open');};
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const exact=(o,k)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===k.length&&k.every(x=>Object.hasOwn(o,x));
function entry(v){
 if(v===null)return null;
 check(exact(v,['scope','count','root'])&&hex(v.scope)&&hex(v.root)&&Number.isInteger(v.count)&&v.count>=0&&v.count<=256);
 return [v.scope,v.count,v.root];
}
function tuple(c){
 check(exact(c,['format','network','authorityPin','sequence','root','admission','financial'])&&c.format==='quantic-pay-external-checkpoint/v1'&&hex(c.network)&&hex(c.authorityPin)&&hex(c.root)&&Number.isInteger(c.sequence)&&c.sequence>=0&&c.sequence<=32);
 return [c.format,c.network,c.authorityPin,c.sequence,c.root,entry(c.admission),entry(c.financial)];
}
export function assertExternalPayCheckpoint(actual,expected){
 check(JSON.stringify(tuple(actual))===JSON.stringify(tuple(expected)));
 return true;
}
