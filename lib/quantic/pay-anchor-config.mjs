// Private local provisioning files; no environment or command-line secrets.
import {lstatSync,realpathSync,openSync,readFileSync,closeSync,fstatSync,constants} from 'node:fs';
import {isAbsolute} from 'node:path';
export const check=v=>{if(!v)throw Error('Pay anchor configuration refused');};
export const exact=(o,k)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===k.length&&k.every(x=>Object.hasOwn(o,x));
export const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
export function privateRead(path,max){
 check(process.platform==='linux'&&typeof path==='string'&&isAbsolute(path)&&realpathSync(path)===path);
 const s=lstatSync(path);check(s.isFile()&&s.uid===process.getuid()&&s.nlink===1&&(s.mode&0o077)===0&&s.size>0&&s.size<=max);
 const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW);
 try{const a=fstatSync(fd);check(a.ino===s.ino&&a.dev===s.dev&&a.size===s.size);const b=readFileSync(fd);check(b.length===s.size);return b;}
 finally{closeSync(fd);}
}
export function config(path){const b=privateRead(path,16384);try{return JSON.parse(b.toString('utf8'));}finally{b.fill(0);}}
export const port=p=>Number.isInteger(p)&&p>=1&&p<=65535;
