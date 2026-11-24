import {readdirSync,readFileSync,lstatSync} from 'node:fs';
import {join,relative,resolve,basename} from 'node:path';
import {pathToFileURL} from 'node:url';

const forbiddenNames=new Set(['durable-web-relay-route.mjs','main.cjs','hostinger-main.ts','next.config.ts','proxy.ts']);
const forbiddenRoot=new Set(['app','components','public','node_modules','.next','out']);
const oldAdapter=/(?:^|[\/'"\s])durable-web-relay-route\.mjs(?:['"\s]|$)/m;

export function verifyNativePayload(root){
 root=resolve(root);
 const walk=(dir)=>{
  for(const entry of readdirSync(dir,{withFileTypes:true})){
   const full=join(dir,entry.name);
   const path=relative(root,full).replaceAll('\\','/');
   const base=basename(full).toLowerCase();
   if(entry.isSymbolicLink()||lstatSync(full).isSymbolicLink())throw Error('Unexpected link in installer payload: '+path);
   if(forbiddenRoot.has(path.split('/')[0].toLowerCase())||forbiddenNames.has(base))throw Error('Legacy Web payload refused: '+path);
   if(entry.isDirectory())walk(full);
   else if(entry.isFile()&&/\.(?:mjs|cjs|js|ts|ps1)$/i.test(base)&&oldAdapter.test(readFileSync(full,'utf8')))throw Error('Legacy Web route reference refused: '+path);
  }
 };
 walk(root);
 return true;
}

if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
 if(process.argv.length!==3)throw Error('Expected staged package directory');
 verifyNativePayload(process.argv[2]);
 console.log('Native installer payload boundary passed');
}
