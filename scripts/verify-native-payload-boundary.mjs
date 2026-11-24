import {readdirSync,readFileSync,lstatSync} from 'node:fs';
import {join,relative,resolve,basename,sep} from 'node:path';
import {pathToFileURL} from 'node:url';

const forbiddenNames=new Set(['durable-web-relay-route.mjs','main.cjs','hostinger-main.ts','next.config.ts','proxy.ts']);
const forbiddenDirs=new Set(['app','components','public','node_modules','.next','out']);
const oldAdapter=/(?:^|[\/'"\s])durable-web-relay-route\.mjs(?:['"\s]|$)/im;
const oldEndpoint=/(?:quanticmail(?:-network-relay)?\.onrender\.com|quantic-network-relay-backup-production\.up\.railway\.app|quantic-hostinger-relay\.invalid)/i;

export function verifyNativePayload(root){
 root=resolve(root);
 const rootInfo=lstatSync(root);
 if(rootInfo.isSymbolicLink()||!rootInfo.isDirectory())throw Error('Expected real installer payload directory');
 const walk=(dir)=>{
  for(const entry of readdirSync(dir,{withFileTypes:true})){
   const full=join(dir,entry.name);
   const path=relative(root,full).split(sep).join('/');
   const base=basename(full).toLowerCase();
   const info=lstatSync(full);
   if(entry.isSymbolicLink()||info.isSymbolicLink())throw Error('Unexpected link in installer payload: '+path);
   if(forbiddenNames.has(base)||(info.isDirectory()&&forbiddenDirs.has(base))||/\.url$/i.test(base))throw Error('Legacy Web payload refused: '+path);
   if(info.isDirectory())walk(full);
   else if(info.isFile()){
    if(/\.(?:mjs|cjs|js|ts|ps1|json|ini|cfg|conf|xml|html|htm)$/i.test(base)){
     const source=readFileSync(full,'utf8');
     if(oldAdapter.test(source))throw Error('Legacy Web route reference refused: '+path);
     if(oldEndpoint.test(source))throw Error('Legacy hosted endpoint refused: '+path);
    }
   }else throw Error('Unexpected entry in installer payload: '+path);
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
