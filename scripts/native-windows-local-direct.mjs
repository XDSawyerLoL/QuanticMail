import {localDirectOperation} from '../desktop/native-windows-local-direct.mjs';
try{
 const [binary,binarySha256,dir,action]=process.argv.slice(2);
 if(process.platform!=='win32'||process.argv.length!==6||process.stdin.isTTY||process.versions.node.split('.')[0]!=='24')throw Error('GUI pipe required');
 const chunks=[];let n=0;
 for await(const c of process.stdin){n+=c.length;if(n>131072)throw Error('Input bound');chunks.push(c);}
 const raw=Buffer.concat(chunks);for(const c of chunks)c.fill(0);
 let fields;try{fields=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));}finally{raw.fill(0);}
 process.stdout.write(JSON.stringify(await localDirectOperation({binary,binarySha256,dir},action,fields))+'\n');
}catch{process.stderr.write('Operation locale directe non confirmee. Conservez les originaux; aucun renvoi automatique.\n');process.exitCode=1;}
