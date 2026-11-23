// One-shot headless GUI helper. Plaintext is read only over a local private pipe.
import {saveWindowsDraftFromInput} from '../desktop/native-windows-draft.mjs';
try{
 const args=process.argv.slice(2);
 if(process.platform!=='win32'||process.versions.node.split('.')[0]!=='24'||args.length!==3||process.stdin.isTTY)throw Error('Not the Windows GUI lab');
 const chunks=[];let length=0;
 for await(const chunk of process.stdin){
  length+=chunk.length;if(length>8192)throw Error('Input too large');
  chunks.push(chunk);
 }
 const b=Buffer.concat(chunks);for(const chunk of chunks)chunk.fill(0);
 let fields;try{fields=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(b));}finally{b.fill(0);}
 const result=await saveWindowsDraftFromInput({binary:args[0],binarySha256:args[1],dir:args[2]},fields);
 process.stdout.write(JSON.stringify(result)+'\n');
}catch{
 // Never echo draft content or cryptographic configuration into diagnostics.
 process.stderr.write('Le coffre de test ou le contact verifie est indisponible. Aucun brouillon transmis.\n');
 process.exitCode=1;
}
