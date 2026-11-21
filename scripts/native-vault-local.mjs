// Trusted terminal only. Explicit laboratory operation; never invoke from a Web renderer.
import {readFile,stat,open} from 'node:fs/promises';
import {isAbsolute} from 'node:path';
import {connectNativeVault} from '../desktop/native-vault-controller.mjs';
const [configPath,operation,inputPath,outputPath]=process.argv.slice(2);
let controller,output;
try {
  if(process.platform!=='linux'||!process.stderr.isTTY||process.argv.length!==6||!['open-static','sign-enrollment'].includes(operation)||![configPath,inputPath,outputPath].every(p=>typeof p==='string'&&isAbsolute(p)))throw Error('usage: native-vault-local.mjs /absolute/private-config.json open-static|sign-enrollment /absolute/input /absolute/new-output');
  const st=await stat(configPath);
  if(!st.isFile()||st.uid!==process.getuid()||(st.mode&0o077)!==0||st.size>32768)throw Error('private configuration required');
  const config=JSON.parse(await readFile(configPath,'utf8'));
  const source=await stat(inputPath);
  if(!source.isFile()||source.size>32768)throw Error('invalid input');
  const input=await readFile(inputPath,'utf8');
  // Reserve a new private file before requesting an irreversible journal commit.
  output=await open(outputPath,'wx',0o600);
  controller=await connectNativeVault(config);
  const result=operation==='open-static'?await controller.openStatic(JSON.parse(input)):await controller.signEnrollment(input);
  await output.writeFile(JSON.stringify(result)+'\n','utf8');await output.sync();
  process.stderr.write('Native result saved in private output file. No migration or key deletion performed.\n');
}catch{
  process.stderr.write('Native operation failed or was refused. Output may be empty or incomplete; do not automatically retry or delete original data.\n');
  process.exitCode=1;
}finally{controller?.close();await output?.close();}
