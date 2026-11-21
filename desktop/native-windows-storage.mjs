// Windows trusted-process adapter. The out-of-band binary pin must not
// originate in the private configuration being opened. No renderer or HTTP.
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {win32} from 'node:path';
const pin=/^[a-f0-9]{64}$/;
const name=/^(desktop\.json|controller\.pem|contacts\.json|peer-[a-z0-9-]{1,48}\.pem|draft-[a-z0-9-]{1,48}\.json|wire-[a-z0-9-]{1,48}\.json)$/;
const check=x=>{if(!x)throw Error('Windows native laboratory refused');};
export function windowsLabPath(dir,path){
 check(typeof dir==='string'&&typeof path==='string'&&win32.isAbsolute(dir)&&/^[A-Za-z]:\\/.test(dir)&&win32.normalize(dir)===dir&&win32.dirname(path)===dir&&name.test(win32.basename(path)));
 return win32.basename(path);
}
export async function createWindowsNativeStorage({binary,binarySha256,dir}){
 check(process.platform==='win32'&&typeof binary==='string'&&win32.isAbsolute(binary)&&pin.test(binarySha256)&&win32.isAbsolute(dir));
 const verifyBinary=async()=>check(createHash('sha256').update(await readFile(binary)).digest('hex')===binarySha256);
 await verifyBinary();
 // Trusted installation directory and OS required. No arbitrary OpenSSL env or PATH.
 const system=process.env.SystemRoot??process.env.SYSTEMROOT;
 check(typeof system==='string'&&win32.isAbsolute(system));
 const env={SystemRoot:system,WINDIR:system,PATH:win32.dirname(binary)+';'+win32.join(system,'System32')};
 async function run(op,path,input){
  const n=windowsLabPath(dir,path);await verifyBinary();
  return new Promise((resolve,reject)=>{
   const child=spawn(binary,[op,dir,n],{shell:false,windowsHide:true,cwd:win32.dirname(binary),env,stdio:['pipe','pipe','ignore']});
   const chunks=[];let length=0,done=false;
   const finish=(e,b)=>{if(done)return;done=true;clearTimeout(timer);if(e){child.kill();for(const c of chunks)c.fill(0);reject(e);}else resolve(b);};
   const timer=setTimeout(()=>finish(Error('Windows native helper timeout')),10000);
   child.on('error',()=>finish(Error('Windows native helper refused')));
   child.stdin.on('error',()=>finish(Error('Windows native helper refused')));
   child.stdout.on('error',()=>finish(Error('Windows native helper refused')));
   child.stdout.on('data',b=>{length+=b.length;if(length>131072){finish(Error('Windows native helper bounds'));return;}chunks.push(b);});
   child.on('close',code=>{if(code!==0){finish(Error('Windows native helper refused'));return;}const b=Buffer.concat(chunks);for(const c of chunks)c.fill(0);finish(null,b);});
   child.stdin.end(input);
  });
 }
 return Object.freeze({binary,binarySha256,dir,env,verifyBinary,
  async read(path){return run('--windows-client-read-lab',path);},
  async writeWire(path,buffer){check(/^wire-[a-z0-9-]{1,48}\.json$/.test(windowsLabPath(dir,path))&&Buffer.isBuffer(buffer)&&buffer.length>0&&buffer.length<=32768);const r=await run('--windows-client-write-wire-lab',path,buffer);check(r.length===0);}
 });
}
