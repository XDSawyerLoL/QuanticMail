/* Native-only launch policy. No URL, remote renderer or Web fallback.
 * Kept independently testable without Electron.
 */
// CommonJS is required by the Electron native entry and its VM regression tests.
// eslint-disable-next-line @typescript-eslint/no-require-imports
const {win32}=require('node:path');
const SHA256=/^[a-f0-9]{64}$/;
const windowsPath=/^[a-zA-Z]:\\[A-Za-z0-9 _.-]+(?:\\[A-Za-z0-9 _.-]+)*$/;
function canonicalWindowsPath(value){
  if(typeof value!=='string'||value.length>240||!windowsPath.test(value)||!win32.isAbsolute(value)||win32.normalize(value)!==value)return false;
  const parts=value.slice(3).split('\\');
  return parts.every(p=>p!=='.'&&p!=='..'&&!p.endsWith('.')&&!p.endsWith(' ')&&
    !/^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i.test(p));
}
function nativeStartupPolicy(argv,{platform,nodeVersion,tty}={}){
  if(!Array.isArray(argv)||!argv.every(x=>typeof x==='string'&&x.length<=1024))throw Error('Native startup arguments refused');
  const winFlag='--native-vault-windows-lab',linuxFlag='--native-vault-lab';
  const w=argv.filter(x=>x===winFlag).length,l=argv.filter(x=>x===linuxFlag).length;
  if(w+l>1)throw Error('Conflicting native entrypoints');
  if(w===1){
    const index=argv.indexOf(winFlag);
    const rest=argv.slice(index+1);
    if(platform!=='win32'||Number.parseInt(String(nodeVersion).split('.')[0],10)<24||
      rest.length!==3||!canonicalWindowsPath(rest[0])||!SHA256.test(rest[1])||
      !canonicalWindowsPath(rest[2]))throw Error('Unpinned native Windows lab refused');
    return Object.freeze({mode:'windows-native-lab',binary:rest[0],binarySha256:rest[1],dir:rest[2]});
  }
  if(l===1){
    const index=argv.indexOf(linuxFlag);
    if(platform!=='linux'||tty!==true||argv.length!==index+1)throw Error('Untrusted native Linux terminal');
    return Object.freeze({mode:'linux-native-lab'});
  }
  // No remotely loaded page is ever a supported application entrypoint.
  // Intentional harmless closed default until the native app is installed.
  return Object.freeze({mode:'native-install-required'});
}
module.exports={nativeStartupPolicy,canonicalWindowsPath};
