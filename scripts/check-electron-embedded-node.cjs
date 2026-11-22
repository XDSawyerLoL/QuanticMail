/* Verify the ACTUAL bundled Electron binary. Package.json versions alone
 * do not prove Node 24/ML-DSA support. Refuse release on runtime mismatch. */
const {spawnSync}=require('node:child_process');
const {readFileSync}=require('node:fs');
const {join}=require('node:path');
const pkg=JSON.parse(readFileSync(join(__dirname,'../package.json'),'utf8'));
const expected=pkg.devDependencies?.electron;
if(!/^4[5-9]\.\d+\.\d+$/.test(expected))
 throw Error('An explicitly pinned supported Electron 45+ is required');
const binary=require('electron');
if(typeof binary!=='string'||!binary)throw Error('Electron binary unavailable');
const run=spawnSync(binary,['-e',[
 'const v=process.versions;',
 'process.stdout.write(JSON.stringify({node:v.node,electron:v.electron,openssl:v.openssl}));'
].join('')],{
 env:{...process.env,ELECTRON_RUN_AS_NODE:'1'},encoding:'utf8',
 timeout:20000,maxBuffer:4096,windowsHide:true
});
if(run.error||run.status!==0){
 throw Error('Embedded Electron runtime probe refused: '+String(run.error?.message||run.stderr||run.status).slice(0,250));
}
let v;try{v=JSON.parse(run.stdout)}catch{throw Error('Electron embedded version report invalid');}
const major=x=>Number.parseInt(String(x||'').split('.')[0],10);
if(major(v.node)<24||major(v.electron)<45||v.electron!==expected)
 throw Error('Electron binary version or embedded Node runtime mismatch');
process.stdout.write('ELECTRON_NODE24_NATIVE_GATE '+JSON.stringify({electron:v.electron,node:v.node})+'\n');
