// Test-only static response fixture. No private keys or arbitrary signing API.
// Accept only a precomputed synthetic vote for one bounded loopback endpoint.
import {createServer} from 'node:http';
import {readFileSync,lstatSync} from 'node:fs';
import {isAbsolute} from 'node:path';
const path=process.argv[2];
if(process.argv.length!==3||!isAbsolute(path))throw Error('fixture config required');
const st=lstatSync(path);
if(!st.isFile()||st.size>16384||(st.mode&0o077)!==0)throw Error('fixture refused');
const c=JSON.parse(readFileSync(path,'utf8'));
if(c.simulationOnly!==true||!Number.isInteger(c.port)||c.port<1||c.port>65535||!/^[a-f0-9]{64}$/.test(c.token)||!/^[a-f0-9]{64}$/.test(c.network))throw Error('fixture refused');
const server=createServer(async(req,res)=>{
 try{
  if(req.method!=='POST'||req.url!=='/api/quantic/pay-committee-vote-lab/v1/prepare'||req.headers.authorization!=='Bearer '+c.token)throw Error('fixture route');
  let bytes=0;for await(const b of req){bytes+=b.length;if(bytes>32768)throw Error('fixture cap');}
  const body=JSON.stringify({scope:c.network,simulationOnly:true,realPaymentAuthorized:false,output:c.vote});
  res.writeHead(200,{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body)});res.end(body);
 }catch{res.writeHead(400);res.end();}
});
server.listen(c.port,'127.0.0.1',()=>console.log('READY SYNTHETIC WRONG VOTE'));
process.once('SIGTERM',()=>{server.closeAllConnections();server.close();});
