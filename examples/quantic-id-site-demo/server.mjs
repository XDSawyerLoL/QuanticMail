
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createQuanticSitePresence } from '../../lib/quantic-id/site-presence.mjs';

const dir = dirname(fileURLToPath(import.meta.url));
const HOST = '127.0.0.1';
async function jsonBody(req) {
  if (!/^application\/json(?:;|$)/i.test(String(req.headers['content-type'] || ''))) throw new Error('JSON requis');
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.byteLength;
    if (size > 18000) throw new Error('Requête trop volumineuse');
    chunks.push(chunk);
  }
  const result = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error('Objet requis');
  return result;
}
function respond(res, status, value) {
  res.writeHead(status, {'content-type':'application/json; charset=utf-8'});
  res.end(JSON.stringify(value));
}

/** Demo is deliberately bound to localhost only. Not a public authentication server. */
export async function startDemoSite({port=0, now=Date.now}={}) {
  let audience, presence;
  const server = createServer(async (req, res) => {
    res.setHeader('Cache-Control','no-store, max-age=0');
    res.setHeader('X-Content-Type-Options','nosniff');
    res.setHeader('Referrer-Policy','no-referrer');
    res.setHeader('Content-Security-Policy',"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self' http://127.0.0.1:47621; frame-ancestors 'none'; base-uri 'none'");
    if (req.headers.host !== new URL(audience).host) return respond(res,403,{error:'Hôte invalide'});
    const path = new URL(req.url||'/',audience).pathname;
    try {
      if (req.method==='GET' && path==='/api/presence') {
        return respond(res,200,{visitors:presence.listVisible().map(x=>({name:x.displayName,online:true}))});
      }
      const staticPaths={'/':'index.html','/client.js':'client.js','/site.css':'site.css'};
      if (req.method==='GET' && Object.hasOwn(staticPaths,path)) {
        const file=staticPaths[path], buffer=await readFile(join(dir,file));
        res.writeHead(200,{'Content-Type':file.endsWith('.js')?'text/javascript; charset=utf-8':file.endsWith('.css')?'text/css; charset=utf-8':'text/html; charset=utf-8'});
        return res.end(buffer);
      }
      if (req.method!=='POST') return respond(res,404,{error:'Route inconnue'});
      if (req.headers.origin!==audience || req.headers['sec-fetch-site']==='cross-site') return respond(res,403,{error:'Origine interdite'});
      const body=await jsonBody(req);
      if (path==='/api/challenge') return respond(res,200,presence.begin({purpose:body.purpose,token:body.token}));
      if (path==='/api/activate') return respond(res,200,await presence.activate({challenge:body.challenge,proof:body.proof,displayName:body.displayName}));
      if (path==='/api/renew') return respond(res,200,await presence.renew({challenge:body.challenge,proof:body.proof,token:body.token}));
      if (path==='/api/lock') return respond(res,200,{revoked:presence.lock(body.token)});
      return respond(res,404,{error:'Route inconnue'});
    } catch (error) {
      return respond(res,400,{error:error instanceof Error?error.message:'Erreur'});
    }
  });
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,HOST,resolve)});
  audience='http://'+HOST+':'+server.address().port;
  presence=createQuanticSitePresence({audience,now,ttlMs:10000});
  return {url:audience,presence,close:()=>new Promise((resolve,reject)=>server.close(e=>e?reject(e):resolve()))};
}
if (process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) {
  startDemoSite({port:Number(process.env.QUANTIC_DEMO_PORT||41985)})
    .then(site=>process.stdout.write('Quantic ID : '+site.url+'\n'))
    .catch(e=>{process.stderr.write(String(e)+'\n');process.exitCode=1});
}
