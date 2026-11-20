
'use strict';
const origin=location.origin, bridge='http://127.0.0.1:47621';
const login=document.getElementById('login'), logout=document.getElementById('logout');
const statusLine=document.getElementById('status'), people=document.getElementById('people');
let lease=null, working=false, lastRenew=0;
async function request(path,body) {
  const response=await fetch('/api/'+path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body),cache:'no-store'});
  const data=await response.json();
  if(!response.ok) throw new Error(data.error||'Requête refusée');
  return data;
}
async function vaultStatus() {
  const response=await fetch(bridge+'/v1/status',{cache:'no-store'});
  if(!response.ok) throw new Error('Coffre indisponible');
  return response.json();
}
async function getProof(purpose,token) {
  const status=await vaultStatus();
  if(!status.identityAvailable) throw new Error('Déverrouille Quantic Identity Vault');
  const {challenge}=await request('challenge',{purpose,token});
  const response=await fetch(bridge+'/v1/assert',{
    method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify({challenge,audience:origin}),cache:'no-store',
  });
  if(!response.ok) throw new Error('Signature locale refusée');
  return {challenge,proof:await response.json(),displayName:status.label||'Utilisateur Quantic'};
}
function ui(message) {
  statusLine.textContent=message;
  login.disabled=working||Boolean(lease);
  logout.disabled=working||!lease;
}
async function refresh() {
  try {
    const data=await (await fetch('/api/presence',{cache:'no-store'})).json();
    people.replaceChildren();
    for(const person of data.visitors) {
      const li=document.createElement('li');
      li.textContent=person.name+' — présent';
      people.append(li);
    }
    if(!people.childElementCount) {
      const li=document.createElement('li');li.textContent='Aucune présence';people.append(li);
    }
  } catch { ui('Site local inaccessible'); }
}
async function connect() {
  if(lease||working)return;
  working=true;ui('Vérification de Quantic ID…');
  try {
    const args=await getProof('activate');
    lease=await request('activate',args);
    lastRenew=Date.now();
    ui('Présence activée — bail de 10 secondes');
  } catch(e) { ui(e.message); }
  finally {working=false;ui(statusLine.textContent);await refresh();}
}
async function disconnect() {
  const old=lease;lease=null;
  if(old){try{await request('lock',{token:old.token});}catch{}}
  ui('Présence supprimée ou en expiration');
  await refresh();
}
async function tick() {
  if(working)return;
  if(lease) {
    try{
      const state=await vaultStatus();
      if(!state.identityAvailable)return disconnect();
      if(Date.now()-lastRenew>5000){
        working=true;
        const proof=await getProof('renew',lease.token);
        await request('renew',{...proof,token:lease.token});
        lastRenew=Date.now();
      }
    }catch{return disconnect();}
    finally{working=false;ui(statusLine.textContent);}
  }
  await refresh();
}
login.addEventListener('click',()=>void connect());
logout.addEventListener('click',()=>void disconnect());
window.addEventListener('pagehide',()=>{
  if(!lease)return;
  navigator.sendBeacon('/api/lock',new Blob([JSON.stringify({token:lease.token})],{type:'application/json'}));
  lease=null;
});
ui('Aucune présence active');
void refresh();
window.setInterval(()=>void tick(),1500);
