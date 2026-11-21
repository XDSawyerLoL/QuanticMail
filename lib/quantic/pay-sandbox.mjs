// Local fictional payment simulation. No network, bank account, credential,
// official digital euro, vault authorization or actual monetary value.
export const PAYEES=Object.freeze([{id:'demo-shop',label:'Commerce de demonstration'},{id:'demo-person',label:'Particulier de demonstration'}].map(Object.freeze));
export const START_CENTS=10000;
const check=(ok,msg)=>{if(!ok)throw Error(msg)};
export function parseDemoAmount(text){
 check(typeof text==='string'&&/^(?:0|[1-9][0-9]{0,2})(?:[.,][0-9]{1,2})?$/.test(text),'Montant invalide (2 decimales maximum).');
 const [u,f='']=text.replace(',','.').split('.');
 const cents=Number(u)*100+Number(f.padEnd(2,'0'));
 check(Number.isSafeInteger(cents)&&cents>=1&&cents<=START_CENTS,'Montant de test hors limites.');
 return cents;
}
export function formatDemoAmount(cents){
 check(Number.isSafeInteger(cents)&&cents>=0&&cents<=START_CENTS,'Montant de test invalide.');
 return (Math.floor(cents/100))+','+String(cents%100).padStart(2,'0')+' EUR fictifs';
}
export function createPaySandbox({clock=Date.now}={}){
 let balance=START_CENTS,seq=0,current=null;
 const ledger=[];
 const now=()=>{const t=clock();check(Number.isSafeInteger(t)&&t>=0,'Horloge invalide.');return t};
 const freeze=v=>Object.freeze({...v});
 const snapshot=()=>Object.freeze({mode:'simulation',currency:'EUR',redeemable:false,balanceCents:balance,pending:current,history:Object.freeze(ledger.slice().reverse())});
 function settle(id,kind){
  const previous=ledger.find(x=>x.id===id);
  if(previous){check(previous.status===kind,'Operation deja terminee.');return previous}
  check(current&&current.id===id,'Demande inexistante.');
  const time=now();
  if(time<current.createdAt||time>=current.expiresAt){
   ledger.push(freeze({...current,status:'expired',settledAt:time}));current=null;throw Error('Demande expiree.');
  }
  if(kind==='simulated'){check(balance>=current.cents,'Solde fictif insuffisant.');balance-=current.cents;}
  const result=freeze({...current,status:kind,settledAt:time,balanceAfterCents:balance,realPayment:false});
  ledger.push(result);current=null;return result;
 }
 return Object.freeze({
  snapshot,
  prepare({payeeId,amount}){
   check(!current,'Confirmez ou annulez la demande en cours.');
   check(PAYEES.some(p=>p.id===payeeId),'Destinataire de test uniquement.');
   check(ledger.length<100,'Session de demonstration terminee.');
   const cents=parseDemoAmount(amount);check(cents<=balance,'Solde fictif insuffisant.');
   const time=now();
   current=freeze({id:'DEMO-'+String(++seq).padStart(6,'0'),payeeId,cents,currency:'EUR',createdAt:time,expiresAt:time+120000,status:'prepared',realPayment:false});
   return current;
  },
  confirm:id=>settle(id,'simulated'),
  cancel:id=>settle(id,'cancelled')
 });
}
