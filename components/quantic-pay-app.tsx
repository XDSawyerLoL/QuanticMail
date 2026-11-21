"use client";
import {useState,type FormEvent} from "react";
import {createPaySandbox,formatDemoAmount,PAYEES,type DemoSnapshot} from "@/lib/quantic/pay-sandbox.mjs";
const payee=(id:string)=>PAYEES.find(p=>p.id===id)?.label??"Inconnu";
const labels={prepared:"A confirmer",simulated:"Simulation terminee",cancelled:"Annulee",expired:"Expiree"};
export function QuanticPayApp(){
 const [engine]=useState(()=>createPaySandbox());
 const [state,setState]=useState<DemoSnapshot>(()=>engine.snapshot());
 const [recipient,setRecipient]=useState(PAYEES[0].id);
 const [amount,setAmount]=useState("12,50");
 const [error,setError]=useState("");
 function action(fn:()=>unknown){setError("");try{fn()}catch(e){setError(e instanceof Error?e.message:"Operation refusee.")}finally{setState(engine.snapshot())}}
 function prepare(e:FormEvent){e.preventDefault();action(()=>engine.prepare({payeeId:recipient,amount}))}
 return <main className="qn-onboarding qn-pay"><section className="qn-card qn-pay-card">
  <p className="qn-kicker">QUANTIC SILLAGE / FINANCE</p><h1>Quantic Pay</h1>
  <p className="qn-lead">Laboratoire de paiement. Préparer, confirmer et suivre une opération fictive.</p>
  <p className="qn-pay-warning" role="note">SIMULATION UNIQUEMENT — aucun euro réel, aucune valeur remboursable, aucune connexion BCE ou bancaire. Les données sont réinitialisées à la fermeture de la page.</p>
  <div className="qn-pay-grid">
   <section><p className="qn-kicker">PORTEFEUILLE DE TEST</p><p className="qn-pay-balance">{formatDemoAmount(state.balanceCents)}</p><p className="qn-footnote">Identité fictive : DEMO-ALICE. Aucun accès à vos clés Quantic ID.</p>
   <h2>Nouvelle opération</h2>
   <form className="qn-vault-form" onSubmit={prepare}>
    <label htmlFor="payee">Destinataire fictif</label><select id="payee" disabled={!!state.pending} value={recipient} onChange={e=>setRecipient(e.target.value)}>{PAYEES.map(p=><option key={p.id} value={p.id}>{p.label}</option>)}</select>
    <label htmlFor="amount">Montant fictif</label><input id="amount" inputMode="decimal" maxLength={6} disabled={!!state.pending} value={amount} onChange={e=>setAmount(e.target.value)} required/>
    <button disabled={!!state.pending}>Préparer la simulation</button>
   </form></section>
   <section><h2>Validation explicite</h2>{state.pending?<div className="qn-pay-confirm"><p>{payee(state.pending.payeeId)}</p><h3>{formatDemoAmount(state.pending.cents)}</h3><p className="qn-footnote">Demande {state.pending.id} · valide deux minutes.</p><button onClick={()=>action(()=>engine.confirm(state.pending!.id))}>Confirmer la simulation</button><button className="qn-sync" onClick={()=>action(()=>engine.cancel(state.pending!.id))}>Annuler</button></div>:<p className="qn-footnote">Aucune demande en attente.</p>}
   {error&&<p className="qn-error" role="alert">{error}</p>}
   <h2>Historique de test</h2>{state.history.length===0?<p className="qn-footnote">Aucune opération.</p>:<div className="qn-pay-history" aria-live="polite">{state.history.map(m=><article key={m.id}><strong>{formatDemoAmount(m.cents)}</strong><span>{payee(m.payeeId)}</span><small>{m.id} · {labels[m.status]} · sans valeur monétaire</small></article>)}</div>}</section>
  </div>
  <p className="qn-footnote">Future intégration : consentement lié à l’identité, coffre natif et prestataire de paiement autorisé. Les standards, signatures financières et interfaces officielles ne sont pas implémentés dans ce laboratoire.</p>
 </section></main>
}
