// Engineering evidence baseline only. Never confers legal status or live access.
// Keep public draft requirements distinct from enacted legal obligations.
const rows=[
 ['EU-01','PSP and authoritative settlement','external-required'],
 ['EU-02','Versioned PSP data schemas','partial-lab'],
 ['EU-03','Strong customer authentication and dynamic linking','partial-lab'],
 ['EU-04','GDPR minimization and privacy controls','partial-lab'],
 ['EU-05','DORA operational resilience and contractual evidence','partial-lab'],
 ['EU-06','CPACE and SoftPOS interoperability','not-implemented'],
 ['EU-07','EUDI relying-party integration','not-implemented'],
 ['EU-08','Offline transfer and privacy controls','not-implemented'],
 ['EU-09','Fraud AML and disputes','not-implemented'],
 ['EU-10','Accessibility and inclusion','not-implemented'],
 ['EU-11','Cryptographic agility custody and audit','partial-lab'],
 ['EU-12','Internal fault-tolerant consensus','partial-lab'],
 ['EU-13','Contractual and supply-chain evidence','external-required']
];
const baseline=Object.freeze(rows.map(([id,requirement,status])=>Object.freeze({id,requirement,status})));
export function payEuropeanReadiness(){
 return Object.freeze({asOf:'2026-11-21',rulebookDraft:'0.91',pilotFaqDate:'2026-10-28',
  normativeStatus:'draft-scheme-legislation-pending',scope:'technical-service-provider-preparation',
  requirements:baseline,environment:'offline-laboratory',productionReady:false,certified:false,despConnected:false,realPaymentAuthorized:false});
}
