import {writeFileSync, mkdirSync} from 'node:fs';
import {resolve} from 'node:path';
import {runBenchmark} from '../src/benchmark.mjs';
const trials=Number(process.argv[2]??5000);
const report=runBenchmark({trials,seed:'verification-v14-20261123'});
const out=resolve(import.meta.dirname,'../results/v14-benchmark.json');
mkdirSync(resolve(import.meta.dirname,'../results'),{recursive:true});
writeFileSync(out,JSON.stringify(report,null,2)+'\n');
console.log(`Audit synthétique : ${trials} répétitions par attaque et méthode.`);
for(const [attack,strategies] of Object.entries(report.attacks)){
 console.log(`${attack.padEnd(22)} ${Object.entries(strategies).map(([name,v])=>`${name} ${(v.rate*100).toFixed(2)}%`).join('  /  ')}`);
}
console.log(`Rapport enregistré : ${out}`);
