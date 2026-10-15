import {readFile,writeFile} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import assert from 'node:assert/strict';
const directory=resolve(process.argv[2]);
const metadata=JSON.parse(await readFile(join(directory,'metadata.json'),'utf8'));
const runs=JSON.parse(await readFile(join(directory,'results.json'),'utf8'));
const median=values=>{const a=[...values].sort((x,y)=>x-y);return a.length%2?a[(a.length-1)/2]:(a[a.length/2-1]+a[a.length/2])/2;};
const stat=values=>values.length?{median:median(values),min:Math.min(...values),max:Math.max(...values),n:values.length}:null;
const rows=[];
for(const name of [...new Set(runs.flatMap(r=>(r.results??[]).map(c=>c.name)))]){
 const row={scenario:name};
 for(const variant of ['typescript','rust']){
  const cases=runs.filter(r=>r.variant===variant).flatMap(r=>r.results??[]).filter(c=>c.name===name);
  const passed=cases.filter(c=>c.status==='passed');
  row[variant]={runs:cases.length,passed:passed.length,failures:cases.filter(c=>c.status!=='passed'),duration_ms:stat(passed.map(c=>c.elapsed_ms)),messages_s:stat(passed.map(c=>c.throughput_messages_s)),ack_mean_ms:stat(passed.map(c=>c.ack.mean_ms)),ack_p95_ms:stat(passed.map(c=>c.ack.p95_ms)),offered_ack_p95_ms:stat(passed.map(c=>c.completion_from_offer.p95_ms)),server_cpu_ms:stat(passed.filter(c=>c.server).map(c=>c.server.cpu_ms)),server_rss_end_bytes:stat(passed.filter(c=>c.server).map(c=>c.server.rss_end_bytes)),lost:passed.reduce((n,c)=>n+c.lost,0),duplicates:passed.reduce((n,c)=>n+c.duplicates,0),recovered:passed.reduce((n,c)=>n+c.recovered,0),out_of_order_rooms:passed.reduce((n,c)=>n+c.out_of_order_rooms,0)};
 }
 if(row.typescript.passed&&row.rust.passed){row.rust_duration_ratio=row.rust.duration_ms.median/row.typescript.duration_ms.median;row.rust_throughput_delta_percent=100*(row.rust.messages_s.median/row.typescript.messages_s.median-1);}
 rows.push(row);
}
const summary={metadata,rows,run_errors:runs.filter(r=>r.error)};
await writeFile(join(directory,'summary.json'),JSON.stringify(summary,null,2));
console.log('| Escenario | TS ms | Rust ms | TS msg/s | Rust msg/s | Rust tiempo / TS |');
console.log('| --- | ---: | ---: | ---: | ---: | ---: |');
for(const r of rows)console.log(`| ${r.scenario} | ${r.typescript.duration_ms?.median.toFixed(1)??'FALLÓ'} | ${r.rust.duration_ms?.median.toFixed(1)??'FALLÓ'} | ${r.typescript.messages_s?.median.toFixed(1)??'-'} | ${r.rust.messages_s?.median.toFixed(1)??'-'} | ${r.rust_duration_ratio?.toFixed(2)??'-'} |`);
assert.equal(summary.run_errors.length,0,'runner errors must be reported');
assert.ok(rows.every(r=>r.typescript.passed===metadata.rounds&&r.rust.passed===metadata.rounds),'all paired rounds must pass before interpreting medians');
