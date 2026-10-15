import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import {resolve,join} from 'node:path';

function argument(...names){for(const name of names){const i=process.argv.indexOf(name);if(i>=0){assert.ok(process.argv[i+1]&&!process.argv[i+1].startsWith('--'),name+' requires a directory');return resolve(process.argv[i+1]);}}return null;}
const input=argument('--input','--inputdir'),diagnostic=argument('--diagnostic','--diagnosticdir');
assert.ok(input,'Usage: node experiments/backend-benchmark/comparison-summary.mjs --inputdir <directory> [--diagnosticdir <directory>]');
const read=async(directory,name)=>JSON.parse(await readFile(join(directory,name),'utf8'));
const metadata=await read(input,'metadata.json'),runs=await read(input,'results.json');
const names=['1000-one-chat-256B','1000-twenty-chats-256B','2000-one-chat-256B','1000-one-chat-4KiB'];
const variants=['sequential','rust'];
function validateRuns(data,rounds,cases){
 assert.equal(data.length,rounds*2,'Expected exactly paired sequential/rust runs');
 for(let round=1;round<=rounds;round++)for(const variant of variants){
  const matches=data.filter(r=>r.round===round&&r.variant===variant);assert.equal(matches.length,1,'Missing/duplicate run '+round+' '+variant);
  const r=matches[0];assert.ok(!r.error,r.error);assert.equal(r.exit,0);assert.equal(r.results.length,cases.length);
  for(const name of cases){const c=r.results.filter(c=>c.name===name);assert.equal(c.length,1,'Missing/duplicate case '+name);assert.equal(c[0].status,'passed');assert.equal(c[0].recovered,c[0].messages);assert.equal(c[0].lost,0);assert.equal(c[0].duplicates,0);assert.equal(c[0].out_of_order_rooms,0);assert.equal(c[0].ack.count,c[0].messages);assert.equal(c[0].recipient_arrival.count,c[0].messages);for(const key of ['cpu_ms','event_loop_p99_ms','event_loop_max_ms'])assert.ok(Number.isFinite(c[0].load_generator?.[key]),'Missing load generator telemetry: '+key);}
 }
}
assert.equal(metadata.rounds,3);assert.equal(metadata.profiling,false,'Primary comparison must run without profiling');
assert.deepEqual(metadata.variants,[...variants],'Expected sequential,rust alternating comparison');
assert.ok(metadata.artifacts?.sequential?.wasm_sha256&&metadata.artifacts?.rust?.wasm_sha256,'Artifact provenance required');
validateRuns(runs,3,names);
const mean=values=>values.reduce((a,b)=>a+b,0)/values.length;
const median=values=>{const sorted=[...values].sort((a,b)=>a-b);return sorted[Math.floor(sorted.length/2)];};
const number=(value,label)=>{assert.ok(typeof value==='number'&&Number.isFinite(value)&&value>=0,'Missing/invalid '+label);return value;};
const metrics={elapsed_ms:c=>c.elapsed_ms,ack_p95_ms:c=>c.ack.p95_ms,ack_mean_ms:c=>c.ack.mean_ms,server_cpu_ms:c=>c.server?.cpu_ms};
const generatorTelemetry=runs.map(r=>({round:r.round,variant:r.variant,cases:r.results.map(c=>({name:c.name,...c.load_generator}))}));
const cases=names.map(name=>{
 const paired=[1,2,3].map(round=>({round,...Object.fromEntries(variants.map(v=>[v,runs.find(r=>r.round===round&&r.variant===v).results.find(c=>c.name===name)]))}));
 for(const p of paired)for(const key of ['users','rooms','per_user','text_bytes','messages','max_global_inflight'])assert.equal(p.sequential[key],p.rust[key],'Unmatched workload '+key);
 return{name,total_recovered:Object.fromEntries(variants.map(v=>[v,paired.reduce((sum,p)=>sum+p[v].recovered,0)])),metrics:Object.fromEntries(Object.entries(metrics).map(([key,get])=>{
  const pairs=paired.map(p=>{const sequential=number(get(p.sequential),key),rust=number(get(p.rust),key);return{round:p.round,sequential,rust,improvement_percent:sequential===0?null:(sequential-rust)/sequential*100};});
  const sequentialValues=pairs.map(p=>p.sequential),rustValues=pairs.map(p=>p.rust);
  const sequential=mean(sequentialValues),rust=mean(rustValues);return[key,{sequential_mean:sequential,rust_mean:rust,sequential_median:median(sequentialValues),rust_median:median(rustValues),sequential_range:[Math.min(...sequentialValues),Math.max(...sequentialValues)],rust_range:[Math.min(...rustValues),Math.max(...rustValues)],improvement_percent:sequential===0?null:(sequential-rust)/sequential*100,rust_faster_pairs:pairs.filter(p=>p.rust<p.sequential).length,pairs}];
 }))};
});
let diagnosticSummary=null;
if(diagnostic){
 const dm=await read(diagnostic,'metadata.json'),dr=await read(diagnostic,'results.json');
 for(const key of ['node','wrangler','workerd','compatibility_date','cpu','max_global_inflight'])assert.equal(dm[key],metadata[key],'Diagnostic runtime differs: '+key);
 assert.equal(dm.profiling,true);assert.equal(dm.rounds,1);validateRuns(dr,1,['1000-one-chat-256B']);
 for(const v of variants){assert.equal(dm.artifacts[v].wasm_sha256,metadata.artifacts[v].wasm_sha256,'Diagnostic artifact differs');assert.equal(dm.artifacts[v].entry_sha256,metadata.artifacts[v].entry_sha256,'Diagnostic entry differs');}
 diagnosticSummary=Object.fromEntries(variants.map(v=>{const c=dr.find(r=>r.variant===v).results[0],p=c.timing_profile;assert.ok(p&&p.count===p.expected_count&&p.count>0,'Missing complete timing profile');return[v,{count:p.count,phases_ms:p.phases_ms,total_ms:p.total_ms,external_ack_ms:p.external_ack_ms,external_ack_residual_ms:p.external_ack_residual_ms,residual_below_tolerance_count:p.residual_below_tolerance_count,batches:p.batches}];}));
}
const summary={input,diagnostic,validation:'All 24 primary case results passed; three matched pairs per case; full recovery, no lost or duplicate messages, matching ACK counts and workload dimensions.',artifacts:metadata.artifacts,load_generator:generatorTelemetry,metric_note:'Improvement is (sequential mean - rust mean) / sequential mean; positive favors current Rust. ACK figures summarize each run equally. Three local pairs do not establish statistical significance.',cases,diagnostic:diagnosticSummary};
const fmt=n=>n===null?'n/a':n.toFixed(2);
const lines=['# Customer quota A/B comparison','',summary.validation,'',summary.metric_note,'','Both variants are Rust. `rust` labels the parallel candidate at measurement time; it does not imply that candidate was adopted. All rounds, including the slower third candidate run, remain included. No cause is assigned to that variation.','', '| Case | Metric | Sequential mean | Parallel candidate mean | Improvement % | Faster pairs |','|---|---|---:|---:|---:|---:|'];
for(const c of cases)for(const [metric,m]of Object.entries(c.metrics))lines.push(`| ${c.name} | ${metric} | ${fmt(m.sequential_mean)} | ${fmt(m.rust_mean)} | ${fmt(m.improvement_percent)} | ${m.rust_faster_pairs}/3 |`);
lines.push('','| Case | Sequential recovered | Current Rust recovered |','|---|---:|---:|');for(const c of cases)lines.push(`| ${c.name} | ${c.total_recovered.sequential} | ${c.total_recovered.rust} |`);
if(diagnosticSummary){lines.push('','Profiled 1000-message diagnostic (one run per variant; excluded from primary means):','','| Variant | Samples | Phase | Mean ms | P95 ms |','|---|---:|---|---:|---:|');for(const [v,p]of Object.entries(diagnosticSummary))for(const [phase,s]of Object.entries(p.phases_ms))lines.push(`| ${v} | ${p.count} | ${phase} | ${fmt(s.mean_ms)} | ${fmt(s.p95_ms)} |`);}
await writeFile(join(input,'comparison-summary.json'),JSON.stringify(summary,null,2)+'\n');await writeFile(join(input,'comparison-summary.md'),lines.join('\n')+'\n');console.log(join(input,'comparison-summary.md'));
