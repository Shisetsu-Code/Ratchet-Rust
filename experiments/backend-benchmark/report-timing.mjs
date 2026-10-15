import {readFile,writeFile} from 'node:fs/promises';
import {join,relative,resolve} from 'node:path';
import assert from 'node:assert/strict';

const [primaryPath,focusedPath,controlPath,lowPath]=process.argv.slice(2).map(p=>resolve(p));
assert.ok(lowPath,'Provide primary profile, detailed profile, control, and inflight=1 directories');
async function load(path){
 const metadata=JSON.parse(await readFile(join(path,'metadata.json'),'utf8'));
 const runs=JSON.parse(await readFile(join(path,'results.json'),'utf8'));
 assert.ok(runs.length===metadata.rounds&&runs.every(r=>r.variant==='rust'&&r.exit===0&&!r.error));
 const cases=runs.flatMap(r=>r.results);
 assert.ok(cases.every(c=>c.status==='passed'&&c.lost===0&&c.duplicates===0&&c.out_of_order_rooms===0));
 return{path,metadata,cases};
}
const primary=await load(primaryPath),focused=await load(focusedPath),control=await load(controlPath),low=await load(lowPath);
assert.equal(focused.metadata.rust_wasm_sha256,control.metadata.rust_wasm_sha256);
assert.equal(focused.metadata.rust_wasm_sha256,low.metadata.rust_wasm_sha256);
assert.equal(focused.metadata.max_global_inflight,32);assert.equal(control.metadata.max_global_inflight,32);assert.equal(low.metadata.max_global_inflight,1);
const mean=values=>values.reduce((sum,n)=>sum+n,0)/values.length;
function summarize(cases){
 const samples=cases.flatMap(c=>c.timing_profile.samples);
 assert.ok(samples.length&&samples.every(s=>s.total_ms>0));
 const phases=Object.fromEntries(Object.keys(samples[0].phases_ms).map(key=>[key,mean(samples.map(s=>s.phases_ms[key]))]));
 const batches=cases.flatMap(c=>c.timing_profile.batches.samples);
 return{samples:samples.length,ack_ms:mean(samples.map(s=>s.external_ack_ms)),handler_ms:mean(samples.map(s=>s.total_ms)),outside_handler_ms:mean(samples.map(s=>s.external_ack_residual_ms)),phases_ms:phases,fanout:mean(samples.map(s=>s.fanout)),batch_size:mean(batches.map(b=>b.batch_size)),batch_sync_ms:mean(batches.map(b=>b.phases_ms.durable_sync)),batch_barrier_ms:mean(batches.map(b=>b.phases_ms.publication_barrier)),residual_below_tolerance:cases.reduce((sum,c)=>sum+c.timing_profile.residual_below_tolerance_count,0)};
}
const scenarios=[...new Set(primary.cases.map(c=>c.name))].map(name=>({name,...summarize(primary.cases.filter(c=>c.name===name))}));
const detailed=summarize(focused.cases),serial=summarize(low.cases);
const controlMs=control.cases[0].elapsed_ms,profileMs=focused.cases[0].elapsed_ms;
const overheadPercent=100*(profileMs/controlMs-1);
const portable=path=>relative(process.cwd(),path).replaceAll('\\','/');
const result={primary:portable(primaryPath),focused:portable(focusedPath),control:portable(controlPath),low:portable(lowPath),scenarios,detailed,serial,control_ms:controlMs,profile_ms:profileMs,observed_profile_duration_delta_percent:overheadPercent,total_messages_recovered:[primary,focused,control,low].flatMap(r=>r.cases).reduce((sum,c)=>sum+c.recovered,0)};
await writeFile(join(primaryPath,'timing-summary.json'),JSON.stringify(result,null,2));
const f=(n,d=2)=>n.toFixed(d);
const link=run=>`[${relative(process.cwd(),run.path).replaceAll('\\','/')}](../${relative(process.cwd(),join(run.path,'metadata.json')).replaceAll('\\','/')})`;
const lines=[
'# Desglose local de latencia Rust — 2026-10-15','',
'Nota posterior: el [ensayo de cuotas paralelas](QUOTA_PARALLEL_EXPERIMENT_2026-10-15.md) no demostró una ganancia consistente y no se incorporó al runtime. Miniflare simula las cuotas mediante SQLite; estas esperas no describen el costo de la API cacheada real. Se conservan los datos del artefacto secuencial como historial.','',
'Las esperas de las cuotas dominan el tiempo dentro del handler durante estas cargas. No son tiempo de cifrado ni de escritura SQLite, y tampoco equivalen a CPU consumida por el limitador: cada await incluye espera en el runtime y trabajo de otros mensajes.','',
'## Dos rondas de las cuatro cargas','',
'Muestreo determinista de uno de cada diez mensajes por remitente, excluido el calentamiento. Medias de las mismas muestras emparejadas con su ACK; milisegundos por mensaje. Las columnas no incluyen todas las fases pequeñas.','',
'| Caso | Muestras | ACK | Handler completo | Cuotas | Cola de listos | Espera tras commit | SQLite | Preparación/cifrado | Publicación | Fuera del handler |',
'| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |',
];
for(const row of scenarios){const p=row.phases_ms;lines.push(`| ${row.name} | ${row.samples} | ${f(row.ack_ms)} | ${f(row.handler_ms)} | ${f(p.quota_io)} | ${f(p.ready_queue_wait)} | ${f(p.postcommit_wait)} | ${f(p.sqlite_commit)} | ${f(p.prepare_validate_crypto)} | ${f(p.publish_total)} | ${f(row.outside_handler_ms)} |`);}
lines.push('','## Comprobación de concurrencia y cuotas','',
'Mismo artefacto WASM y caso de 1.000 mensajes, 20 cuentas y 21 sockets en un chat. Una ronda por condición; exploratorio, no intervalo de confianza.','',
'| Medida por mensaje | 32 en vuelo | 1 en vuelo |','| --- | ---: | ---: |');
for(const [label,key] of [['ACK real','ack_ms'],['Handler completo','handler_ms'],['Fuera del handler','outside_handler_ms']])lines.push(`| ${label} | ${f(detailed[key])} ms | ${f(serial[key])} ms |`);
for(const [label,key] of [['Cuota dispositivo','quota_device_io'],['Cuota cliente: ráfaga','quota_customer_burst_io'],['Cuota cliente: sostenida','quota_customer_sustained_io'],['Cuotas completas','quota_io'],['Listos hasta claim','ready_queue_wait'],['Commit hasta publicación','postcommit_wait'],['Preparación/cifrado','prepare_validate_crypto'],['SQLite commit','sqlite_commit'],['Publicación total','publish_total']])lines.push(`| ${label} | ${f(detailed.phases_ms[key])} ms | ${f(serial.phases_ms[key])} ms |`);
lines.push('','## Durabilidad y distribución','',
`En el caso detallado de 32 en vuelo: lote medio ${f(detailed.batch_size)}; sync durable medio por lote ${f(detailed.batch_sync_ms)} ms; barrera completa de publicación ${f(detailed.batch_barrier_ms)} ms. Son tiempos compartidos: no se suman una vez por cada mensaje ni a la espera tras commit.`,
'','| Distribución a los 21 sockets, por mensaje muestreado | Media |','| --- | ---: |');
for(const [label,key] of [['Enumerar sockets','publish_enumerate_sockets'],['Decodificar autoridades','publish_peer_decode'],['Caché de permisos','publish_peer_authorize'],['Construir eventos','publish_event_build'],['Serializar JSON','publish_event_serialize'],['Puente WASM/JS y encolar envío','publish_wasm_js_send'],['Programar push','publish_push_schedule']])lines.push(`| ${label} | ${f(detailed.phases_ms[key])} ms |`);
lines.push('','## Lectura correcta y siguiente cambio candidato','',
'- El código Rust consulta primero la cuota del dispositivo, después la de ráfaga y después la sostenida. La referencia TypeScript consulta dispositivo y luego las dos cuotas del cliente en Promise.all. Es una diferencia de planificación comprobada, no un costo inherente al lenguaje.',
'- Candidato: conservar las tres cuotas y sus claves, pero solapar las dos comprobaciones independientes del cliente. Debe probarse antes de atribuir una ganancia o desplegarlo. Este trabajo sólo instrumenta; no retira ni paraleliza validaciones.',
'- La espera de cuota crece con concurrencia. La medición de un await no distingue su latencia de servicio del tiempo que tarda el runtime en volver a ejecutar el handler; no se atribuye toda esa espera a CPU ni a red.',
'- Fuera del handler es ACK observado por el generador menos handler medido. Incluye despacho/event loop, transporte local, respuesta ACK y trabajo del cliente. No es una medida de WSS puro, Internet ni Cloudflare remoto.',
'- Publicación mide construir/serializar/encolar eventos; no confirma recepción del destinatario. El benchmark comprueba llegada y recuperación por separado. El push de fondo no se mide como entrega externa.',
'- publish_total contiene publish_*; quota_io contiene las tres cuotas. La barrera comparte projection/durable_sync y puede esperar el turno de publicación. No sumar padres e hijos ni tiempos de distintos mensajes que se solapan.',
'- El reloj observado tiene resolución de 1 ms. Los submilisegundos de las tablas son medias de muestras cuantizadas; cero no demuestra costo nulo. Los timers locales avanzan durante ejecución síncrona; en Cloudflare desplegado sólo avanzan tras I/O. [Documentación de Cloudflare](https://developers.cloudflare.com/workers/runtime-apis/performance/).','',
`Control de interferencia: el mismo lote sin diagnóstico tardó ${f(controlMs/1000)} s y con diagnóstico ${f(profileMs/1000)} s: diferencia observada ${f(overheadPercent,1)}%. Una ronda por condición y orden distinto no permiten separar toda la interferencia del ruido. Los tiempos no deben tratarse como precisión de microbenchmark.`,
'',
`Integridad: ${result.total_messages_recovered.toLocaleString('es-AR')} mensajes medidos recuperados en estas ejecuciones, sin pérdidas, duplicados ni desorden. ${scenarios.reduce((n,r)=>n+r.residual_below_tolerance,0)+detailed.residual_below_tolerance+serial.residual_below_tolerance} muestras con residuo inferior a -1 ms. [Regresión y verificaciones del artefacto](VALIDATION.md).`,
'','## Evidencia y reproducción','',
`Dos rondas principales: ${link(primary)}. Incluyen desglose inicial de cuota total. Caso detallado: ${link(focused)}. Control sin diagnóstico: ${link(control)}. Concurrencia uno: ${link(low)}.`,
'',
'Cada metadata.json identifica fuente Rust y WASM por SHA-256. Los JSON contienen muestras, fases y correlación con ACK; no payloads, cookies ni claves. La instrumentación está desactivada por defecto y no se habilitó ni desplegó en staging. La copia TypeScript permanece intacta.',
'',
'```powershell',
'node experiments/backend-benchmark/run.mjs --profile --variants rust --rounds 2 --inflight 32',
'node experiments/backend-benchmark/run.mjs --profile --variants rust --rounds 1 --cases 1000-one-chat-256B --inflight 32',
'node experiments/backend-benchmark/run.mjs --variants rust --rounds 1 --cases 1000-one-chat-256B --inflight 32',
'node experiments/backend-benchmark/run.mjs --profile --variants rust --rounds 1 --cases 1000-one-chat-256B --inflight 1',
'```','',
'No instala herramientas ni cambia los límites de mensajes. Usa el entorno local ya existente y estado sintético nuevo por ejecución.','');
await writeFile('docs/LATENCY_BREAKDOWN_2026-10-15.md',lines.join('\n'));
console.log(JSON.stringify({scenarios,detailed,serial,overheadPercent,messages:result.total_messages_recovered},null,2));
