import {readFile,writeFile} from 'node:fs/promises';
import {resolve,join,relative} from 'node:path';
import assert from 'node:assert/strict';

const directory=resolve(process.argv[2]);
const baseline=resolve(process.argv[3]??'experiments/backend-benchmark/results/2026-10-15T12-22-46-196Z');
const current=JSON.parse(await readFile(join(directory,'summary.json'),'utf8'));
const before=JSON.parse(await readFile(join(baseline,'summary.json'),'utf8'));
const {metadata,rows}=current;
assert.equal(metadata.max_global_inflight,before.metadata.max_global_inflight);
assert.equal(metadata.typescript_backend_source_sha256,before.metadata.typescript_backend_source_sha256);
assert.ok(rows.length===4&&rows.every(row=>['typescript','rust'].every(v=>row[v].passed===metadata.rounds&&row[v].lost===0&&row[v].duplicates===0&&row[v].out_of_order_rooms===0)));
const f=(n,d=2)=>n.toFixed(d);
const names={'1000-one-chat-256B':'1.000 / 1 chat / 256 B','1000-twenty-chats-256B':'1.000 / 20 chats / 256 B','2000-one-chat-256B':'2.000 / 1 chat / 256 B','1000-one-chat-4KiB':'1.000 / 1 chat / 4 KiB'};
const old=row=>before.rows.find(r=>r.scenario===row.scenario).rust;
const improvements=rows.map(row=>100*(1-row.rust.duration_ms.median/old(row).duration_ms.median));
const recovered=rows.reduce((sum,row)=>sum+row.rust.recovered+row.typescript.recovered,0);
const lines=[
'# Rust: recuperación de caché y lotes — 2026-10-15','',
`Resultado local: la duración mediana de los lotes Rust cambió entre ${f(Math.min(...improvements),1)}% y ${f(Math.max(...improvements),1)}% respecto del port anterior (positivo significa reducción). La tabla compara además con TypeScript ejecutado de nuevo en la misma PC. Son tiempos del lote completo, no de cada mensaje.`,
'','## Comparación','',
`Medianas de ${metadata.rounds} rondas por versión, cuatro escenarios, ventana idéntica de ${metadata.max_global_inflight} mensajes en vuelo. ACK posterior a durabilidad y llegada al receptor por WebSocket.`,
'','| Mensajes / distribución / contenido | Rust anterior | Rust corregido | TypeScript repetido | Reducción Rust | Rust / TS |',
'| --- | ---: | ---: | ---: | ---: | ---: |',
];
for(const [index,row] of rows.entries())lines.push(`| ${names[row.scenario]} | ${f(old(row).duration_ms.median/1000)} s | ${f(row.rust.duration_ms.median/1000)} s | ${f(row.typescript.duration_ms.median/1000)} s | ${f(improvements[index],1)}% | ${f(row.rust_duration_ratio)} |`);
lines.push('','| Escenario | ACK medio Rust | ACK p95 Rust | ACK p95 TS | Rust mensajes/s | CPU Rust |','| --- | ---: | ---: | ---: | ---: | ---: |');
for(const row of rows)lines.push(`| ${names[row.scenario]} | ${f(row.rust.ack_mean_ms.median,1)} ms | ${f(row.rust.ack_p95_ms.median,1)} ms | ${f(row.typescript.ack_p95_ms.median,1)} ms | ${f(row.rust.messages_s.median,1)} | ${f(row.rust.server_cpu_ms.median/1000)} s |`);
lines.push('','## Cambios y garantías','',
'- Caché por objeto de hasta 512 permisos, con vencimiento y recarga persistida. Los hits evitan consultas SQL y deserialización de grants por destinatario. Cercar/liberar autoridad invalida antes de modificar SQL; el contador de generación impide confirmar preparaciones anteriores a una revocación.',
'- Preparación concurrente limitada a 64 trabajos; reservas FIFO anteriores al primer await. Una cabeza lenta conserva el orden y una reserva cancelada libera a los seguidores.',
'- Drenado inmediato de hasta 16 trabajos ya preparados, sin temporizador para esperar a completar un lote. Cada mensaje conserva su transacción y deduplicación; los commits del lote comparten la espera de durabilidad. ACK y publicación quedan después de esa barrera.',
'- Se mantienen cuotas, reclamación y compensación de adjuntos, secuencias, permisos de mutación y orden de publicación con recibos. No se cambió el modelo de cifrado ni el backend TypeScript de referencia.',
'',`Integridad: ${rows.length*metadata.rounds*2} casos aprobados, ${recovered.toLocaleString('es-AR')} mensajes medidos recuperados por HTTP tras reconectar. Cero pérdidas, duplicados o habitaciones con revisiones fuera de orden en estas rondas.`,'',
'## Alcance y reproducción','',
`PC ${metadata.cpu.trim()}, Node ${metadata.node}, Wrangler ${metadata.wrangler}, workerd ${metadata.workerd}, compatibilidad ${metadata.compatibility_date}. Orden alternado TS/Rust y Rust/TS, esquemas nuevos y fixtures equivalentes. Cuotas de mensajes activas; sólo se eleva igualmente la admisión de conexiones para crear las fixtures.`,
'',
'ACK medio/p95 se mide desde el envío efectivo, con carga y 32 mensajes en vuelo; la cola del generador también queda registrada por separado. CPU es del emulador workerd local. No son latencias WAN, de render ni CPU facturada por Cloudflare. Las tres rondas no prueban rendimiento universal; el cambio agrupa varias optimizaciones y no atribuye un porcentaje causal a cada una.',
'',
`Artefacto WASM SHA-256: \`${metadata.rust_wasm_sha256}\`. La huella de cada fuente Rust y la del backend TypeScript están en metadata.json; permiten identificar el código probado aunque el commit aún tuviera cambios locales.`,
'',
`[Resultados nuevos](../${relative(process.cwd(),join(directory,'summary.json')).replaceAll('\\','/')}) · [Condiciones y fuentes](../${relative(process.cwd(),join(directory,'metadata.json')).replaceAll('\\','/')}) · [Benchmark anterior](BENCHMARK_TYPESCRIPT_RUST_2026-10-15.md) · [Método](../experiments/backend-benchmark/README.md).`,
'',
'Repetir: `node experiments/backend-benchmark/run.mjs --rounds 3 --inflight 32`, luego `summarize.mjs <carpeta>` y `report-optimized.mjs <carpeta>`. No instala dependencias ni despliega.',
'');
await writeFile('docs/BENCHMARK_RUST_OPTIMIZED_2026-10-15.md',lines.join('\n'));
console.log('Optimized comparison report saved.');
