import {readFile,writeFile} from 'node:fs/promises';
import {resolve,join,relative} from 'node:path';
import assert from 'node:assert/strict';
const directory=resolve(process.argv[2]);
const summary=JSON.parse(await readFile(join(directory,'summary.json'),'utf8'));
const {metadata,rows}=summary;
assert.ok(rows.every(r=>r.typescript.passed===metadata.rounds&&r.rust.passed===metadata.rounds));
const f=(n,d=2)=>n.toFixed(d),median=(row,variant,key)=>row[variant][key].median;
const names={'1000-one-chat-256B':'1.000 mensajes / 1 chat / 256 B','1000-twenty-chats-256B':'1.000 mensajes / 20 chats / 256 B','2000-one-chat-256B':'2.000 mensajes / 1 chat / 256 B','1000-one-chat-4KiB':'1.000 mensajes / 1 chat / 4 KiB'};
const lines=[
 '# Benchmark TypeScript frente a Rust — 2026-10-15',
 '',
 'Resultado: en estos cuatro escenarios locales, esta implementación Rust tarda más que la versión TypeScript anterior. La migración conserva el contrato funcional, pero el benchmark no muestra una mejora de rendimiento.',
 '',
 '## Tiempo total y capacidad',
 '',
 `Medianas de ${metadata.rounds} ejecuciones por versión. Los segundos corresponden al lote completo, con ACK durable y llegada al receptor. Ventana global idéntica de ${metadata.max_global_inflight} mensajes; el resto espera en el generador y su tiempo también está contabilizado.`,
 '',
 '| Escenario | TypeScript, lote completo | Rust, lote completo | TS mensajes/s | Rust mensajes/s | Rust tarda |',
 '| --- | ---: | ---: | ---: | ---: | ---: |',
];
for(const row of rows)lines.push(`| ${names[row.scenario]} | ${f(median(row,'typescript','duration_ms')/1000)} s | ${f(median(row,'rust','duration_ms')/1000)} s | ${f(median(row,'typescript','messages_s'),1)} | ${f(median(row,'rust','messages_s'),1)} | ${f(row.rust_duration_ratio)} veces |`);
lines.push('','## Latencia y CPU','','p95 de ACK desde el envío efectivo del frame, bajo carga y con 32 en vuelo. Es la mediana de los p95 de cada ronda; no es tiempo de render del navegador ni latencia WAN. Las distribuciones desde la oferta inicial del lote, con toda la cola, están en los JSON.','','| Escenario | p95 ACK TS | p95 ACK Rust | CPU workerd TS | CPU workerd Rust |','| --- | ---: | ---: | ---: | ---: |');
for(const row of rows)lines.push(`| ${names[row.scenario]} | ${f(median(row,'typescript','ack_p95_ms'),1)} ms | ${f(median(row,'rust','ack_p95_ms'),1)} ms | ${f(median(row,'typescript','server_cpu_ms')/1000)} s | ${f(median(row,'rust','server_cpu_ms')/1000)} s |`);
lines.push('','## Integridad y saturación','');
const recovered=rows.reduce((n,row)=>n+row.typescript.recovered+row.rust.recovered,0);
lines.push(`Se completaron ${rows.length*metadata.rounds*2} casos comparables: ${recovered.toLocaleString('es-AR')} mensajes medidos y recuperados por HTTP tras reconectar, además de los calentamientos. Se verificaron ID, contenido, autor, dispositivo, secuencia y revisión. Cero pérdidas, duplicados y rechazos en estas rondas controladas.`, '',
 'El ensayo preliminar que enviaba toda la ráfaga sin límite de mensajes en vuelo recibió SEND_QUEUE_FULL en TypeScript: su cola admite 64 trabajos pendientes. Rust aceptó los lotes completos de 1.000 y 2.000 en ese ensayo. Los casos TS se detuvieron al primer rechazo y no permiten calcular su throughput de éxito ni afirmar pérdida de mensajes ya confirmados. Por eso se presentan aparte de las medianas comparables.', '',
 '## Diferencias comprobadas en el código','',
 '- TypeScript usa ReadyBatchQueue con capacidad 64 y lotes de hasta 16; superpone preparación y persistencia. Rust mantiene autorización, cuota y preparación dentro de una cola de envío serializada.',
 '- TypeScript conserva LocalAuthority.cached, un Map de permisos que se invalida al cercar/liberar autoridad. Rust authority::cached ejecuta consultas de SQLite y deserialización de la autorización al consultar cada destinatario. En un chat de 41 sockets, sólo esas dos consultas por destinatario representan aproximadamente 164.000 SELECT para repartir 2.000 mensajes, más otras consultas del envío.',
 '- Esta diferencia de caché y planificación es relevante para el aumento de CPU y la desventaja con mayor fanout. No se ha medido cuánto aporta cada una mediante un cambio aislado; no se atribuye todo el resultado al lenguaje ni a una única causa.', '',
 'Código relevante: crates/worker/src/chat/mod.rs, crates/worker/src/chat/authority.rs; en la copia TypeScript de referencia, src/worker/durable/{ready-batch-queue,chat-realtime,local-authority}.ts.', '',
 '## Condiciones, variación y límites','',
 `- PC: ${metadata.cpu.trim()}, ${metadata.logical_cpus} procesadores lógicos, ${f(metadata.total_memory_bytes/1024**3,1)} GiB de RAM; Node ${metadata.node}.`,
 `- Wrangler ${metadata.wrangler}, workerd ${metadata.workerd}, compatibilidad ${metadata.compatibility_date}, idénticos para ambas versiones. Orden TS/Rust, Rust/TS, TS/Rust.`,
 `- Rust: commit ${metadata.rust_commit}; WASM release SHA-256 ${metadata.rust_wasm_sha256}.`,
 `- TypeScript: HEAD ${metadata.typescript_head}, más los cambios locales de la fuente original. Coincidencia de los archivos backend con el manifiesto de migración: ${metadata.typescript_working_tree_matches_migration_baseline}. Huella ${metadata.typescript_backend_source_sha256}.`,
 '- Esquemas nativos y datos lógicos iguales, estado local nuevo por ronda. Conexiones autorizadas y calientes; un mensaje previo por remitente. Las cuotas de mensajes permanecen activas; sólo se amplió la cuota de apertura de sockets a 1.000/min para preparar las fixtures.',
 '- CPU corresponde al árbol de procesos workerd local. RSS y picos disponibles en JSON incluyen el emulador y sus instancias; no equivalen a memoria de un Worker de producción ni a CPU facturada por Cloudflare.',
 '- Son tres rondas por versión; no se pretende significancia estadística universal. Rangos mínimo/máximo por escenario y demoras del generador están en summary.json y archivos por ronda.',
 '- No se midieron navegador, archivos adjuntos, TLS o red de Cloudflare. Las cifras comparan estas implementaciones locales; no predicen directamente latencia geográfica.', '',
 '## Reproducción y datos','',
 '[Generador y método](../experiments/backend-benchmark/README.md). No hubo cambios en el código del producto ni despliegues durante el benchmark.', '',
 `[Resultados agregados](../${relative(process.cwd(),join(directory,'summary.json')).replaceAll('\\','/')}) y [condiciones y huellas](../${relative(process.cwd(),join(directory,'metadata.json')).replaceAll('\\','/')}). Los archivos de cada ronda conservan las métricas originales.`,
 '');
await writeFile('docs/BENCHMARK_TYPESCRIPT_RUST_2026-10-15.md',lines.join('\n'));
console.log('Benchmark report saved.');
