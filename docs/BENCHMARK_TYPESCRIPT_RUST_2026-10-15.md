# Benchmark TypeScript frente a Rust — 2026-10-15

Resultado: en estos cuatro escenarios locales, esta implementación Rust tarda más que la versión TypeScript anterior. La migración conserva el contrato funcional, pero el benchmark no muestra una mejora de rendimiento.

## Tiempo total y capacidad

Medianas de 3 ejecuciones por versión. Los segundos corresponden al lote completo, con ACK durable y llegada al receptor. Ventana global idéntica de 32 mensajes; el resto espera en el generador y su tiempo también está contabilizado.

| Escenario | TypeScript, lote completo | Rust, lote completo | TS mensajes/s | Rust mensajes/s | Rust tarda |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1.000 mensajes / 1 chat / 256 B | 5.29 s | 12.50 s | 189.0 | 80.0 | 2.36 veces |
| 1.000 mensajes / 20 chats / 256 B | 5.18 s | 6.62 s | 193.2 | 151.1 | 1.28 veces |
| 2.000 mensajes / 1 chat / 256 B | 14.95 s | 46.68 s | 133.8 | 42.9 | 3.12 veces |
| 1.000 mensajes / 1 chat / 4 KiB | 6.08 s | 13.43 s | 164.4 | 74.5 | 2.21 veces |

## Latencia y CPU

p95 de ACK desde el envío efectivo del frame, bajo carga y con 32 en vuelo. Es la mediana de los p95 de cada ronda; no es tiempo de render del navegador ni latencia WAN. Las distribuciones desde la oferta inicial del lote, con toda la cola, están en los JSON.

| Escenario | p95 ACK TS | p95 ACK Rust | CPU workerd TS | CPU workerd Rust |
| --- | ---: | ---: | ---: | ---: |
| 1.000 mensajes / 1 chat / 256 B | 189.9 ms | 516.8 ms | 4.75 s | 12.09 s |
| 1.000 mensajes / 20 chats / 256 B | 190.6 ms | 284.3 ms | 3.88 s | 5.17 s |
| 2.000 mensajes / 1 chat / 256 B | 316.9 ms | 1270.3 ms | 16.36 s | 42.16 s |
| 1.000 mensajes / 1 chat / 4 KiB | 230.9 ms | 581.5 ms | 5.81 s | 12.75 s |

## Integridad y saturación

Se completaron 24 casos comparables: 30.000 mensajes medidos y recuperados por HTTP tras reconectar, además de los calentamientos. Se verificaron ID, contenido, autor, dispositivo, secuencia y revisión. Cero pérdidas, duplicados y rechazos en estas rondas controladas.

El ensayo preliminar que enviaba toda la ráfaga sin límite de mensajes en vuelo recibió SEND_QUEUE_FULL en TypeScript: su cola admite 64 trabajos pendientes. Rust aceptó los lotes completos de 1.000 y 2.000 en ese ensayo. Los casos TS se detuvieron al primer rechazo y no permiten calcular su throughput de éxito ni afirmar pérdida de mensajes ya confirmados. Por eso se presentan aparte de las medianas comparables.

## Diferencias comprobadas en el código

- TypeScript usa ReadyBatchQueue con capacidad 64 y lotes de hasta 16; superpone preparación y persistencia. Rust mantiene autorización, cuota y preparación dentro de una cola de envío serializada.
- TypeScript conserva LocalAuthority.cached, un Map de permisos que se invalida al cercar/liberar autoridad. Rust authority::cached ejecuta consultas de SQLite y deserialización de la autorización al consultar cada destinatario. En un chat de 41 sockets, sólo esas dos consultas por destinatario representan aproximadamente 164.000 SELECT para repartir 2.000 mensajes, más otras consultas del envío.
- Esta diferencia de caché y planificación es relevante para el aumento de CPU y la desventaja con mayor fanout. No se ha medido cuánto aporta cada una mediante un cambio aislado; no se atribuye todo el resultado al lenguaje ni a una única causa.

Código relevante: crates/worker/src/chat/mod.rs, crates/worker/src/chat/authority.rs; en la copia TypeScript de referencia, src/worker/durable/{ready-batch-queue,chat-realtime,local-authority}.ts.

## Condiciones, variación y límites

- PC: AMD Ryzen 5 3600 6-Core Processor, 12 procesadores lógicos, 31.9 GiB de RAM; Node v26.8.1.
- Wrangler 4.151.0, workerd 1.20261012.1, compatibilidad 2026-10-15, idénticos para ambas versiones. Orden TS/Rust, Rust/TS, TS/Rust.
- Rust: commit fab45b78dff6388c2c0b61264883cef5510af2d4; WASM release SHA-256 ec71db36ddc8e8a306a7fff591e46d8801ea5a1e30737690663dda5ac0ede327.
- TypeScript: HEAD 76754e0d059ed8fc8c03ed978ac39aca3bb2a98c, más los cambios locales de la fuente original. Coincidencia de los archivos backend con el manifiesto de migración: true. Huella 66b6e3ed682de33b3d88bdba6ee5d93baa6d3cbea1b1a1d910160d1271932d40.
- Esquemas nativos y datos lógicos iguales, estado local nuevo por ronda. Conexiones autorizadas y calientes; un mensaje previo por remitente. Las cuotas de mensajes permanecen activas; sólo se amplió la cuota de apertura de sockets a 1.000/min para preparar las fixtures.
- CPU corresponde al árbol de procesos workerd local. RSS y picos disponibles en JSON incluyen el emulador y sus instancias; no equivalen a memoria de un Worker de producción ni a CPU facturada por Cloudflare.
- Son tres rondas por versión; no se pretende significancia estadística universal. Rangos mínimo/máximo por escenario y demoras del generador están en summary.json y archivos por ronda.
- No se midieron navegador, archivos adjuntos, TLS o red de Cloudflare. Las cifras comparan estas implementaciones locales; no predicen directamente latencia geográfica.

## Reproducción y datos

[Generador y método](../experiments/backend-benchmark/README.md). No hubo cambios en el código del producto ni despliegues durante el benchmark.

[Resultados agregados](../experiments/backend-benchmark/results/2026-10-15T12-22-46-196Z/summary.json) y [condiciones y huellas](../experiments/backend-benchmark/results/2026-10-15T12-22-46-196Z/metadata.json). Los archivos de cada ronda conservan las métricas originales.
