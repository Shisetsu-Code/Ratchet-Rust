# Rust: recuperación de caché y lotes — 2026-10-15

Resultado local: la duración mediana de los lotes Rust cambió entre 11.3% y 65.8% respecto del port anterior (positivo significa reducción). La tabla compara además con TypeScript ejecutado de nuevo en la misma PC. Son tiempos del lote completo, no de cada mensaje.

## Comparación

Medianas de 3 rondas por versión, cuatro escenarios, ventana idéntica de 32 mensajes en vuelo. ACK posterior a durabilidad y llegada al receptor por WebSocket.

| Mensajes / distribución / contenido | Rust anterior | Rust corregido | TypeScript repetido | Reducción Rust | Rust / TS |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1.000 / 1 chat / 256 B | 12.50 s | 5.95 s | 5.46 s | 52.4% | 1.09 |
| 1.000 / 20 chats / 256 B | 6.62 s | 5.87 s | 5.34 s | 11.3% | 1.10 |
| 2.000 / 1 chat / 256 B | 46.68 s | 15.97 s | 16.02 s | 65.8% | 1.00 |
| 1.000 / 1 chat / 4 KiB | 13.43 s | 6.37 s | 6.44 s | 52.5% | 0.99 |

| Escenario | ACK medio Rust | ACK p95 Rust | ACK p95 TS | Rust mensajes/s | CPU Rust |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1.000 / 1 chat / 256 B | 188.8 ms | 227.7 ms | 202.1 ms | 168.1 | 5.45 s |
| 1.000 / 20 chats / 256 B | 184.2 ms | 248.3 ms | 207.5 ms | 170.4 | 4.44 s |
| 2.000 / 1 chat / 256 B | 254.1 ms | 321.3 ms | 372.7 ms | 125.2 | 16.83 s |
| 1.000 / 1 chat / 4 KiB | 201.7 ms | 251.4 ms | 238.5 ms | 156.9 | 6.13 s |

## Cambios y garantías

- Caché por objeto de hasta 512 permisos, con vencimiento y recarga persistida. Los hits evitan consultas SQL y deserialización de grants por destinatario. Cercar/liberar autoridad invalida antes de modificar SQL; el contador de generación impide confirmar preparaciones anteriores a una revocación.
- Preparación concurrente limitada a 64 trabajos; reservas FIFO anteriores al primer await. Una cabeza lenta conserva el orden y una reserva cancelada libera a los seguidores.
- Drenado inmediato de hasta 16 trabajos ya preparados, sin temporizador para esperar a completar un lote. Cada mensaje conserva su transacción y deduplicación; los commits del lote comparten la espera de durabilidad. ACK y publicación quedan después de esa barrera.
- Se mantienen cuotas, reclamación y compensación de adjuntos, secuencias, permisos de mutación y orden de publicación con recibos. No se cambió el modelo de cifrado ni el backend TypeScript de referencia.

Integridad: 24 casos aprobados, 30.000 mensajes medidos recuperados por HTTP tras reconectar. Cero pérdidas, duplicados o habitaciones con revisiones fuera de orden en estas rondas.

## Alcance y reproducción

PC AMD Ryzen 5 3600 6-Core Processor, Node v26.8.1, Wrangler 4.151.0, workerd 1.20261012.1, compatibilidad 2026-10-15. Orden alternado TS/Rust y Rust/TS, esquemas nuevos y fixtures equivalentes. Cuotas de mensajes activas; sólo se eleva igualmente la admisión de conexiones para crear las fixtures.

ACK medio/p95 se mide desde el envío efectivo, con carga y 32 mensajes en vuelo; la cola del generador también queda registrada por separado. CPU es del emulador workerd local. No son latencias WAN, de render ni CPU facturada por Cloudflare. Las tres rondas no prueban rendimiento universal; el cambio agrupa varias optimizaciones y no atribuye un porcentaje causal a cada una.

Artefacto WASM SHA-256: `82a825fca6c8b07d3c266b59599ef476330252ff8333570b52ef2a873496c2f5`. La huella de cada fuente Rust y la del backend TypeScript están en metadata.json; permiten identificar el código probado aunque el commit aún tuviera cambios locales.

[Resultados nuevos](../experiments/backend-benchmark/results/2026-10-15T12-49-56-234Z/summary.json) · [Condiciones y fuentes](../experiments/backend-benchmark/results/2026-10-15T12-49-56-234Z/metadata.json) · [Benchmark anterior](BENCHMARK_TYPESCRIPT_RUST_2026-10-15.md) · [Método](../experiments/backend-benchmark/README.md).

Repetir: `node experiments/backend-benchmark/run.mjs --rounds 3 --inflight 32`, luego `summarize.mjs <carpeta>` y `report-optimized.mjs <carpeta>`. No instala dependencias ni despliega.
