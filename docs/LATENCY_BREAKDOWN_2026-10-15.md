# Desglose local de latencia Rust — 2026-10-15

Nota posterior: el [ensayo de cuotas paralelas](QUOTA_PARALLEL_EXPERIMENT_2026-10-15.md) no demostró una ganancia consistente y no se incorporó al runtime. Se comprobó además que Miniflare simula las cuotas mediante SQLite; estas esperas no describen el costo de la API real, que usa contadores cacheados. Los datos siguientes identifican el artefacto secuencial medido y se conservan como historial.

Las esperas de las cuotas dominan el tiempo dentro del handler durante estas cargas. No son tiempo de cifrado ni de escritura SQLite, y tampoco equivalen a CPU consumida por el limitador: cada await incluye espera en el runtime y trabajo de otros mensajes.

## Dos rondas de las cuatro cargas

Muestreo determinista de uno de cada diez mensajes por remitente, excluido el calentamiento. Medias de las mismas muestras emparejadas con su ACK; milisegundos por mensaje. Las columnas no incluyen todas las fases pequeñas.

| Caso | Muestras | ACK | Handler completo | Cuotas | Cola de listos | Espera tras commit | SQLite | Preparación/cifrado | Publicación | Fuera del handler |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1000-one-chat-256B | 200 | 196.16 | 126.72 | 98.78 | 8.41 | 17.00 | 0.24 | 0.07 | 0.45 | 69.43 |
| 1000-twenty-chats-256B | 200 | 183.60 | 131.59 | 115.92 | 0.01 | 15.15 | 0.25 | 0.06 | 0.09 | 52.01 |
| 2000-one-chat-256B | 400 | 247.16 | 134.45 | 95.27 | 13.31 | 23.16 | 0.22 | 0.05 | 0.73 | 112.71 |
| 1000-one-chat-4KiB | 200 | 209.88 | 134.54 | 101.61 | 11.86 | 18.56 | 0.21 | 0.17 | 0.49 | 75.34 |

## Comprobación de concurrencia y cuotas

Mismo artefacto WASM y caso de 1.000 mensajes, 20 cuentas y 21 sockets en un chat. Una ronda por condición; exploratorio, no intervalo de confianza.

| Medida por mensaje | 32 en vuelo | 1 en vuelo |
| --- | ---: | ---: |
| ACK real | 186.53 ms | 11.40 ms |
| Handler completo | 119.95 ms | 5.93 ms |
| Fuera del handler | 66.58 ms | 5.47 ms |
| Cuota dispositivo | 33.82 ms | 1.65 ms |
| Cuota cliente: ráfaga | 29.30 ms | 1.19 ms |
| Cuota cliente: sostenida | 29.87 ms | 1.06 ms |
| Cuotas completas | 93.00 ms | 3.90 ms |
| Listos hasta claim | 8.17 ms | 0.01 ms |
| Commit hasta publicación | 16.43 ms | 0.98 ms |
| Preparación/cifrado | 0.03 ms | 0.06 ms |
| SQLite commit | 0.20 ms | 0.15 ms |
| Publicación total | 0.41 ms | 0.63 ms |

## Durabilidad y distribución

En el caso detallado de 32 en vuelo: lote medio 10.20; sync durable medio por lote 7.85 ms; barrera completa de publicación 7.86 ms. Son tiempos compartidos: no se suman una vez por cada mensaje ni a la espera tras commit.

| Distribución a los 21 sockets, por mensaje muestreado | Media |
| --- | ---: |
| Enumerar sockets | 0.00 ms |
| Decodificar autoridades | 0.06 ms |
| Caché de permisos | 0.05 ms |
| Construir eventos | 0.06 ms |
| Serializar JSON | 0.12 ms |
| Puente WASM/JS y encolar envío | 0.03 ms |
| Programar push | 0.01 ms |

## Lectura correcta y siguiente cambio candidato

- El código Rust consulta primero la cuota del dispositivo, después la de ráfaga y después la sostenida. La referencia TypeScript consulta dispositivo y luego las dos cuotas del cliente en Promise.all. Es una diferencia de planificación comprobada, no un costo inherente al lenguaje.
- Candidato: conservar las tres cuotas y sus claves, pero solapar las dos comprobaciones independientes del cliente. Debe probarse antes de atribuir una ganancia o desplegarlo. Este trabajo sólo instrumenta; no retira ni paraleliza validaciones.
- La espera de cuota crece con concurrencia. La medición de un await no distingue su latencia de servicio del tiempo que tarda el runtime en volver a ejecutar el handler; no se atribuye toda esa espera a CPU ni a red.
- Fuera del handler es ACK observado por el generador menos handler medido. Incluye despacho/event loop, transporte local, respuesta ACK y trabajo del cliente. No es una medida de WSS puro, Internet ni Cloudflare remoto.
- Publicación mide construir/serializar/encolar eventos; no confirma recepción del destinatario. El benchmark comprueba llegada y recuperación por separado. El push de fondo no se mide como entrega externa.
- publish_total contiene publish_*; quota_io contiene las tres cuotas. La barrera comparte projection/durable_sync y puede esperar el turno de publicación. No sumar padres e hijos ni tiempos de distintos mensajes que se solapan.
- El reloj observado tiene resolución de 1 ms. Los submilisegundos de las tablas son medias de muestras cuantizadas; cero no demuestra costo nulo. Los timers locales avanzan durante ejecución síncrona; en Cloudflare desplegado sólo avanzan tras I/O. [Documentación de Cloudflare](https://developers.cloudflare.com/workers/runtime-apis/performance/).

Control de interferencia: el mismo lote sin diagnóstico tardó 5.56 s y con diagnóstico 5.72 s: diferencia observada 2.9%. Una ronda por condición y orden distinto no permiten separar toda la interferencia del ruido. Los tiempos no deben tratarse como precisión de microbenchmark.

Integridad: 13.000 mensajes medidos recuperados en estas ejecuciones, sin pérdidas, duplicados ni desorden. 0 muestras con residuo inferior a -1 ms. [Regresión y verificaciones del artefacto](VALIDATION.md).

## Evidencia y reproducción

Dos rondas principales: [experiments/backend-benchmark/results/2026-10-15T13-18-17-472Z](../experiments/backend-benchmark/results/2026-10-15T13-18-17-472Z/metadata.json). Incluyen desglose inicial de cuota total. Caso detallado: [experiments/backend-benchmark/results/2026-10-15T13-22-24-170Z](../experiments/backend-benchmark/results/2026-10-15T13-22-24-170Z/metadata.json). Control sin diagnóstico: [experiments/backend-benchmark/results/2026-10-15T13-23-12-407Z](../experiments/backend-benchmark/results/2026-10-15T13-23-12-407Z/metadata.json). Concurrencia uno: [experiments/backend-benchmark/results/2026-10-15T13-24-45-249Z](../experiments/backend-benchmark/results/2026-10-15T13-24-45-249Z/metadata.json).

Cada metadata.json identifica fuente Rust y WASM por SHA-256. Los JSON contienen muestras, fases y correlación con ACK; no payloads, cookies ni claves. La instrumentación está desactivada por defecto y no se habilitó ni desplegó en staging. La copia TypeScript permanece intacta.

```powershell
node experiments/backend-benchmark/run.mjs --profile --variants rust --rounds 2 --inflight 32
node experiments/backend-benchmark/run.mjs --profile --variants rust --rounds 1 --cases 1000-one-chat-256B --inflight 32
node experiments/backend-benchmark/run.mjs --variants rust --rounds 1 --cases 1000-one-chat-256B --inflight 32
node experiments/backend-benchmark/run.mjs --profile --variants rust --rounds 1 --cases 1000-one-chat-256B --inflight 1
```

No instala herramientas ni cambia los límites de mensajes. Usa el entorno local ya existente y estado sintético nuevo por ejecución.
