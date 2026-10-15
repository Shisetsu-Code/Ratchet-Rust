# Ensayo de cuotas en paralelo — 2026-10-15

**Decisión: conservar el envío secuencial actual.** El candidato funciona, pero no demuestra una mejora consistente de latencia o capacidad. Se conserva como parche reproducible; no se incorporó al runtime ni se desplegó.

## Qué se probó

Sólo se solaparon las cuotas de ráfaga y sostenida del cliente. La cuota del dispositivo siguió primero. Ambas comprobaciones tenían que terminar y permitir el envío; cualquier rechazo o error impedía continuar. No cambiaron claves, límites, autorización, cifrado, transacciones, durabilidad ni orden del ACK.

El candidato suma otra diferencia de comportamiento: consume la cuota sostenida también en intentos rechazados por ráfaga. Puede endurecer la recuperación después de un exceso. Sin una ganancia demostrada, no se introduce ese cambio.

## Resultados bajo carga

Tres pares alternados, cuatro casos por versión, 30.000 mensajes recuperados sin pérdidas, duplicados, rechazos ni desorden. Ambas variantes son Rust. `rust` en los JSON identifica al candidato paralelo, no al runtime que se decidió conservar. Segundos del lote completo, con ACK durable y llegada al receptor; ventana idéntica de 32.

| Caso | Media secuencial | Media paralelo | Mediana secuencial | Mediana paralelo |
| --- | ---: | ---: | ---: | ---: |
| 1.000 / 1 chat / 256 B | 5,69 | 5,79 | 5,72 | 5,55 |
| 1.000 / 20 chats / 256 B | 5,87 | 8,27 | 5,94 | 5,74 |
| 2.000 / 1 chat / 256 B | 15,50 | 19,44 | 15,68 | 15,55 |
| 1.000 / 1 chat / 4 KiB | 6,29 | 8,37 | 6,30 | 6,34 |

La tercera ronda del candidato fue especialmente lenta: 13,50 s en 20 chats, 27,72 s en el caso de 2.000 y 12,80 s con 4 KiB. **Se conservan todas las rondas.** No se atribuye una causa no aislada ni se descarta esa ejecución para presentar una ganancia. Los rangos, datos de cada par, CPU y event loop del generador están en [el agregado](../experiments/backend-benchmark/results/2026-10-15T13-38-12-913Z/comparison-summary.json).

## Latencia y cuotas

Ensayos diagnósticos separados, una ejecución por condición y 100 muestras de cada versión. Medias por mensaje en un chat con 20 cuentas y 21 sockets:

| Condición | Cuotas secuenciales | Cuotas paralelas | ACK secuencial | ACK paralelo |
| --- | ---: | ---: | ---: | ---: |
| 32 en vuelo | 96,52 ms | 90,44 ms | 190,80 ms | 179,90 ms |
| 1 en vuelo | 3,75 ms | 3,76 ms | 10,91 ms | 10,78 ms |

En la muestra de uno en vuelo, cada cuota del cliente tardó unos 1,1 ms en secuencia y 2,1 ms al solaparlas. Se lanzaron juntas, pero esa superposición no redujo la espera total en el entorno medido. Una mejora del ACK de 0,13 ms en una ronda no acredita una ganancia significativa.

Los temporizadores locales tienen resolución observada de 1 ms; los decimales son medias de muestras cuantizadas. Los intervalos de cuotas paralelas se solapan y no se suman. La duración de un await incluye espera de servicio y reanudación del runtime, no sólo CPU.

## Por qué no extrapolarlo a Cloudflare

En la versión instalada, Miniflare simula `limit()` con un fetch interno a `RateLimiterObject`: lee y escribe contadores en SQLite (`_mf_ratelimit_buckets`), con ventanas alineadas al reloj. Fuente comprobada: `node_modules/miniflare/dist/src/workers/ratelimit/{ratelimit,ratelimit-object}.worker.js`.

La API real utiliza contadores cacheados en la misma máquina y actualizaciones de fondo; el `await` no representa una llamada de red según [Cloudflare](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/#performance). Por tanto, los ~90–100 ms locales no prueban ese costo en producción ni justifican quitar controles. No se midió un A/B remoto del candidato rechazado.

El staging conservado pasó nuevamente: 30 mensajes WSS en orden, recuperación HTTPS exacta, reconexión, logout con cierre 4001 sin afectar al otro cliente y consola owner cifrada. Llegada WSS: 556 ms de lote completo, media 494 ms y p95 547 ms. Es una muestra WAN, sin render DOM; no se compara como regresión contra otras ejecuciones aisladas.

## Validación y artefactos

- Candidato: 57 pruebas Rust, 35 contratos completos, parser 4/4, herramientas 5/5, Clippy nativo/WASM y build aprobados. Dos pruebas nuevas fallaron con planificación secuencial y pasaron al usar `join!`.
- Runtime conservado: fuente restaurada byte por byte y WASM verificado contra el artefacto anterior; 54 pruebas Rust y 35 contratos completos aprobados (69,989 s).
- Contrato nuevo CUSTOMER: 100 ACK, mensaje 101 rechazado explícitamente, HTTP no elude la cuota, reintento duplicado conserva el ACK, sync y secuencia exactos. Se alinea con la ventana local de 10 s para evitar flakiness por rollover.
- Principal y diagnósticos: **34.000 mensajes medidos recuperados**. Calentamientos, contratos funcionales y control remoto se contabilizan aparte.
- Base de fuente: `07fd1bdae694ce61ff790883a52f50766fe12f6e`. WASM secuencial: `f2fab22521d85be0cc9d7c1ae0c7d74a3c4bd59bbc9dcf4cd6e12c26d7e15c5d`; candidato: `de8f143cf48bf3644f59696bf7a5bedfcfc4dc2bfae2d1595e1251c6672c2b7d`.

[Parche candidato](../experiments/backend-benchmark/parallel-customer-quotas.patch) · [comparación](../experiments/backend-benchmark/results/2026-10-15T13-38-12-913Z/comparison-summary.md) · [diagnóstico 32](../experiments/backend-benchmark/results/2026-10-15T13-44-46-470Z/metadata.json) · [diagnóstico 1](../experiments/backend-benchmark/results/2026-10-15T13-45-56-818Z/metadata.json).

Los metadatos identifican fuente y artefactos por SHA-256. Datos sintéticos y JSON sin cookies ni claves; binarios y bases locales quedan ignorados. No hubo instalaciones, cambio de dependencias ni despliegue del candidato.
