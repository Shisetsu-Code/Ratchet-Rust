# Comparación local TypeScript / Rust

## Experimento de cuotas paralelas

El [ensayo](../../docs/QUOTA_PARALLEL_EXPERIMENT_2026-10-15.md) queda aislado como `parallel-customer-quotas.patch`; el runtime normal conserva la versión secuencial. Para reproducirlo con las herramientas existentes, partiendo del runtime secuencial y una carpeta de artefacto nueva:

```powershell
npm run build:worker
node experiments/backend-benchmark/capture-rust-artifact.mjs .wrangler/quota-baseline-new
git apply --check experiments/backend-benchmark/parallel-customer-quotas.patch
git apply experiments/backend-benchmark/parallel-customer-quotas.patch
npm run build:worker
node experiments/backend-benchmark/run.mjs --variants sequential,rust --sequential-artifact .wrangler/quota-baseline-new --rounds 3 --inflight 32
node experiments/backend-benchmark/run.mjs --variants sequential,rust --sequential-artifact .wrangler/quota-baseline-new --rounds 1 --cases 1000-one-chat-256B --inflight 32 --profile
node experiments/backend-benchmark/run.mjs --variants sequential,rust --sequential-artifact .wrangler/quota-baseline-new --rounds 1 --cases 1000-one-chat-256B --inflight 1 --profile
git apply --reverse experiments/backend-benchmark/parallel-customer-quotas.patch
npm run build:worker
```

`capture-rust-artifact.mjs` debe ejecutarse después de compilar: conserva JS, WASM y huellas de fuente, exige una carpeta dentro de `.wrangler` y rechaza sobreescribirla. El runner comprueba sus hashes y alterna el orden pedido/reverso entre rondas. Ambas variantes usan el mismo esquema Rust, límites, clientes y verificador. No instala ni despliega.

`comparison-summary.mjs --inputdir CARPETA_PRINCIPAL --diagnosticdir CARPETA_DIAGNOSTICO_32` genera medias, medianas, rangos, cada par y el desglose de cuotas; exige las tres rondas completas y todas las verificaciones de integridad. `rust` etiqueta al candidato durante el experimento, sin implicar adopción.

## Diagnóstico de etapas

`--profile --variants rust` habilita exclusivamente en el runtime local `RATCHET_TIMING_PROBE=sample10`. Se muestrean las secuencias 11, 21, 31, 41 y 51 de cada remitente; warmups fuera. `--cases 1000-one-chat-256B` permite aislar un caso y `--inflight 1` contrastar las esperas bajo concurrencia. Sin estas opciones, el benchmark comparativo conserva su comportamiento.

Se registran fases y correlación con ACK, sin contenido, cookies o claves. El reloj observado cuantiza a 1 ms; no permite interpretar cero como costo nulo. Duraciones asíncronas no son tiempo exclusivo de CPU. Padres e hijos de publicación/cuotas se solapan y los tiempos compartidos por lote no se suman por mensaje. Pruebas del parser: `node --test experiments/backend-benchmark/timing-profile.test.mjs`.

`report-timing.mjs <principal> <detallado32> <control32> <detallado1>` genera [el informe por etapas](../../docs/LATENCY_BREAKDOWN_2026-10-15.md). Los runtimes de diagnóstico usan `--log-level log`: `info` oculta console.log y no sirve para capturar estas trazas. Los dos smoke iniciales conservaron 30 ACK/entregas pero fallaron la validación de captura por ese filtro; no se incluyen en las 13.000 entregas del análisis.

## Comparación de versiones

El generador ejecuta ambos backends con el mismo Wrangler/workerd instalado, en la misma PC y de forma secuencial. Conserva la fuente TypeScript local utilizada para la migración y comprueba sus hashes contra `baseline/source-manifest.json`. Rust usa el WASM release ya compilado; no se instala ni se despliega nada.

```powershell
node experiments/backend-benchmark/run.mjs --smoke --rounds 1
node experiments/backend-benchmark/run.mjs --rounds 3 --inflight 32
node experiments/backend-benchmark/summarize.mjs experiments/backend-benchmark/results/CARPETA_DE_LA_EJECUCION
node experiments/backend-benchmark/report-optimized.mjs experiments/backend-benchmark/results/CARPETA_DE_LA_EJECUCION
```

Requiere la carpeta hermana `Ratchet-SQLite` con sus dependencias existentes. Se puede indicar otra con `RATCHET_TYPESCRIPT_SOURCE`. Los resultados identifican el commit y los hashes reales; el HEAD de TypeScript por sí solo no incluye sus cambios locales.

`report-optimized.mjs` compara las nuevas rondas con el port anterior conservado. `report.mjs` sólo reproduce el informe histórico de la primera medición: su explicación describe aquel artefacto y no debe utilizarse para rondas posteriores. Ahora también se guarda la huella de cada fuente Rust en `metadata.json`.

## Condiciones

- Orden pareado: TS/Rust, Rust/TS, TS/Rust; cada arranque utiliza D1/R2/DO locales nuevos y el esquema nativo de su versión.
- Igual compatibilidad de runtime, claves sintéticas y datos lógicos. Autorización real de cada conexión y las cuotas de mensajes habituales siguen activas.
- Sólo se amplía la cuota de apertura de WebSockets a 1.000/min en ambas configuraciones efímeras para preparar las conexiones; no cambia código del producto.
- Conexiones calientes y un envío de calentamiento por remitente, comprobado antes de medir. Sin navegador, adjuntos, TLS ni red de Cloudflare.
- Carga ofrecida completa al inicio y ventana global idéntica de 32 mensajes hasta recibir ACK. Esto evita comparar una cola que rechaza con otra que acepta todo. `--inflight 5000` permite observar sobrecarga sin control como ensayo distinto.
- Payloads preparados antes de medir. `text_bytes` corresponde al texto UTF-8; el frame incluye además identidad y metadatos idénticos.

## Casos

| Caso | Cuentas | Chats | Mensajes | Texto | Sockets por chat |
| --- | ---: | ---: | ---: | ---: | ---: |
| Concentrado | 20 | 1 | 1.000 | 256 B | 21 |
| Distribuido | 20 | 20 | 1.000 | 256 B | 2 |
| Mayor concentración | 40 | 1 | 2.000 | 256 B | 41 |
| Mayor payload | 20 | 1 | 1.000 | 4 KiB | 21 |

## Mediciones y controles

`elapsed_ms` es el tiempo de completar el lote entero con ACK durable y llegada al destinatario. `ack` y `recipient_arrival` empiezan al enviar cada frame; `completion_from_offer` y `recipient_from_offer` incluyen también la cola del generador desde que se ofrece el lote completo. No se debe presentar la primera medida como latencia sin cola de una ráfaga infinita.

Cada mensaje requiere exactamente un ACK y una entrega, con ID, revisión, autor, dispositivo, secuencia y texto correctos. Después se reconecta el receptor y se recupera todo por HTTP paginado; se comprueba cada ID, payload y revisión, incluidos calentamientos. Los mensajes recuperados reportados excluyen los calentamientos. NACK, desconexión, timeout o diferencias hacen fallar el caso y permanecen en los resultados.

En Windows se miden CPU y memoria de los procesos workerd descendientes del servidor. El CPU es acumulado de esos procesos durante el intervalo de medición; la memoria es RSS del emulador completo, no asignación de un Worker de producción. El pico es de toda la vida del proceso. También se registra CPU y demora del event loop del generador para detectar saturación del cliente.

La comparación evalúa estas dos implementaciones completas. No aísla el lenguaje: tras la corrección ambas conservan preparación superpuesta, lotes de hasta 16 y caché de permisos, con diferencias de implementación. Los resultados locales no acreditan latencia WAN ni facturación/CPU de Cloudflare.

Los logs quedan ignorados por Git; los JSON públicos contienen métricas y condiciones, sin cookies ni claves. Bases y secretos sintéticos se guardan en `.wrangler/c-*`; una ejecución exitosa los elimina y una fallida conserva su estado para diagnóstico.
