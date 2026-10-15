# Comparación local TypeScript / Rust

El generador ejecuta ambos backends con el mismo Wrangler/workerd instalado, en la misma PC y de forma secuencial. Conserva la fuente TypeScript local utilizada para la migración y comprueba sus hashes contra `baseline/source-manifest.json`. Rust usa el WASM release ya compilado; no se instala ni se despliega nada.

```powershell
node experiments/backend-benchmark/run.mjs --smoke --rounds 1
node experiments/backend-benchmark/run.mjs --rounds 3 --inflight 32
node experiments/backend-benchmark/summarize.mjs experiments/backend-benchmark/results/CARPETA_DE_LA_EJECUCION
```

Requiere la carpeta hermana `Ratchet-SQLite` con sus dependencias existentes. Se puede indicar otra con `RATCHET_TYPESCRIPT_SOURCE`. Los resultados identifican el commit y los hashes reales; el HEAD de TypeScript por sí solo no incluye sus cambios locales.

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

La comparación evalúa estas dos implementaciones completas. No aísla el lenguaje: TypeScript conserva preparación superpuesta, lotes de hasta 16 y caché de permisos; Rust tiene otros caminos de ejecución. Los resultados locales no acreditan latencia WAN ni facturación/CPU de Cloudflare.

Los logs quedan ignorados por Git; los JSON públicos contienen métricas y condiciones, sin cookies ni claves. Bases y secretos sintéticos se guardan en `.wrangler/c-*`; una ejecución exitosa los elimina y una fallida conserva su estado para diagnóstico.
