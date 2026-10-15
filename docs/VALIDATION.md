# Validación de Ratchet Rust

## Recuperación de optimizaciones — 2026-10-15

El backend vuelve a usar caché de permisos invalidada por cercado/liberación, preparación concurrente limitada a 64 y lotes inmediatos de hasta 16 con durabilidad compartida. Mantiene transacciones individuales, deduplicación, secuencias, claims de adjuntos y publicación FIFO con recibos. La sesión se comprueba también al confirmar, para impedir que venza mientras el trabajo espera en cola.

Regresión del artefacto corregido: **52 pruebas Rust, 3 criptográficas, 5 de herramientas y 34 contratos completos aprobados**; estos últimos en 65,064 s. Formato, Clippy nativo/WASM y tipos del cliente aprobados. Tres contratos nuevos cubren un rechazo seguido de envíos válidos, duplicados en una misma ráfaga y recibos concurrentes con mensajes. La suite incluye navegador real, tres adjuntos con SHA-256 idéntico, fondo compartido con píxeles idénticos, offline/reconexión, revocación y consola owner.

La carga integrada sin ventana del generador recuperó los 1.000 mensajes desde 20 cuentas en cinco páginas, sin pérdidas ni duplicados; el lote terminó en 5,804 s. Esa muestra no sustituye la comparación pareada: [benchmark posterior a las correcciones](BENCHMARK_RUST_OPTIMIZED_2026-10-15.md). Las cifras anteriores que siguen debajo se conservan como historial.

Historial previo a las correcciones: la [primera comparación contra TypeScript](BENCHMARK_TYPESCRIPT_RUST_2026-10-15.md) completó 24 casos y 30.000 mensajes; detectó una regresión del port. Ese informe identifica el artefacto anterior y se conserva para comparar la mejora, sin confundir aprobación funcional con capacidad.

Cierre de implementación y pruebas del 2026-10-15. Las 74 rutas activas están implementadas en Rust y comprobadas localmente; staging independiente desplegado y recorrido funcional remoto aprobado. Implementación publicada y verificada en GitHub: `72a40707384a09bd82421ba3484c0a03fe9f1c90`.

## Rutas y contratos

`baseline/routes.json` contiene 74 rutas únicas con módulo Rust y evidencia. De las 77 declaraciones originales se excluyen tres reemplazadas por rutas anteriores. Hay 72 handlers operativos y dos HTTP 410 intencionales de inscripción de passkeys (`ACCESS_PASSKEY_ENROLLMENT_DISABLED`), iguales al contrato de referencia; login/reauth con passkeys existentes funcionan. Las 74 tienen `verified-local`, incluidas las aserciones agregadas para listado de grants, PATCH de nombre visible, agregado de envelopes de fondo y GET de configuración push autorizado.

| Área | Código | Evidencia en tests/contracts/ |
| --- | --- | --- |
| Bootstrap, provisión y acceso | `bootstrap.rs`, `provisioning.rs`, `password.rs`, `portable.rs` | `auth.mjs`: firmas, replay, origen, cookies, sesiones, reauth y dispositivo revocado |
| Identidad | `identity.rs`, `identity/` | `identity.mjs`: ES256/RS256/Ed25519 reales, firma/origen/desafío/contador, prekeys, activación y aprobación |
| Administración | `admin.rs`, `admin/` | `admin.mjs`: aislamiento de ADMIN, grants concurrentes, invitaciones, cuentas, reset y nombre reflejado en WSS abierto |
| Consola owner | `owner.rs` | `owner.mjs`, `native-console.py`: operación firmada, recuperación, cierre WSS, historial y cliente Python real |
| Chat y control | `chat/` | `auth.mjs`, `chat-boundary.mjs`, `metadata.mjs`, `load.mjs`: durabilidad, secuencia, idempotencia, recibos, batch, proyección, cuotas y recuperación |
| Archivos, fondos y push | `files.rs`, `files/` | `files.mjs`: multipart, ETag/tamaño, claims, rangos, aislamiento, fondos y suscripciones; `metadata.mjs`: limpieza programada |
| Interfaz | `src/client/`, Worker same-origin | `browser.mjs`: Chrome real de escritorio/móvil; mensajes, archivos, fondos, recarga y offline |

Una ruta verificada no implica que se hayan agotado todas las combinaciones de fallos y plataformas.

## Modelo de confidencialidad verificado

`src/client/crypto/server-message-transport.ts` implementa transporte de mensajes legible por el servidor sobre HTTPS/WSS, como el prototipo actual de referencia. El mensaje se almacena cifrado con AES-GCM en el servidor; la caché y outbox locales también permanecen cifrados. **No se afirma cifrado de extremo a extremo para mensajes.** Adjuntos y fondos se cifran en el cliente. Las pruebas de transporte/orden no se describen como demostración de E2EE.

## Resultado local integrado

La ejecución conservada en `final-contracts.log` terminó con **31 pruebas, 31 aprobadas, cero fallos/omitidas**, duración total **80,136 s**. Incluye las correcciones de autorización, nombre visible, publicación en orden, reintentos durables y el recorrido de navegador completo. Pasaron 35 pruebas Rust de workspace, tres pruebas criptográficas y cinco de herramientas; formato/Clippy, tipos, build y empaquetado fueron comprobados durante el cierre. `npm audit` informó cero vulnerabilidades.

| Escenario local | Mensajes | Total envío/recepción | ACK medio | ACK p95 | ACK p99 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Ráfaga | 20 | 187.38 ms | 91.88 ms | 156.97 ms | 164.25 ms |
| Ráfaga | 30 | 246.64 ms | 142.01 ms | 235.98 ms | 242.79 ms |
| Tres cuentas, 30 cada una | 90 | 752.69 ms | 387.65 ms | 700.05 ms | 728.18 ms |
| Veinte cuentas, 50 cada una | 1000 | 14490.59 ms | 7689.73 ms | 13805.32 ms | 14328.18 ms |
| Sostenido hasta 10 mensajes/s | 120 | 13073.47 ms | 36.78 ms | 186.41 ms | 306.01 ms |

Los tiempos de ráfaga incluyen la espera de cola desde el envío simultáneo. La llegada y presentación medidas por `load.mjs` son decodificación en Node; **no son render DOM**. Los 1.000 mensajes se recuperaron por HTTP en cinco páginas con 1.000 IDs únicos y sin pérdidas ni duplicados. La prueba de cuota aceptó 100 de 101 y devolvió un NACK reintentable para el restante.

Una ejecución anterior se detuvo en 100 de 1.000 mensajes sin causa aislada. El diagnóstico focalizado posterior pasó en aproximadamente 14 s y la regresión completa pasó en 16,033 s para ese escenario. Se conserva este dato sin atribuirlo a infraestructura o lógica sin evidencia. Tras retirar las trazas temporales, el escenario de 1.000 volvió a pasar en ejecuciones integradas posteriores. La aceptación final 31/31 corresponde al artefacto sin trazas. El generador sostenido se corrigió para no lanzar ráfagas de recuperación al retrasarse su reloj; los límites temporales del cliente devuelven NACK reintentable.

## Navegador real local y remoto

Chrome headless completó escritorio y emulación móvil con contextos separados y eventos táctiles CDP:

1. Login por interfaz, invitación, entrada del invitado y conversión a cliente conservando chat.
2. Mensajes bidireccionales y recuperación después de recargar.
3. Opciones del cliente sin acciones de staff, gestos reales para abrir/cerrar navegación y envío con viewport de teclado reducido.
4. Tres archivos juntos: dos PNG —uno de 400 KB— y PDF; el receptor descargó bytes con SHA-256 idéntico.
5. Fondo PNG de 400 KB visible para el cliente móvil después de recargar, con dimensiones y píxeles RGBA iguales al original.
6. Destinatario offline, recuperación durable, envío tras reconectar, cola del remitente offline y recarga posterior.

El recorrido remoto pasó en **55,304 s** de proceso (54,841 s de caso). Capturas en `tests/browser/results/mobile-chat.png`, `desktop-files-wallpaper.png` y `mobile-wallpaper.png`. Las credenciales usadas son sintéticas.

Los gestos revelaron una navegación nativa de Chrome hacia `about:blank`: después del pushState de la app hubo beforeunload sin llamada JavaScript a history.back. Pan-y no bastaba; un touchmove nativo no pasivo cancela el gesto reconocido cuando aún es cancelable. La cola de limpieza de historial evita además la carrera al cerrar/reabrir. El recorrido pasó con ambos gestos presentes.

La CSP permanece estricta: la comprobación del fondo usa Image/canvas en lugar de fetch(blob:), bloqueado correctamente por connect-src 'self'.

## Evidencia en Cloudflare

Destino: [ratchet-rust-staging-20261015.braian-n-l.workers.dev](https://ratchet-rust-staging-20261015.braian-n-l.workers.dev).

`wrangler.staging.jsonc` utiliza Worker, D1 `ratchet-rust-staging-20261015`, R2 `ratchet-rust-staging-20261015-files` y Durable Objects SQLite nuevos y aislados. No se reutilizaron datos ni secretos de referencia.

- Bootstrap/provisión firmada y navegador completo remoto aprobados.
- Ráfaga WSS de 30 aprobada: **487 ms total**, llegada media al receptor **334 ms**, **p95 341 ms**. Es llegada por red medida en Node, separada del render del navegador.
- Publicación WSS en orden **1..30**, sync HTTPS con exactamente 30 mensajes, reconexión y recuperación exacta aprobados. Se corrigió una publicación que antes podía mostrar 2..30,1: la publicación usa una FIFO independiente de la cola de escritura.
- Logout cerró el socket afectado con **4001** y mantuvo conectado al cliente restante.
- Consola Python real con llave local cifrada contra Cloudflare aprobada.
- Configuración Web Push remota comprobada con `enabled=true`; esto no equivale a entrega de notificación a un teléfono físico.

## Correcciones comprobadas y reproducción

Además de Chrome/FIFO, se corrigieron: creación de cuenta por OPERATOR con credencial preexistente (INSERT inicial; reset reservado a ADMIN), renovación de leases al cambiar nombre visible, reintento durable de liberación de control y reintento durable de proyección de estadísticas. Las pruebas de estos cambios forman parte de la regresión local.

```powershell
npm run verify
npm run build
npm run deploy:staging
npm run test:staging
```

`verify-local.mjs` no instala herramientas ni despliega: comprueba versiones, formato, Clippy, Rust/crypto/herramientas, cliente, WASM y contratos locales. `deploy-staging.mjs` restringe recursos al staging nuevo, prepara secretos ignorados, hace dry-run, aplica migración y despliega. `verify-staging.mjs` utiliza cuentas sintéticas aisladas, Chrome y `staging-transport.mjs`; no siembra SQL remoto de referencia. Credenciales y llave cifrada quedan fuera de Git.

## Alcance del cierre

- [x] Implementación y matriz de las 74 rutas activas.
- [x] Regresión integrada 31/31 y pruebas locales de carga/navegador.
- [x] Staging nuevo y recorrido funcional remoto, transporte y consola nativa.
- [x] Documentación del modelo real de cifrado y del alcance de medición.
- [x] Repetición 31/31 sobre el artefacto final sin trazas; resultados públicos en validation-results.json.
- [x] Cierre publicado y verificado en main de Shisetsu-Code/Ratchet-Rust.

Como ampliaciones operativas opcionales quedan pruebas sobre teléfonos físicos, entrega Web Push externa y campañas adicionales de evicción/alarma/fallos de almacenamiento. No son rutas pendientes de portado ni se usan para aplazar indefinidamente la migración terminada.

Artefacto remoto final: `0e3e6029-5158-4ea2-a031-6950b74038ce`. El SHA-256 del WASM probado está en `validation-results.json`. La consola se comprobó con Python cryptography 48.0.1 ya instalado; requirements fija 50.0.2 para instalaciones nuevas, sin actualizar el entorno de esta PC. Los avisos de Clippy restantes corresponden al caché de hard links de Windows, no al código.
