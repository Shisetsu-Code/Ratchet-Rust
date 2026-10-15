# Migration ledger — plan: docs/superpowers/plans/2026-10-15-ratchet-rust.md

- Base: especificación `00d6ffb`; origen local Ratchet-SQLite con cambios sin commit.
- Ruling: ejecución directa y continua, sin otro gate humano, por instrucción explícita del usuario del 2026-10-15.
- Pre-flight: Task 1 contratos → Tasks 2–7; Task 2 dominio → Tasks 3–6; Task 3 auth/DB → Tasks 4–6; Task 4 chat → Tasks 5–7. Interfaces coherentes.
- Herramientas: instalados Rust 1.98.0/1.98.1. Requeridos para verificación final Rust 1.99.0 + target WASM + worker-build 0.8.7. Ninguna instalación realizada.
- Task 1: complete — captura por allowlist, hashes SHA-256, 77 declaraciones de rutas / 74 no reemplazadas; prueba Node RED→GREEN.
- Task 2: dominio de mensajes, permisos y recibos implementado; 12 pruebas RED→GREEN, Clippy correcto con Rust 1.98.1 instalado. Criptografía de almacenamiento: 2 pruebas adicionales de vector y alteración pasadas. Falta verificación final de toolchain 1.99.0.
- Ruling: el usuario autoriza descartar datos de prueba. La nueva instalación inicia vacía; no desarrollar migración de historial ni compatibilidad de datos antiguos. Consolidación del esquema y retiro de módulos sin consumidores al terminar la paridad.
- Ruling: las pruebas criptográficas comparan primitivas contra un vector sintético Web Crypto. Detectaron la longitud implícita HMAC de 512 bits de Web Crypto; corregida y comprobada sin datos reales.
- Task 2: complete (código y verificación disponible) — 22 pruebas Rust nativas pasadas; Clippy de core y de Worker WASM sin advertencias de código. Se usó explícitamente Rust 1.98.1 instalado; la aceptación final con 1.99.0 sigue pendiente.
- Task 3: partial — adaptador workers-rs 0.8.7, errores, cabeceras, origen, límites de stream y cuota de red; handlers de health, bootstrap, contraseña y sesiones compilan a WASM. Todavía sin pruebas de integración en workerd; passkeys, llave portable de login y revocación con fencing pendientes.
- Esquema: una migración nueva basada únicamente en definiciones, sin importar datos. Eliminadas las 26 migraciones históricas del runtime y 10 tablas de almacenamiento/recuperación antiguas. Prueba Node de esquema, FK y guard transaccional pasada.
- Consola: eliminada la carga automática de secretos de otros despliegues. Origen local por defecto; dependencia cryptography 50.0.2 verificada en PyPI y fijada. Dos archivos Python con sintaxis validada; GUI/integración pendiente.
- Validación: 22 pruebas Rust + 2 pruebas Node pasadas; `cargo +1.98.1 clippy -p ratchet-core --all-targets --locked --offline -- -D warnings` y equivalente Worker/WASM pasados.
- Preflight real: faltan Rust 1.99.0 y worker-build 0.8.7; `node scripts/check-toolchain.mjs` devuelve ready=false. Ninguna herramienta global instalada ni actualizada. Detenida la preparación del entorno siguiendo la preferencia explícita del usuario.
- Próximo paso: validar con toolchain final y empaquetar el Worker parcial para pruebas locales de bootstrap/login; continuar Tasks 3–8. No hay despliegue Rust ni una aplicación completa todavía.

## Continuación tras preparar herramientas — 2026-10-15

- El usuario instaló Rust 1.99.0 y worker-build 0.8.7. Preflight ready=true; empaquetado real completado.
- Interfaz: dependencias estables actuales fijadas, package-lock generado, build Vite y typecheck correctos. El capturador incluía inicialmente menos extensiones de las necesarias: incorporados JS/MJS, service worker y tsconfig.base.json.
- Task 3: bootstrap de owner, contraseña y consultas de sesión pasaron en workerd local, incluidos replay, credenciales inválidas, origen ajeno y límites. Aún faltan métodos de llave portable/passkeys y revocación coordinada.
- Task 4: HTTP/WSS, SQLite con AES-GCM/HKDF/HMAC, ACK después de storage.sync, deduplicación, conflictos, secuencias, sync paginado y recibos probados. Faltan batch HTTP, proyección de estadísticas, integración de claims y coordinación de revocaciones antes de considerarlo completo.
- Fallo real corregido: respuestas del DO traen cabeceras inmutables; se copian antes de adjuntar cabeceras de seguridad.
- Fallo real corregido: BLOB de SQLite es ArrayBuffer, no array JS; deserialización binaria explícita.
- Fallo real corregido: futures Mutex no es FIFO. Sustituido por FifoLane con transferencia de guard por oneshot; 3 pruebas nativas cubren orden, cancelación ya notificada y 1.000 esperas. La espera de durabilidad queda fuera del turno.
- Empaquetado release: strip=true rompe catch wrappers de wasm-bindgen (workers-rs#1014). strip=debuginfo conserva metadatos y funciona con las versiones estables actuales.
- Runner Windows: nombres cortos evitan límite de rutas SQLite; cleanup reintenta EBUSY y no modifica secretos si aborta antes de iniciar. Prueba de preservación de archivo pasada.
- Evidencia actual: 25 pruebas Rust (22 dominio + 3 FIFO), 3 Node, 7 contratos locales pasados; interfaz compila/typecheck. Ráfaga WSS de 30: total 205.3 ms, media individual 108.1 ms, p50 105.7 ms, p95 198.6 ms, máximo 204.2 ms. Datos exclusivamente locales/sintéticos, sin equivalencia todavía con WAN.
- Siguiente implementación: control de revocación y registro de rooms serializados en un DO de control; registro antes de conceder leases para cubrir rooms nuevas concurrentes. Las revocaciones deben cercar sólo los chats afectados, mutar D1 y renovar/cerrar sockets según la autoridad vigente.
- Diseño de recuperación del control: journal local + estado D1 de operación PENDING/COMMITTED/ABORTED. Batch D1 verifica PENDING y marca COMMITTED junto con la mutación; recuperación CAS a ABORTED evita que una escritura tardía ocurra después de liberar cercos. No adivinar un commit externo incierto.
- No desplegar: cliente completo aún no tiene todos los endpoints y todavía no hay control de invalidación conectado a mutaciones públicas.

## Autenticación y revocación coordinada — 2026-10-15

- Implementados logout, revocación de sesión y dispositivo propios. Los dos últimos requieren dispositivo autorizado y reautenticación reciente; identidad y propiedad se resuelven otra vez dentro del control serializado.
- El control registra rooms antes de conceder leases. Cerca chats afectados, aplica el batch D1 con guard PENDING y marca COMMITTED junto con la mutación. La recuperación convierte PENDING o ausencia de marcador en ABORTED antes de liberar; una escritura tardía no puede superar el guard.
- Journal local sin cookies, contraseñas ni payload de administración; alarma de recuperación armada antes de cercar. Tombstones persistentes impiden que una llamada fence retrasada reinstale un cerco ya liberado. Retención/limpieza de marcadores y tombstones queda para mantenimiento.
- Release vuelve a resolver la autoridad de los sockets: cierra sólo sesiones revocadas; conserva al otro participante. La revisión independiente detectó ping→4001 durante un cerco transitorio: corregido para conservar el canal durante ese estado. Revisión posterior sin bloqueantes en este bloque.
- Portados prepare/complete de provisión ADMIN con firma de owner, sin sesión de navegador implícita. El batch comprueba de nuevo owner, llave, membresía, expiración y consumo; no basta con una comprobación previa al PBKDF2.
- Portados login y reauth mediante llave portable: desafío firmado con propósito/origen, expiración, consumo único y guard transaccional de llave/usuario/dispositivo/sesión. El alta de dispositivo y la sesión se confirman juntas; dispositivos revocados no vuelven a ingresar.
- Verificación: 25 pruebas nativas y 5 pruebas Node. Los 9 contratos workerd cubren bootstrap, contraseña, provisión ADMIN, llave portable, reautenticación, WSS, secuencias, lookup, recibos individuales/batch, revocación, reconexión y rechazos de autoridad. La prueba WSS mantiene pings del cliente concurrentes con las revocaciones.
- Diagnóstico del runner: algunos sockets nuevos recibían Close4001 pero Node esperaba su limpieza TCP predeterminada de 30s; closeTimeout=1s sólo acota esa limpieza. Se sigue exigiendo el código real 4001, sesión HTTP inválida y continuidad del otro participante. No se ocultó un socket OPEN ni se redujeron controles de autorización.
- Fixtures: retirada la segunda invocación concurrente de Wrangler para sembrar datos; provocaba fallos intermitentes de fetch local. Node SQLite selecciona exclusivamente el archivo efímero con el owner sintético esperado, con FK y transacción. El esquema mantenido ya no puede sobrescribirse accidentalmente con el capturador inicial.
- Pendientes: passkeys y activación de cliente; operadores/invitaciones/clientes y consola owner completa; claims/adjuntos/fondos/push; batch de mensajes/proyección y mantenimiento; E2E integral, carga, revisión final y staging Rust independiente. No es todavía una migración completa ni un despliegue listo.
- Matriz actualizada con evidencia por ruta: 24 verificadas localmente / 74 rutas activas, 50 pendientes. Las pruebas de recuperación SQL verifican el commit tardío y fence tardío; todavía falta inyección de fallos end-to-end de alarma/evicción en workerd.
- Última regresión completa: 9/9 contratos; ráfaga local de 30 mensajes en 204,7 ms, media individual 118 ms y p95 198,1 ms. Es una muestra local variable, no una medición de latencia geográfica ni una garantía de rendimiento.

## Implementación completa y aceptación final abierta — 2026-10-15

Esta sección sustituye los estados parciales anteriores; las secciones previas conservan el historial real de la migración.

- [x] Implementadas en Rust las 74 rutas activas de referencia, sin fallback al backend TypeScript. La matriz activa contiene 72 handlers operativos y dos respuestas 410 intencionales para inscripción de passkeys; login/reauth con passkeys existentes está implementado.
- [x] `baseline/routes.json` actualizado con módulo Rust y pruebas por ruta. Distingue 70 rutas con evidencia local directa/navegador, tres con evidencia de módulo y una con contrato negativo. No se convierte ausencia de prueba individual en una afirmación de cobertura completa.
- [x] Autenticación, dispositivos, certificados, prekeys, activación, agentes/grants, invitaciones/clientes y consola owner integrados. Recuperación owner firmada probada con cliente Python real, cierre WSS e historial conservado.
- [x] Chat batch, metadatos y proyección, adjuntos R2 y claims, fondos cifrados por cuenta, suscripciones/envío Web Push y mantenimiento implementados. La prueba de metadatos también comprueba limpieza local programada de una carga expirada.
- [x] Corregido hallazgo de revisión: alta de cliente usa INSERT de credenciales y rechaza contraseña preexistente; sólo ADMIN puede hacer reset. El caso negativo de OPERATOR prueba que la contraseña original sigue funcionando. Se mantiene dentro de la regresión final pendiente.
- [x] Evidencia conocida: 28 pruebas Rust de workspace, tres criptográficas y cinco de herramientas; 29 contratos de ejecución previa y metadatos comprobado aparte. No se presentan como una única ejecución final posterior a todo cambio.
- [x] Carga local ejercitada: ráfagas de 20/30, varias cuentas, 1.000 mensajes, 10/s sostenidos y rechazo de cuota. Los tests calculan percentiles y comprueban recuperación exacta por ACK durable; no se extrapolan métricas WAN.
- [x] Recorrido completo de Chrome real pasado en escritorio y móvil: login, invitación, entrada/conversión del invitado, mensajes por HTTPS/WSS con cifrado en reposo, recarga, opciones y gestos táctiles, teclado reducido, tres archivos juntos descargados con SHA-256 idéntico, fondo de 400 KB renderizado con píxeles idénticos, destinatario/remitente offline y reconexión.
- Ruling de diagnóstico: el gesto horizontal de Chrome producía navegación nativa tras `pushState` sin llamada JS a `history.back`. `pan-y` no bastaba; listener touchmove no pasivo cancela temprano el gesto reconocido. La limpieza de historial se serializa para cubrir también la carrera close/open. El recorrido posterior pasó con los gestos presentes.
- Ruling CSP: no abrir `connect-src` para el test. La comprobación del fondo usa Image/canvas y píxeles reales en lugar de `fetch(blob:)` bloqueado por la política.
- [x] Staging nuevo configurado en `https://ratchet-rust-staging-20261015.braian-n-l.workers.dev`, con D1/R2/DO nuevos y aislados. Esquema vacío; sin reutilización de datos/secretos de referencia.
- [ ] Última regresión consolidada de todos los módulos después de los cambios finales, formato/Clippy, revisión y empaquetado final.
- [ ] Smoke y recorrido funcional remoto del staging nuevo; entrega Web Push externa y fallos remotos de alarma/evicción siguen sin acreditación integral.
- [ ] Publicación de código/resultados finales. Esta sección no afirma commits/push nuevos.

Evidencia, comandos, capturas y reservas detalladas en `docs/VALIDATION.md`. La implementación completa y la aceptación final son estados distintos; los pendientes anteriores son de validación/publicación, no handlers omitidos.

## Cierre integrado local y remoto — 2026-10-15

Esta sección es el estado vigente y sustituye las reservas de aceptación anteriores.

- [x] Las 74 rutas activas de la matriz tienen implementación Rust y evidencia local. Las dos rutas de inscripción de passkeys responden 410 por contrato; no hay endpoints pendientes de portado. Añadidas aserciones individuales de grantsGET, nombrePATCH/lease, envelopesPOST y pushconfig200.
- [x] Regresión integrada: 31/31 contratos, cero fallos, 81,208 s. Lote 1.000 desde 20 cuentas: 16,0327 s y cinco páginas de recuperación, IDs únicos sin pérdida ni duplicación. Pruebas Rust de workspace, tres crypto, cinco herramientas, tipos/build, formato/Clippy y npm audit 0 comprobados durante el cierre.
- [x] Staging nuevo desplegado y aislado en `https://ratchet-rust-staging-20261015.braian-n-l.workers.dev`. Chrome remoto completo aprobado en 55,518 s de proceso: escritorio/móvil, gestos reales, mensajes, tres archivos descargados con SHA-256 igual, fondo 400 KB con píxeles iguales, reload y offline/reconnect.
- [x] Transporte remoto de 30: total 453 ms, media 403 ms, p95 436 ms de llegada WSS medida en Node; no es render DOM. Publicación 1..30, sync HTTPS 30 exactos, reconexión, logout 4001 y continuidad del otro cliente aprobados. Consola Python remota con llave cifrada aprobada; pushconfig enabled=true.
- [x] Corregidos guard de credencial frente a OPERATOR, gesto nativo Chrome, reintentos durables de control/proyección, nombre visible reflejado en leases y publicación FIFO independiente. El fallo remoto anterior 2..30,1 quedó cubierto por la comprobación de orden real posterior.
- Ruling de confidencialidad: el transporte actual de mensajes es legible por el servidor sobre HTTPS/WSS, como el prototipo de referencia. AES-GCM protege almacenamiento servidor y la caché/outbox local está cifrada. No se afirma E2EE de mensajes. Adjuntos y fondos sí se cifran en el cliente.
- Reserva de carga concreta: una ejecución anterior quedó en 100 de 1.000 sin causa aislada; el caso focalizado (~14 s) y la regresión integrada posterior pasaron. No se atribuye a infraestructura ni lógica sin evidencia.
- [x] Documentados scripts de verificación local y despliegue/prueba del staging, sin instalación de herramientas.
- [ ] Registrar repeticiones tras retirar trazas temporales, separadas del resultado 31/31 ya obtenido.
- [ ] Publicar commit/código/resultados; no se afirma un push nuevo hasta hacerlo.

La entrega física de push y campañas adicionales de fallos de infraestructura son ampliaciones operativas opcionales, no rutas sin portar ni una auditoría abierta que impida cerrar la migración. Evidencia y comandos en `docs/VALIDATION.md`.

## Artefacto de cierre

- Regresión final sin trazas: 31/31 en 80,136 s; 35 pruebas Rust, 3 crypto y 5 tooling; formato, Clippy, typecheck, build y npm audit (0) comprobados.
- Generador sostenido corregido para no recuperar retrasos como ráfagas; cuotas temporales CUSTOMER reintentables. Ráfagas, 1.000 mensajes y recuperación volvieron a pasar. Se conserva la incidencia no reproducida sin atribuir causa.
- Worker remoto 0e3e6029-5158-4ea2-a031-6950b74038ce: health Rust migration_ready=true; navegador completo y última ráfaga30 ordenada, sync, revocación4001 y consola cifrada aprobados.
- Resultado reproducible/limitaciones en docs/validation-results.json. Publicación de este cierre en main del repositorio dedicado; no hay cambios en el despliegue de referencia.
