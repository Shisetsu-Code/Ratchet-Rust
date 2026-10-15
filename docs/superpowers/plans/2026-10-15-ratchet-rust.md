# Ratchet Rust Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Backend íntegro en Rust, con paridad con Ratchet-SQLite y publicación reproducible en Ratchet-Rust.

**Architecture:** Dominio independiente del runtime en `crates/core`; adaptadores y handlers Cloudflare en `crates/worker`. La interfaz React y sus contratos se conservan. Worker, D1, R2 y Durable Objects del staging nuevo son independientes.

**Tech Stack:** Rust 1.99.0, worker/worker-build 0.8.7, Wrangler 4.151.0, React 19.3.1, Vite 8.3.4.

**Spec:** `docs/superpowers/specs/2026-10-15-ratchet-rust-design.md`

## Global Constraints

- Backend Rust compilado a `wasm32-unknown-unknown`; sin reenvío al backend TypeScript.
- Interfaz React; contratos HTTP/WSS actuales; persistencia previa al ACK.
- Versiones estables verificadas, lockfiles, ningún secreto o dato privado en Git.
- La copia local de Ratchet-SQLite incluye cambios no confirmados: capturar hashes.
- El usuario aprobó especificación y ejecución continua; no solicitar más permisos.
- No dedicar la sesión a preparar herramientas: informar requisitos ausentes.

## Review Focus

- Reintento tras pérdida del ACK: mismo mensaje, sin doble cuota ni doble entrega.
- Revocación concurrente con login/envío: no crear sesión ni aceptar mensaje obsoleto.
- Payload firmado alterado: rechazar antes de consultar/modificar conversaciones.
- Adjunto autorizado antes de un fallo: compensar su claim y evitar reutilización ajena.
- Historial con mensajes y recibos concurrentes: paginar por revisión sin saltos.

## Task 1: Captura reproducible y matriz de contratos

**Files:** `scripts/capture-baseline.mjs`, `tests/tooling/baseline.test.mjs`, `baseline/source-manifest.json`, `baseline/routes.json`.

**Interfaces:** `captureBaseline(source: string, output: string): Promise<void>`; manifiesto con SHA-256 por archivo y matriz con método/ruta/origen/estado de implementación.

- [x] Escribir pruebas de exclusión de secretos y detección de cambios locales.
- [x] Ejecutar `node --test tests/tooling/baseline.test.mjs`; observar fallo inicial.
- [x] Implementar copia permitida de interfaz, contratos, migraciones y consola; backend sólo como hashes e inventario, nunca como fallback.
- [x] Ejecutar las pruebas y capturar la fuente local; verificar ausencia de secretos.
- [x] Confirmar captura e inventario en Git.

## Task 2: Dominio y errores Rust

**Files:** `Cargo.toml`, `crates/core/src/{lib,error,message,receipt,policy}.rs`, `crates/core/tests/message_contract.rs`.

**Interfaces:** `validate_message(author: &Author, request: &SendRequest) -> Result<PreparedContent, DomainError>`; `authorize_chat(viewer: &Viewer, chat: &ChatScope) -> Result<(), DomainError>`; `advance_receipt(previous: Option<ReceiptState>, incoming: ReceiptState) -> ReceiptState`.

- [x] Pruebas RED de identidad, límites, adjuntos duplicados, permisos, orden y recibos.
- [x] Portar validación del formato `secure-message-content` v2 y códigos de error exactos.
- [x] Ejecutar `cargo test -p ratchet-core`; después formato y Clippy.
- [x] Confirmar dominio probado y registrar las comprobaciones en el ledger.

## Task 3: Worker, D1 y autenticación

**Files:** `crates/worker/src/{lib,http,db,auth,bootstrap,accounts}.rs`, `wrangler.jsonc`, `tests/contracts/auth.mjs`.

**Interfaces:** `handle(req: worker::Request, env: worker::Env, ctx: worker::Context) -> worker::Result<worker::Response>`; `require_session(req: &Request, env: &Env) -> Result<AuthContext, ApiError>`.

- [x] Contratos RED de health, cookie, contraseña, bootstrap, sesión, expiración y revocación.
- [x] Portar las rutas de autenticación, dispositivos, passkeys/llave portable y guards transaccionales.
- [x] Compilar WASM y ejecutar contratos contra Wrangler local con datos sintéticos.
- [x] Verificar login concurrente con recuperación y dispositivos revocados.
- [x] Confirmar sólo después de pasar contratos; marcar las rutas implementadas.

## Task 4: Chat persistente y WSS

**Files:** `crates/worker/src/chat/{mod,storage,crypto,realtime,sync,receipts}.rs`, `tests/contracts/chat.mjs`.

**Interfaces:** Durable Object `ChatRealtime`; `commit` devuelve el contrato actual sólo tras barrera de durabilidad; `sync` consume revisión y límite.

- [x] Pruebas de secuencia, idempotencia, cuota y recuperación por revisión; reintentos sin duplicados.
- [ ] Ampliación operativa opcional: campaña de inyección de pérdida de ACK y rollback por fallos de almacenamiento.
- [x] Portar HKDF/AES-GCM/HMAC con vectores compatibles; preservar AAD y formatos.
- [x] Portar SQLite, recibos monótonos y paginación; probar mezcla de eventos concurrentes.
- [x] Portar WSS, revocación y cuotas compartidas con HTTP; comprobar reconexión.
- [x] Confirmar con pruebas locales y matriz actualizada.

## Task 5: Administración y consola de owner

**Files:** `crates/worker/src/{operators,invitations,leads,owner}.rs`, `tests/contracts/owner.mjs`.

**Interfaces:** Rutas actuales de consola, desafío firmado de uso único, membresías y acceso; misma consola de escritorio.

- [x] Pruebas RED de firmas alteradas, replay, expiración y permisos entre administradores.
- [x] Portar rutas y transacciones de provisionamiento, invitaciones y recuperación.
- [x] Probar que recuperación revoca sesiones y conexiones existentes conservando historial.
- [x] Ejecutar consola contra Worker local; confirmar y actualizar inventario.

## Task 6: Adjuntos, fondos, push y mantenimiento

**Files:** `crates/worker/src/{attachments,wallpaper,push,maintenance}.rs`, `tests/contracts/files.mjs`.

**Interfaces:** Contratos existentes de subida/descarga, claim, fondo por cuenta y push.

- [x] Pruebas RED de límites, autorización, claims incompletos y exclusión entre cuentas.
- [x] Portar R2, compensación, fondos compartidos, Web Push y tareas programadas.
- [x] Verificar adjuntos múltiples, miniaturas y fondo desde cliente tras recarga.
- [x] Confirmar contratos completos; ninguna ruta activa pendiente.

## Task 7: Interfaz y pruebas de paridad

**Files:** `package.json`, `package-lock.json`, `vite.config.ts`, `tests/e2e/`, `.github/workflows/ci.yml`.

**Interfaces:** API same-origin de Rust; interfaz y PWA conservan flujos actuales.

- [x] Resolver últimas dependencias estables compatibles y fijar lockfiles.
- [x] Ejecutar build/typecheck y E2E de owner, administración, cliente, adjuntos, fondos, móvil y offline.
- [x] Pruebas de carga equivalentes: 20/30 simultáneos, varias cuentas, 1.000 mensajes y 10/s sostenidos.
- [x] Registrar fases, p50/p95/p99, pérdidas y duplicados; corregir regresiones.

## Task 8: Revisión, publicación y despliegue posterior

**Files:** `README.md`, `docs/VALIDATION.md`, `scripts/deploy-staging.mjs`.

- [x] Revisar rama completa con un revisor independiente al finalizar implementación.
- [x] Verificar secretos excluidos, formato, Clippy, pruebas y empaquetado WASM.
- [x] Publicar código completo y resultados reales en `Shisetsu-Code/Ratchet-Rust`.
- [x] Documentar comandos de staging independiente; desplegar y probar remotamente en la etapa posterior solicitada.

## Cierre de migración — 2026-10-15

- [x] Las 74 rutas activas están implementadas y verificadas localmente. Dos conservan HTTP 410 intencional para inscripción de passkeys. No hay handlers pendientes de portado.
- [x] Regresión integrada final: 31/31 contratos, 81,208 s. Incluye navegador completo, administración/owner/identidad/archivos/metadatos y 1.000 mensajes en 16,033 s con recuperación en cinco páginas. Suites Rust/crypto/herramientas, tipos/build, formato/Clippy y auditoría npm comprobados durante el cierre.
- [x] Chrome real de escritorio/móvil remoto: proceso de 55,518 s, gestos, tres descargas SHA-256 idénticas, fondo de 400 KB con píxeles iguales, recarga, offline y reconexión.
- [x] Staging nuevo desplegado y probado: `https://ratchet-rust-staging-20261015.braian-n-l.workers.dev`, D1/R2/DO aislados. Ráfaga remota de 30: 453 ms total, media 403 ms/p95 436 ms de llegada Node, orden 1..30, sync exacto, reconnect, logout 4001 y otro cliente conectado. Consola Python con llave cifrada aprobada; pushconfig enabled=true.
- [x] Documentado el modelo real: mensajes legibles por servidor sobre HTTPS/WSS, AES-GCM en reposo y caché/outbox local cifrados; no se afirma E2EE de mensajes. Adjuntos/fondos cifrados en cliente.
- [x] Scripts `npm run verify`, `deploy:staging` y `test:staging` documentados; no instalan herramientas.
- [x] Regresión final 31/31 después de retirar trazas temporales; escenario de 1.000 repetido con recuperación exacta.
- [x] Implementación y resultados publicados y verificados en GitHub: 72a4070.

Una ejecución anterior de 1.000 se detuvo en 100 sin causa aislada; el caso focalizado y la regresión completa posterior pasaron. Se conserva como reserva concreta y no se atribuye una causa sin evidencia. Pruebas adicionales sobre dispositivos físicos, entrega externa Web Push y campañas de pérdida de ACK/evicción/alarma son ampliaciones operativas; no rutas sin implementar ni gates nuevos de migración. Los pasos de confirmar en Git quedan abiertos sólo hasta publicación.

Cierre final comprobado: 31/31 contratos sin trazas, 35 Rust, 3 crypto, 5 tooling y staging remoto validado; ver validation-results.json. El episodio local no reproducido y pruebas opcionales de teléfono/proveedor quedan registrados explícitamente.
