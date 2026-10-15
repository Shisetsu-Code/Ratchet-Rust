# Ratchet Rust Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Backend íntegro en Rust, con paridad con Ratchet-SQLite y publicación reproducible en Ratchet-Rust.

**Architecture:** Dominio independiente del runtime en `crates/core`; adaptadores y handlers Cloudflare en `crates/worker`. La interfaz React y sus contratos se conservan. Worker, D1, R2 y Durable Objects del futuro staging serán independientes.

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

- [ ] Escribir pruebas de exclusión de secretos y detección de cambios locales.
- [ ] Ejecutar `node --test tests/tooling/baseline.test.mjs`; observar fallo inicial.
- [ ] Implementar copia permitida de interfaz, contratos, migraciones y consola; backend sólo como hashes e inventario, nunca como fallback.
- [ ] Ejecutar las pruebas y capturar la fuente local; verificar ausencia de secretos.
- [ ] Confirmar captura e inventario en Git.

## Task 2: Dominio y errores Rust

**Files:** `Cargo.toml`, `crates/core/src/{lib,error,message,receipt,policy}.rs`, `crates/core/tests/message_contract.rs`.

**Interfaces:** `validate_message(author: &Author, request: &SendRequest) -> Result<PreparedContent, DomainError>`; `authorize_chat(viewer: &Viewer, chat: &ChatScope) -> Result<(), DomainError>`; `advance_receipt(previous: Option<ReceiptState>, incoming: ReceiptState) -> ReceiptState`.

- [ ] Pruebas RED de identidad, límites, adjuntos duplicados, permisos, orden y recibos.
- [ ] Portar validación del formato `secure-message-content` v2 y códigos de error exactos.
- [ ] Ejecutar `cargo test -p ratchet-core`; después formato y Clippy.
- [ ] Confirmar dominio probado y registrar las comprobaciones en el ledger.

## Task 3: Worker, D1 y autenticación

**Files:** `crates/worker/src/{lib,http,db,auth,bootstrap,accounts}.rs`, `wrangler.jsonc`, `tests/contracts/auth.mjs`.

**Interfaces:** `handle(req: worker::Request, env: worker::Env, ctx: worker::Context) -> worker::Result<worker::Response>`; `require_session(req: &Request, env: &Env) -> Result<AuthContext, ApiError>`.

- [ ] Contratos RED de health, cookie, contraseña, bootstrap, sesión, expiración y revocación.
- [ ] Portar las rutas de autenticación, dispositivos, passkeys/llave portable y guards transaccionales.
- [ ] Compilar WASM y ejecutar contratos contra Wrangler local con datos sintéticos.
- [ ] Verificar login concurrente con recuperación y dispositivos revocados.
- [ ] Confirmar sólo después de pasar contratos; marcar las rutas implementadas.

## Task 4: Chat persistente y WSS

**Files:** `crates/worker/src/chat/{mod,storage,crypto,realtime,sync,receipts}.rs`, `tests/contracts/chat.mjs`.

**Interfaces:** Durable Object `ChatRealtime`; `commit` devuelve el contrato actual sólo tras barrera de durabilidad; `sync` consume revisión y límite.

- [ ] Pruebas RED de secuencia, idempotencia, cuota, pérdida de ACK y rollback.
- [ ] Portar HKDF/AES-GCM/HMAC con vectores compatibles; preservar AAD y formatos.
- [ ] Portar SQLite, recibos monótonos y paginación; probar mezcla de eventos concurrentes.
- [ ] Portar WSS, revocación y cuotas compartidas con HTTP; comprobar reconexión.
- [ ] Confirmar con pruebas locales y matriz actualizada.

## Task 5: Administración y consola de owner

**Files:** `crates/worker/src/{operators,invitations,leads,owner}.rs`, `tests/contracts/owner.mjs`.

**Interfaces:** Rutas actuales de consola, desafío firmado de uso único, membresías y acceso; misma consola de escritorio.

- [ ] Pruebas RED de firmas alteradas, replay, expiración y permisos entre administradores.
- [ ] Portar rutas y transacciones de provisionamiento, invitaciones y recuperación.
- [ ] Probar que recuperación revoca sesiones y conexiones existentes conservando historial.
- [ ] Ejecutar consola contra Worker local; confirmar y actualizar inventario.

## Task 6: Adjuntos, fondos, push y mantenimiento

**Files:** `crates/worker/src/{attachments,wallpaper,push,maintenance}.rs`, `tests/contracts/files.mjs`.

**Interfaces:** Contratos existentes de subida/descarga, claim, fondo por cuenta y push.

- [ ] Pruebas RED de límites, autorización, claims incompletos y exclusión entre cuentas.
- [ ] Portar R2, compensación, fondos compartidos, Web Push y tareas programadas.
- [ ] Verificar adjuntos múltiples, miniaturas y fondo desde cliente tras recarga.
- [ ] Confirmar contratos completos; ninguna ruta activa pendiente.

## Task 7: Interfaz y pruebas de paridad

**Files:** `package.json`, `package-lock.json`, `vite.config.ts`, `tests/e2e/`, `.github/workflows/ci.yml`.

**Interfaces:** API same-origin de Rust; interfaz y PWA conservan flujos actuales.

- [ ] Resolver últimas dependencias estables compatibles y fijar lockfiles.
- [ ] Ejecutar build/typecheck y E2E de owner, administración, cliente, adjuntos, fondos, móvil y offline.
- [ ] Pruebas de carga equivalentes: 20/30 simultáneos, varias cuentas, 1.000 mensajes y 10/s sostenidos.
- [ ] Registrar fases, p50/p95/p99, pérdidas y duplicados; corregir regresiones.

## Task 8: Revisión, publicación y despliegue posterior

**Files:** `README.md`, `docs/VALIDATION.md`, `scripts/deploy-staging.mjs`.

- [ ] Revisar rama completa con un revisor independiente al finalizar implementación.
- [ ] Verificar secretos excluidos, formato, Clippy, pruebas y empaquetado WASM.
- [ ] Publicar código completo y resultados reales en `Shisetsu-Code/Ratchet-Rust`.
- [ ] Documentar comandos de staging independiente; desplegar y probar remotamente en la etapa posterior solicitada.
