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
