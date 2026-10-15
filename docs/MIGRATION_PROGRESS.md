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
