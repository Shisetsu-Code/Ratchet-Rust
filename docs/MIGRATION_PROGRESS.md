# Migration ledger — plan: docs/superpowers/plans/2026-10-15-ratchet-rust.md

- Base: especificación `00d6ffb`; origen local Ratchet-SQLite con cambios sin commit.
- Ruling: ejecución directa y continua, sin otro gate humano, por instrucción explícita del usuario del 2026-10-15.
- Pre-flight: Task 1 contratos → Tasks 2–7; Task 2 dominio → Tasks 3–6; Task 3 auth/DB → Tasks 4–6; Task 4 chat → Tasks 5–7. Interfaces coherentes.
- Herramientas: instalados Rust 1.98.0/1.98.1. Requeridos para verificación final Rust 1.99.0 + target WASM + worker-build 0.8.7. Ninguna instalación realizada.
- Task 1: complete — captura por allowlist, hashes SHA-256, 77 declaraciones de rutas / 74 no reemplazadas; prueba Node RED→GREEN.
- Task 2: dominio de mensajes, permisos y recibos implementado; 12 pruebas RED→GREEN, Clippy correcto con Rust 1.98.1 instalado. Criptografía de almacenamiento: 2 pruebas adicionales de vector y alteración pasadas. Falta verificación final de toolchain 1.99.0.
- Ruling: el usuario autoriza descartar datos de prueba. La nueva instalación inicia vacía; no desarrollar migración de historial ni compatibilidad de datos antiguos. Consolidación del esquema y retiro de módulos sin consumidores al terminar la paridad.
- Ruling: las pruebas criptográficas comparan primitivas contra un vector sintético Web Crypto. Detectaron la longitud implícita HMAC de 512 bits de Web Crypto; corregida y comprobada sin datos reales.
