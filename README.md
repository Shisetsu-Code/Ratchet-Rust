# Ratchet Rust

Migración en curso del backend de Ratchet-SQLite a Rust para Cloudflare Workers.
**Todavía no es una aplicación completa ni está lista para desplegar.**

## Alcance y estado

La interfaz React procede de la copia local actual, con hashes de procedencia en
`baseline/source-manifest.json`. `baseline/routes.json` inventaría 77 declaraciones
de rutas, 74 no reemplazadas por otra ruta anterior. La compilación parcial Rust
expone deliberadamente `migration_ready: false`.

Implementados: validación de mensajes y recibos, reglas de permisos, primitivas
de almacenamiento cifrado, firmas Ed25519, contraseñas PBKDF2, seguridad HTTP,
lectura de sesiones, login/reauth por contraseña y bootstrap de owner con firma.
El dominio tiene pruebas nativas; los handlers requieren todavía pruebas en
el runtime local. WSS, persistencia del chat, administración completa, adjuntos,
fondos, push y pruebas de paridad siguen en desarrollo.

Se iniciará con bases vacías. El esquema nuevo está en
`db/migrations/0001_ratchet_rust.sql`; se retiraron las 26 migraciones históricas
y las tablas antiguas de mensajes D1. No se importará historial de prueba.
Los recursos Cloudflare existentes no fueron modificados.

## Entorno

Versiones fijadas: Rust 1.99.0, worker/worker-build 0.8.7 y dependencias estables
actuales en `Cargo.toml`/`Cargo.lock`. La actualización de la interfaz está
pendiente; sus fuentes capturadas no equivalen a una build nueva ya validada.

Comprobación sin instalar nada:

```powershell
node scripts/check-toolchain.mjs
```

Preparación del entorno cuando corresponda:

```powershell
rustup toolchain install 1.99.0 --profile minimal --component rustfmt --component clippy --target wasm32-unknown-unknown
cargo +1.99.0 install worker-build --version 0.8.7 --locked
```

Pruebas y compilación:

```powershell
cargo test -p ratchet-core --locked
cargo check -p ratchet-worker --target wasm32-unknown-unknown --locked
cargo fmt --all --check
cargo clippy -p ratchet-core --all-targets --locked -- -D warnings
node --test tests/tooling/*.test.mjs
```

La primera comprobación de dominio y WASM se hizo con Rust 1.98.1 ya instalado,
sin instalar toolchains ni herramientas globales. La validación con 1.99.0 y el
empaquetado local aún están pendientes. Los vectores criptográficos de `baseline/`
usan exclusivamente llaves sintéticas públicas de prueba.

## Documentación

- [Diseño](docs/superpowers/specs/2026-10-15-ratchet-rust-design.md)
- [Plan](docs/superpowers/plans/2026-10-15-ratchet-rust.md)
- [Progreso y decisiones](docs/MIGRATION_PROGRESS.md)
