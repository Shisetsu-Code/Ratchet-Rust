# Ratchet Rust

Migración en curso del backend de Ratchet-SQLite a Rust para Cloudflare Workers.
**Todavía no es una aplicación completa ni está lista para desplegar.**

## Alcance y estado

La interfaz React procede de la copia local actual, con hashes de procedencia en
`baseline/source-manifest.json`. `baseline/routes.json` inventaría 77 declaraciones
de rutas, 74 no reemplazadas por otra ruta anterior. La compilación parcial Rust
expone deliberadamente `migration_ready: false`.
La matriz distingue 24 rutas ejercitadas localmente y 50 pendientes; esos
24 contratos no equivalen a la aceptación integral del producto.

Implementados: validación de mensajes y recibos, reglas de permisos, primitivas
de almacenamiento cifrado, firmas Ed25519, contraseñas PBKDF2, seguridad HTTP,
lectura de sesiones, login/reauth por contraseña y llave portable, bootstrap de
owner y creación de administradores con firma de owner.
El dominio tiene pruebas nativas y los primeros handlers ya pasaron pruebas en
workerd local. WSS, SQLite cifrado, deduplicación, sincronización y recibos están
integrados y probados con 30 mensajes simultáneos. Logout y revocación de sesiones
y dispositivos invalidan los canales afectados mediante un control recuperable;
los demás participantes conservan su conexión. Administración completa, altas de
clientes, passkeys, adjuntos, fondos, push y paridad integral siguen pendientes.

Se iniciará con bases vacías. El esquema nuevo está en
`db/migrations/0001_ratchet_rust.sql`; se retiraron las 26 migraciones históricas
y las tablas antiguas de mensajes D1. No se importará historial de prueba.
Los recursos Cloudflare existentes no fueron modificados.

## Entorno

Versiones fijadas: Rust 1.99.0, worker/worker-build 0.8.7 y dependencias estables
actuales en `Cargo.toml`/`Cargo.lock`. Las dependencias de la interfaz están
fijadas en `package-lock.json`; typecheck y build Vite pasaron. La paridad de uso
del navegador con todos los endpoints Rust sigue pendiente.

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

La comprobación actual usa Rust 1.99.0 y worker-build 0.8.7, preparados por el
usuario. Pasaron 25 pruebas Rust, 5 de herramientas Node y 9 contratos en workerd
local. También compilan la interfaz y sus tipos con las dependencias fijadas.
Los vectores criptográficos de `baseline/` son sintéticos y públicos.

Para empaquetar y ejecutar contratos locales:

```powershell
Push-Location crates/worker
worker-build --release --no-opt
Pop-Location
npm run test:contracts
```

La build conserva metadatos externos de WASM (`strip = "debuginfo"`), necesarios
por [workers-rs #1014](https://github.com/cloudflare/workers-rs/issues/1014).
Los contratos crean bases locales efímeras y restauran `.dev.vars` al terminar.
Las fixtures se escriben sólo en la base efímera del owner sintético de esa
ejecución. No importan cuentas ni secretos de otros despliegues.

## Documentación

- [Diseño](docs/superpowers/specs/2026-10-15-ratchet-rust-design.md)
- [Plan](docs/superpowers/plans/2026-10-15-ratchet-rust.md)
- [Progreso y decisiones](docs/MIGRATION_PROGRESS.md)
