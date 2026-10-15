# Ratchet Rust: especificación de migración

Fecha: 2026-10-15. Estado: diseño propuesto para revisión; implementación pendiente.

## Objetivo y base

Migrar todo el backend de Ratchet a Rust y publicarlo en
https://github.com/Shisetsu-Code/Ratchet-Rust. Conservar la interfaz React,
los contratos HTTP/WSS y las capacidades de la versión local Ratchet-SQLite.
El despliegue y la validación remota se harán después, en recursos separados.

La fuente incluye los archivos locales modificados y los nuevos archivos de
Ratchet-SQLite, no solamente su último commit. Incluye consola de owner,
recuperación administrativa, controles de concurrencia, cuotas, persistencia
antes de confirmar mensajes y el botón visible para subir el fondo compartido.
Registrar hashes del código de origen al iniciar la implementación. No copiar
secretos, bases de datos, cachés, node_modules ni artefactos de pruebas al repo.

## Arquitectura elegida

- Worker Rust compilado a wasm32-unknown-unknown mediante workers-rs.
- Durable Object Rust por chat: conexiones WSS, secuencia canónica, mensajes
  cifrados en SQLite, deduplicación, confirmaciones y revocación.
- D1: cuentas, sesiones, membresías, permisos, cuotas y metadatos actuales.
- R2: adjuntos y fondos; conservar validación, autorización y compensación
  de operaciones incompletas.
- React/TypeScript: misma interfaz y PWA, consumiendo los mismos contratos.
- Consola local de owner: conservar su interfaz y protocolo firmado; migrar
  a Rust los endpoints y toda su lógica de autorización en el servidor.
- JavaScript generado por las herramientas WASM permitido como adaptación
  al runtime. Ningún servicio TypeScript existente ejecuta lógica de backend
  de la versión final ni recibe peticiones reenviadas para completar funciones.

Alternativas consideradas: reescribir también la interfaz en Rust introduce
otra migración sin necesidad funcional; usar un servidor Rust externo cambia
el alojamiento, las operaciones y el modelo de persistencia. El Worker Rust
conserva el entorno Cloudflare pedido y permite comparar el comportamiento.

## Versiones y compatibilidad

Registros oficiales consultados el 2026-10-15:

| Componente | Estable observada |
| --- | --- |
| Rust | 1.99.0 |
| worker / worker-build | 0.8.7 / 0.8.7 |
| wasm-bindgen | 0.2.129 |
| serde / serde_json | 1.0.229 / 1.0.154 |
| Wrangler | 4.151.0 |
| React / react-dom | 19.3.1 / 19.3.1 |
| Vite / plugin React | 8.3.4 / 6.1.2 |
| TypeScript | 7.0.2 |
| Playwright | 1.64.1 |

Estas versiones son candidatas verificadas en los registros, no una afirmación
de compatibilidad ya probada. worker 0.8.7 requiere wasm-bindgen ^0.2.129.
Resolver el conjunto completo, fijar dependencias directas y guardar Cargo.lock
y package-lock.json. No usar prereleases. Verificar cualquier otra dependencia
en su registro oficial y compilar/pruebar antes de aceptarla. No prometer mejoras
de latencia por el cambio de lenguaje: medirlas.

El equipo tiene Rust 1.98.1 y el target WASM para esa herramienta. Falta
worker-build en PATH. Antes de instalar o actualizar el entorno, informar al
usuario de los requisitos concretos; su preferencia es preparar el entorno él.
También comprobar el target WASM del nuevo toolchain y la coincidencia entre
el binario wasm-bindgen y las librerías resueltas.

## Paridad obligatoria

Inventariar cada ruta activa, método, cuerpo, respuesta y permiso antes de portarla.
Cubrir bootstrap/provisionamiento, owner, contraseña, passkeys/llave portable,
sesiones/dispositivos, operadores, invitaciones, acceso de clientes, chats,
historial, recibos, adjuntos, fondo compartido y notificaciones push.
Conservar tareas programadas, recuperación de operaciones y rotación de claves.
Las funciones web retiradas de recuperación/verificación no deben reaparecer.

Mantener hashes de contraseña y formatos criptográficos interoperables donde
existan. Usar bibliotecas mantenidas o Web Crypto mediante bindings, con vectores
de compatibilidad; no inventar primitivas ni rebajar la verificación de firmas.
La recuperación por consola conserva desafío firmado, expiración, uso único,
archivo de llave y revocación. La sesión no sustituye los permisos por recurso.

WSS debe preservar orden por chat, deduplicación por identificador, cuotas,
persistencia previa al ACK y reintentos seguros después de desconexión.
Una sesión revocada no puede seguir enviando por conexiones ya abiertas.
Nunca registrar contraseñas, llaves, cookies o cuerpos de conversaciones.

## Organización y manejo de errores

Separar dominio, contratos, autorización, adaptadores Cloudflare y handlers.
Mantener módulos pequeños para auth, cuentas, chat, almacenamiento, adjuntos,
apariencia, push, owner y mantenimiento. Errores internos se traducen al contrato
actual con código estable y request ID; no exponer errores SQL ni secretos.
Limitar tamaños y memoria antes de cargar cuerpos completos.

## Criterios de aceptación

1. Compilación Rust nativa para pruebas de dominio y WASM para Worker, formato,
   Clippy y validación de dependencias; compilación/typecheck de la interfaz.
2. Matriz de rutas sin pendientes, contratos equivalentes y pruebas negativas
   de autorización, revocación, límites y firmas.
3. Pruebas de persistencia, reconexión, duplicados, carreras de recuperación,
   cuotas compartidas entre HTTP/WSS y fallo antes/después del commit.
4. Flujos reales locales: owner/admin/cliente, varios navegadores, mensajes,
   offline, adjuntos múltiples, límites, fondos compartidos, móvil, gestos y PWA.
5. Rendimiento comparable: aislado, ráfaga de 20/30, varias cuentas simultáneas,
   1.000 mensajes y uso sostenido a 10 mensajes/s. Reportar p50/p95/p99,
   pérdidas, duplicados y fases con condiciones iguales a la referencia.
6. Publicar código, lockfiles, comandos reproducibles y resultados reales en
   Ratchet-Rust. No presentar scaffolding o endpoints incompletos como migración.
7. Despliegue posterior a staging propio con D1/R2/DO y secretos propios;
   comprobar permisos, transporte y entrega desde clientes reales.

## Fuentes

- https://developers.cloudflare.com/workers/languages/rust/
- https://crates.io/api/v1/crates/worker
- https://crates.io/api/v1/crates/worker/0.8.7/dependencies
- https://crates.io/api/v1/crates/worker-build
- https://registry.npmjs.org/wrangler/latest
- https://static.rust-lang.org/dist/channel-rust-stable.toml
