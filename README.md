# Ratchet Rust

Comparación real emparejada del prototipo SQLite y Rust: [Cloudflare 2026-10-16](docs/PAIRED_CLOUDFLARE_2026-10-16.md). Con la misma carga sostenida a 8/s: medias de 189 y 194 ms hasta el receptor; sin cambios de aplicación ni interfaces incluidas.

Staging vigente: `6d3e6254-0f47-43ef-acac-57c38b4b02c4`. Medición real de Cloudflare y recuperación automática de mensajes tras agotar reintentos: [resultados y límites de la prueba](docs/REMOTE_PERFORMANCE_2026-10-15.md). Esta sección es posterior a los despliegues históricos descritos más abajo.

Ensayo posterior de cuotas paralelas: **sin ganancia consistente; se conserva el runtime actual**. Se recuperaron 34.000 mensajes y pasaron 35 contratos. El candidato queda como parche reproducible, sin desplegar. [Resultados y decisión](docs/QUOTA_PARALLEL_EXPERIMENT_2026-10-15.md).

Desglose medido por etapas: con 32 mensajes en vuelo, las esperas de cuotas dominan el handler; con un solo envío, el ACK de las muestras baja de 186,5 a 11,4 ms. Se midieron 13.000 mensajes sin pérdidas; el diagnóstico es local, muestreado y desactivado por defecto. [Datos, desglose y límites](docs/LATENCY_BREAKDOWN_2026-10-15.md). No se cambió ni desplegó una optimización adicional.

Recuperadas la caché de permisos, la preparación concurrente y los lotes de hasta 16. El benchmark local repetido redujo los tiempos Rust entre 11,3% y 65,8% frente al port anterior: 1.000 mensajes en un chat, 12,50 → 5,95 s; 2.000, 46,68 → 15,97 s. Ahora queda cerca de TypeScript, sin ventaja general demostrada. Tres rondas pareadas, 24 casos, 30.000 mensajes recuperados sin pérdidas ni duplicados. Ver [comparación posterior y datos](docs/BENCHMARK_RUST_OPTIMIZED_2026-10-15.md) y [benchmark histórico](docs/BENCHMARK_TYPESCRIPT_RUST_2026-10-15.md).

Backend de Ratchet en Rust/WASM para Cloudflare Workers, con interfaz React y API desde el mismo origen. La migración implementa las 74 rutas activas de Ratchet-SQLite y está desplegada en un staging nuevo e independiente. No utiliza un backend TypeScript de respaldo.

72 rutas tienen handlers operativos y las dos rutas de inscripción de passkeys conservan el HTTP 410 `ACCESS_PASSKEY_ENROLLMENT_DISABLED` intencional de la referencia. El login y reauth con passkeys existentes están implementados. La matriz de las 74 rutas tiene evidencia local y referencias a código y pruebas.

## Funcionalidad

- Contraseña PBKDF2, llaves portables firmadas y passkeys ES256/RS256/Ed25519; bootstrap, activación, sesiones, dispositivos, certificados y prekeys.
- Administradores independientes, agentes mediante enlaces de uso único, invitaciones, invitados y clientes. Consola owner con operaciones firmadas y recuperación conservando historial.
- Chat HTTP/WSS en Durable Objects SQLite, almacenamiento AES-GCM/HKDF/HMAC, cola FIFO, ACK posterior a durabilidad, deduplicación, secuencias, sync paginado, recibos, batch y estadísticas proyectadas.
- Revocación recuperable que cerca los chats afectados, confirma la mutación con su marcador D1 y revalida conexiones. Reintentos de control y proyección sobreviven a reinicios del objeto.
- Adjuntos multipart R2, validación de tamaño/ETag, claims y compensación; fondos compartidos por cuenta; Web Push y mantenimiento programado.

La instalación empieza vacía con `db/migrations/0001_ratchet_rust.sql`. No importa cuentas, secretos ni historial de otros despliegues. `baseline/source-manifest.json` conserva la procedencia y `baseline/routes.json` documenta implementación y evidencia.

## Modelo de cifrado

Los mensajes viajan por HTTPS/WSS y el servidor puede leer su contenido, igual que en el prototipo de referencia actual. El almacenamiento del servidor usa AES-GCM; la caché y la cola local del navegador permanecen cifradas. **Los mensajes no se presentan como cifrado de extremo a extremo.** Los adjuntos y fondos sí se cifran en el cliente. El transporte explícito está en `src/client/crypto/server-message-transport.ts`.

## Validación

Última regresión tras recuperar optimizaciones: **52 pruebas Rust, 3 criptográficas, 5 de herramientas y 34 contratos integrados aprobados**, más formato, Clippy nativo/WASM y tipos del cliente. Incluye navegador, adjuntos, fondo compartido, ráfagas, recuperación, revocación y consola; los tres contratos nuevos cubren errores dentro de ráfagas, duplicados concurrentes y orden entre recibos y mensajes. Los resultados anteriores se conservan abajo como historial.

Staging actualizado y verificado: versión `b25a5c76-95aa-4918-8299-6fe9e3a49dda`, código `5ff18e3`. Pasaron nuevamente navegador escritorio/móvil, archivos, fondo y reconexión; 30 mensajes WSS remotos llegaron en 327 ms de lote completo (media 279 ms, p95 305 ms), con recuperación HTTPS y revocación correctas. [Evidencia vigente](docs/performance-validation-results.json).

La regresión integrada final pasó **31/31 contratos** en 81,208 s, incluidos navegador real, owner, identidad, administración, archivos, metadatos y carga. Pasaron también las suites Rust de workspace, tres pruebas criptográficas, cinco pruebas de herramientas, tipos/build del cliente y auditoría npm sin vulnerabilidades. El lote de 1.000 mensajes desde 20 cuentas terminó en 16,033 s y se recuperó en cinco páginas sin pérdida ni duplicación.

En Cloudflare pasó el recorrido completo de Chrome de escritorio/móvil: login, invitación y cliente, mensajes, gestos táctiles, teclado móvil, tres archivos descargados con SHA-256 idéntico, fondo de 400 KB renderizado con píxeles idénticos, recarga y offline/reconexión. Pasaron además la ráfaga WSS remota de 30 en orden, sync HTTPS exacto, reconexión, logout con cierre 4001 sin desconectar al cliente restante y consola Python con llave cifrada. La configuración push remota devuelve enabled=true.

Una ejecución de carga anterior se detuvo en 100 de 1.000 mensajes; no se atribuye una causa sin evidencia. El caso focalizado y la regresión integrada posterior pasaron. [VALIDATION.md](docs/VALIDATION.md) registra la muestra, las métricas y su alcance.

## Comandos reproducibles

Versiones fijadas: Rust 1.99.0, worker/worker-build 0.8.7, Wrangler 4.151.0, React 19.3.1 y Vite 8.3.4. Se utilizan las herramientas y dependencias ya disponibles; estos scripts no instalan paquetes.

```powershell
npm run verify
```

`verify` comprueba toolchain, formato, Clippy nativo/WASM, pruebas Rust/crypto/herramientas, tipos del cliente, empaquetado y todos los contratos locales. Usa D1/R2/DO efímeros y secretos sintéticos; restaura `.dev.vars`. El navegador requiere Chrome y la consola usa Python ya preparado.

```powershell
npm run build
npm run deploy:staging
npm run test:staging
```

`deploy:staging` valida el nombre de los recursos aislados, prepara secretos locales ignorados, hace dry-run, aplica el esquema nuevo y despliega. `test:staging` utiliza el staging dedicado, provisión firmada, navegador real, transporte remoto y consola nativa. La llave cifrada y las credenciales sintéticas quedan en archivos locales ignorados, nunca en Git.

## Staging y documentación

[ratchet-rust-staging-20261015.braian-n-l.workers.dev](https://ratchet-rust-staging-20261015.braian-n-l.workers.dev) utiliza Worker, D1, R2 y Durable Objects nuevos, aislados de Ratchet-SQLite mediante `wrangler.staging.jsonc`.

- [Validación y métricas](docs/VALIDATION.md)
- [Diseño](docs/superpowers/specs/2026-10-15-ratchet-rust-design.md)
- [Plan](docs/superpowers/plans/2026-10-15-ratchet-rust.md)
- [Historial de decisiones](docs/MIGRATION_PROGRESS.md)

Código y resultados publicados en `main` de `Shisetsu-Code/Ratchet-Rust`: commit de implementación `72a4070`. El staging utiliza el artefacto probado; los datos de aceptación están en `docs/validation-results.json`.

Cierre final: 35 pruebas Rust + 3 criptográficas + 5 de herramientas + 31 contratos integrados aprobados. Staging verificado y matriz completa; métricas y SHA-256 del artefacto en [validation-results.json](docs/validation-results.json).
