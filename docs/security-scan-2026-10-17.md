# Correcciones del scan del 17 de octubre de 2026

Repositorio: `Shisetsu-Code/Ratchet-Rust`.

Scan de referencia: `wfr_a0fefc04bff24587210a762d63c9f9fc8fc194ab83383037e58d7bc7119acec9`.

Código analizado y respaldado: `824b3dfb1e412a165711a84d2167e5c9e1e26976`.

## Respaldo y alcance

La rama `backup/security-2026-10-17-824b3df` conserva el commit original. También se generó `Ratchet-Rust-backup-2026-10-17.bundle`, con el historial completo y verificación mediante `git bundle verify`.

El respaldo Git cubre el código y su historial. Las migraciones incluidas en esta rama requieren el procedimiento de actualización y respaldo de datos documentado en [operación de almacenamiento](security-storage-operations.md). La preparación del cambio y las pruebas usan bases, objetos y sesiones locales desechables.

Para recuperar una copia independiente del código original:

```sh
git bundle verify /ruta/Ratchet-Rust-backup-2026-10-17.bundle
git clone /ruta/Ratchet-Rust-backup-2026-10-17.bundle Ratchet-Rust-restaurado
git -C Ratchet-Rust-restaurado switch --detach 824b3dfb1e412a165711a84d2167e5c9e1e26976
```

## Cobertura de los hallazgos

| ID del hallazgo | Corrección | Regresiones principales |
| --- | --- | --- |
| `csf_0697c80ef3a91e7adfe94440` | Cuotas de frames y bytes antes de parsear, deserialización tipada única y cierre de mensajes inválidos. | `realtime-resources.mjs`, `realtime-limits.test.mjs`, prueba Rust de tipos de frame. |
| `csf_1a3d419509cab6992676d9f1` | Conexiones simultáneas acotadas y presencia emitida cuando cambia el conjunto de usuarios. | `realtime-resources.mjs`, contratos existentes de mensajes y carga. |
| `csf_f43645f3fedb185b46502990` | Admisión atómica y limpieza de challenges y consumos; límites separados para login y reautenticación. | `auth-admission.test.mjs`, `auth-hardening.mjs`. |
| `csf_907028dde45af32c239e5e27` | Contraseña local independiente para archivos de llaves, incluida recuperación; recifrado local compatible. | `tools/owner_setup/test_key_separation.py`, `owner.mjs`. |
| `csf_c372015bfcae4f4ed9cc54ab` | Un endpoint reemplazable por dispositivo, cuotas, cola persistente acotada y reintentos con selección justa. | `storage-quotas.test.mjs`, `storage-hardening.mjs`, `push-leases.test.mjs`, pruebas Rust del planificador y plazo de push. |
| `csf_0bb43b602a87ac1d07329f35` | Proyección cifrada del historial, consultas y descifrado acotados, paginación y ventana limitada de mensajes. | `client-resources.test.mjs`, `message-window.test.mjs`, contratos de navegador. |
| `csf_4b8de7ae331d683266528ab0` | Los adjuntos confirmados y pendientes de borrado siguen consumiendo cuota; las partes respetan la reserva. | `storage-quotas.test.mjs`, `storage-hardening.mjs`, pruebas Rust de adjuntos. |
| `csf_6edf6fca4c307a2f489c142e` | Los reportes usan plantillas de rutas permitidas y salida agregada predeterminada. | `summarize-remote-tail.test.mjs`. |
| `csf_ad49836a29b0c3ce21e08013` | Descarga de adjuntos a pedido, límites compartidos de concurrencia y memoria, cancelación y límites de imagen. | `client-resources.test.mjs`, `attachment-budget.test.mjs`. |
| `csf_ea36898c111d5940425c885a` | Separación entre admisión y fallos reales; el bloqueo anterior deja de impedir el acceso de toda la cuenta. | `auth-hardening.mjs`, `auth-admission.test.mjs`. |
| `csf_10fffde000c57251fa9f8eee` | Recibos de hasta 32 KiB, campos estrictos, fingerprint canónico y caché de respuestas con TTL y cuotas. | `storage-hardening.mjs`, `realtime-resources.mjs`, `chat-storage-quota.test.mjs`. |
| `csf_6de17ac4f032252dd73fba11` | Cuotas acumulativas de fondos y limpieza que excluye filas ya terminadas, con recuperación de multipart. | `storage-quotas.test.mjs`, `storage-hardening.mjs`, contratos de archivos. |
| `csf_5e3ae1a9e5b9dc2eb8052faf` | Presupuesto persistente por sala y créditos globales, controlados dentro de la transacción de escritura. | `chat-storage-quota.test.mjs`, `storage-quotas.test.mjs`, contratos de carga y orden. |
| `csf_f5e215746be55710a59406f6` | Mismo presupuesto PBKDF2 para nombres existentes, desconocidos y credenciales antiguas admitidas. | `password_contract.rs`, `auth-hardening.mjs`. |
| `csf_21d876c49f6822d24aabefeb` | La presencia filtra destinatarios autorizados y cierra sockets con sesión vencida. | `realtime-resources.mjs`, `authority-refresh.mjs`, contratos de revocación. |

Los IDs corresponden al scan del commit original. Esta tabla documenta el cambio y su verificación; no modifica el estado del scan ni equivale a un nuevo análisis de seguridad de la rama.

## Límites de tiempo real

Cada sala admite hasta cuatro conexiones por dispositivo, ocho por usuario y 256 en total. Los conteos se reconstruyen desde los sockets y sus autorizaciones persistidas, incluidos los recuperados tras hibernación. Una pestaña adicional de un usuario ya conectado recibe su propia instantánea de presencia sin provocar otro broadcast general.

Durante una revocación, los sockets pendientes de revalidación siguen contando para los límites y la presencia queda pausada. Una autorización temporalmente ausente durante esa actualización no se interpreta como una sesión vencida. Al completar la revalidación durable, los destinatarios autorizados reciben una instantánea nueva; las sesiones vencidas o revocadas se cierran.

Los presupuestos de aplicación se comparten entre sockets y reconexiones dentro de una sala:

| Alcance | Frames por ventana de 10 segundos | Bytes por ventana |
| --- | ---: | ---: |
| Dispositivo | 240 | 8 MiB |
| Usuario | 480 | 16 MiB |
| Sala | 4.096 | 128 MiB |

La admisión de los tres alcances es una única escritura SQLite: una denegación no consume parcialmente otro presupuesto. Los contadores tienen vencimiento indexado y un límite de 1.024 filas. La comprobación se hace antes de interpretar JSON, incluidos pings, frames binarios o mensajes malformados. Los límites de apertura y envío existentes siguen aplicándose.

La cola de envío conserva la reserva FIFO antes de las esperas de autorización. El presupuesto de almacenamiento se solicita para todo el lote preparado antes de escribir, y se vuelve a comprobar la autorización antes del commit. La publicación y el ACK conservan la barrera de persistencia durable.

## Compatibilidad y operación

- [Admisión de autenticación](authentication-admission.md): límites, costo de contraseñas, desafío de trabajo y compatibilidad de llaves existentes.
- [Almacenamiento y recuperación](security-storage-operations.md): migraciones, cuotas, conciliación de salas antiguas, multipart, recibos y push.
- [Herramientas del owner](../tools/owner_setup/README.md): separación de contraseñas y recifrado local de archivos existentes.

Las cuotas de almacenamiento detienen el crecimiento al alcanzar el límite; no borran automáticamente mensajes ni adjuntos confirmados. El estado `READ` sigue siendo monotónico. Los recibos antiguos conservan su respuesta de replay; los nuevos tienen una ventana documentada de 30 días. El historial del navegador conserva un cursor de recepción independiente del cursor de proyección y navegación.

## Verificación reproducible

```sh
npm ci
npm run verify
python -m unittest discover -s tools/owner_setup -p 'test_*.py' -v
```

`npm run verify` ejecuta formato, Clippy nativo y Wasm, pruebas Rust, pruebas de herramientas y navegador, TypeScript, los builds y los contratos completos con recursos locales desechables. Las once regresiones iniciales de tiempo real y almacenamiento se ejecutaron contra el commit original y fallaron por los comportamientos reportados; posteriormente se comprobaron contra el Worker corregido. Se agregaron además pruebas del límite físico de partes multipart y de actualización de datos existentes.

### Resultado local del 17 de octubre de 2026

La ejecución completa de `npm run verify` terminó con código de salida cero y 205 pruebas aprobadas:

| Grupo | Pruebas aprobadas |
| --- | ---: |
| Workspace Rust | 64 |
| Módulo criptográfico del navegador | 3 |
| Herramientas Python del owner | 6 |
| Herramientas, SQLite y recursos del cliente, incluido Chrome | 70 |
| Reportes y medición del backend | 8 |
| Contratos completos contra el Worker local | 54 |

También pasaron `cargo fmt`, Clippy nativo y Wasm con advertencias tratadas como errores, TypeScript y las compilaciones del cliente, el módulo criptográfico y el Worker. Los contratos ejercitan navegadores de escritorio y móvil, subida y descarga de tres adjuntos con SHA-256 idéntico, fondos y recarga, colas sin conexión, revocación con lectores pasivos y recuperación exacta de 1.000 mensajes de 20 cuentas. Esta verificación usa servicios locales desechables y no ejecuta un despliegue.

La revisión independiente final señaló dos casos adicionales que se reprodujeron antes de corregirlos: una sala llena no podía recuperar espacio de recibos vencidos antes de solicitar más capacidad, y las tandas posteriores de push reutilizaban la hora inicial del lote para sus reservas. La limpieza ahora precede a la admisión de crecimiento; cada envío push obtiene su propio plazo desde la reclamación y limita conjuntamente preparación y transporte. Las nuevas regresiones y la ejecución completa anterior incluyen ambas correcciones.
