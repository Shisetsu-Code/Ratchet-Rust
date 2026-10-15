# Medición real y recuperación de pendientes — 2026-10-15

Destino exclusivo: `ratchet-rust-staging-20261015.braian-n-l.workers.dev`.
Referencia inicial: despliegue `b25a5c76-95aa-4918-8299-6fe9e3a49dda`.

## Resultados anteriores a la corrección

| Prueba real | Entrega media al receptor | p95 | Resultado |
|---|---:|---:|---|
| Ráfaga de 30, pasada 1 | 423 ms | 439 ms | 30/30 |
| Ráfaga de 30, pasada 2 | 441 ms | 472 ms | 30/30 |
| Ráfaga de 30, pasada 3 | 419 ms | 450 ms | 30/30 |
| Ráfaga de 30, pasada 4 | 555 ms | 603 ms | 30/30 |
| 30 a 10/s | 312 ms | 420 ms | 30/30 |
| 300 a 8/s | 314 ms | 442 ms | 300/300, sin NACK |
| 300 a 10/s, recuperación serial del comprobador | 10.840 ms | 36.155 ms | 300/300 tras reintentar |

La última fila **no es latencia normal del servidor**: dos NACK por cuota generaron
117 NACK de secuencia; el comprobador recuperó los pendientes uno a uno, con un RTT
por mensaje. Incluye esa recuperación artificialmente serial. Una ejecución previa
sin recuperación falló con 122 NACK; tampoco se excluye del diagnóstico.

Una apertura WSS devolvió 503 durante pruebas solapadas. La telemetría confirma el
503; no contiene su código de dominio, por lo que no se atribuye definitivamente a
una causa. Las aperturas posteriores aisladas pasaron. No se oculta como éxito.

El ping WSS observado fue aproximadamente 141–146 ms. Puede responder desde el
borde y **no localiza el Durable Object**. `/cdn-cgi/trace` indicó `colo=GIG`,
`loc=AR`, HTTP/2 y TLS 1.3; no se guardaron IP. No corresponde restar ese ping
de la entrega para afirmar cuánto consume exclusivamente el servidor.

## Navegador y límites de medición

Tres recorridos completos de escritorio/móvil pasaron antes de la corrección:
login, invitación, conversión de invitado, entrega bidireccional, gestos, viewport
con teclado, tres adjuntos con SHA-256 idéntico, fondo de 400 KB compartido y
persistente, cola offline, recarga y reconexión. La consola nativa y la revocación
WSS con cierre 4001 también pasaron.

La medición visual inicial con `expect` dio aproximadamente 350–869 ms por el
sondeo del comprobador. Se sustituyó por MutationObserver y dos animation frames:
diez muestras dieron 343–775 ms, mayoría alrededor de 359 ms. Incluyen el control
de Playwright y no son una medición aislada del pintado o la red.

Las muestras de CPU/duración de Wrangler son por invocación y están muestreadas;
mezclan mensajes, recibos, conexiones y otras operaciones. No equivalen a una
descomposición exacta por mensaje. El diagnóstico local `sample10` se mantiene
desactivado en staging: [los relojes de Workers tienen restricciones](https://developers.cloudflare.com/workers/runtime-apis/performance/).

## Corrección acotada

El cliente ya reintentaba HTTP seis veces. Si se agotaban con error transitorio,
el pendiente dependía de reconexión/cambio de chat para un nuevo intento.
Se añade recuperación automática sólo cuando queda trabajo pendiente: espera
2/4/8/16/30 segundos, máximo 30 entre pasadas, sin ejecuciones solapadas del
programador y cancelación al salir del chat. Se reutiliza el outbox e identidad
existentes. No se cambian cuotas, permisos, cifrado ni durabilidad del servidor.
La cancelación detiene futuras pasadas; una entrega durable ya iniciada termina.

La regresión real inyecta un NACK WSS y seis respuestas HTTP 429. La versión
anterior agotó sus reintentos y no entregó el mensaje durante la espera adicional
de 15 segundos. Las pruebas de exploración iniciales ajustaron la ruta WSS con
query y demostraron que un único 429 sí era recuperado por los reintentos cortos;
no se cuentan como prueba de este defecto.

## Verificación de la corrección

Staging actualizado a `6d3e6254-0f47-43ef-acac-57c38b4b02c4`, cliente
`index-XXMFqWCk.js`. WASM SHA-256:
`f2fab22521d85be0cc9d7c1ae0c7d74a3c4bd59bbc9dcf4cd6e12c26d7e15c5d`.
El diagnóstico sigue apagado; no hay cambios de lógica Rust en esta iteración.

- La misma regresión NACK + seis 429 pasó: entrega automática, mismo ID, sin
  recarga y una sola aparición en el receptor.
- El recorrido completo posterior pasó en 106,3 segundos: móvil/escritorio,
  adjuntos, fondo compartido, gestos, offline y reconexión. Diez muestras visibles
  posteriores: 342–559 ms; no demuestran un cambio de latencia normal por sí solas.
- Ráfaga posterior: 30/30, media 509 ms, p95 558 ms; sync HTTPS exacto, revocación
  4001 y consola owner correctos. Se conserva la variación frente a pasadas previas.
- Control sostenido posterior: 300/300 a 8/s, sin NACK, media 307 ms y p95 375 ms;
  recuperación paginada HTTPS, reconexión, revocación y consola correctas. La mejora
  numérica frente a la pasada anterior no basta para afirmar una ganancia estable.
- Once pruebas de herramientas/parser aprobadas, incluidas cuatro del programador
  de recuperación; typecheck y build cliente correctos. El build conserva el aviso
  de bundle de 625 KB. No se instalaron ni actualizaron dependencias.

Telemetría agregada sin cabeceras ni credenciales:
[remote-tail-summary-2026-10-15.json](remote-tail-summary-2026-10-15.json).
Reproducción: `RATCHET_RETRY_PROBE=1` al ejecutar `scripts/verify-staging.mjs`.
Para transporte sostenido: `RATCHET_TRANSPORT_PROFILE=paced`,
`RATCHET_TRANSPORT_COUNT=300`, `RATCHET_TRANSPORT_SPACING_MS=125`, ejecutando
`scripts/staging-transport.mjs`. No solapar scripts que revocan sesiones de la
misma cuenta de prueba.

Resultados crudos: `experiments/backend-benchmark/remote-results/`. Las credenciales,
llaves, capturas y logs completos permanecen ignorados. Los tiempos no demuestran
una ventaja global de Rust frente a TypeScript. Esta prueba de decenas de segundos
no sustituye una prueba de resistencia de horas ni un perfil de memoria prolongado.
