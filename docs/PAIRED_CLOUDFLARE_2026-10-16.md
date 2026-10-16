# Prototipo SQLite frente a Rust en Cloudflare — 2026-10-16

Comparación real desde el mismo proceso Node y conexión de salida. Reloj
monotónico único, desde `socket.send` hasta el callback WSS del receptor. No se
comparan directamente estas cifras con tiempos de pintado de las interfaces.

## Método

- Prototipo: copia exacta de `../sqlite-chat-poc/{worker.mjs,core.mjs,client.html}`.
  El despliegue antiguo había vencido; se creó un laboratorio temporal autenticado,
  con claves nuevas y vencimiento de cuatro horas. SHA-256 en los JSON de evidencia.
- Rust: staging `ratchet-rust-staging-20261015`, versión
  `6d3e6254-0f47-43ef-acac-57c38b4b02c4`. No se modificó ni desplegó Ratchet.
- Tres pares por carga, orden prototipo/Rust, Rust/prototipo, prototipo/Rust.
  Una conexión abierta por participante y calentamiento excluido de cada resumen.
- Texto de exactamente 256 bytes en ambos. El protocolo Rust incluye metadatos y
  envelopes: aproximadamente 1.188 bytes por frame frente a 334 del prototipo.
  No es una comparación de lenguajes con programas ni frames idénticos.
- Casos: diez mensajes individuales esperando entrega y ACK antes del siguiente,
  ráfaga de ocho, y treinta mensajes con intervalo objetivo de 125 ms (8/s).
  El prototipo original admite diez mensajes por segundo, por lo que una ráfaga
  simultánea de treinta introduciría rechazos y no sería una comparación limpia.
- Se comprueban contenido, orden, unicidad, ausencia de NACK y recuperación completa
  en un nuevo WSS del prototipo y mediante sync HTTPS de Rust.

Una prueba exploratoria inicial utilizó IDs con sufijo, incompatibles con la
validación UUID de Rust. Falló durante el calentamiento y no integra los tiempos.
La primera pasada válida recuperó 56 mensajes del prototipo (incluye uno de esa
exploración) y 55 de Rust; midió 108 mensajes y se conserva íntegra. Después se
reinició únicamente la sala del laboratorio para una pasada limpia que también
incluye carga sostenida. No se descartaron resultados lentos de pasadas válidas.

Esa pasada completó las 18 cargas sin pérdidas ni NACK, pero su comprobación final
falló al leer sólo la primera página de 100 mensajes frente a 145 esperados en
Rust. Sus agregados se conservan en `pagination-checker-failure.json` y no se
presentan como verificación íntegra. Se corrigió el cursor y se repitió. La pasada
final reutilizó la sala del prototipo con esos 145 registros previos; Rust abrió
un chat nuevo. Es una limitación del control de historial, no se oculta como salas
idénticas. Finalmente se recuperaron 290 registros del prototipo y 145 de Rust.

## Resultados finales

| Carga | Muestras por versión | Prototipo: media / p95 | Rust: media / p95 |
|---|---:|---:|---:|
| Individual, siguiente tras entrega y ACK | 30 | 183 / 226 ms | 198 / 238 ms |
| Ráfaga simultánea de ocho | 24 | 289 / 539 ms | 239 / 247 ms |
| Sostenido a objetivo 8/s | 90 | 189 / 260 ms | 194 / 250 ms |

Son latencias **por mensaje** hasta el receptor. Los resúmenes completos incluyen
el ACK durable y todos los valores lentos. Las 288 entregas medidas de la pasada
final mantuvieron contenido y orden exactos, sin duplicados ni rechazos.

La pasada anterior válida con dos cargas dio individual 204 ms prototipo frente
a 187 ms Rust y ráfaga 268 frente a 275 ms. Se invierte el orden entre pasadas:
no hay evidencia de una penalización grande y constante del backend Rust.
En carga sostenida, los 194 ms actuales tampoco respaldan que 307 ms sea un coste
fijo del programa; no hubo cambios de aplicación entre ambas mediciones.

Laboratorio: versiones temporales `852909a4-3410-4dbb-8511-1fcbf684ce6f` y
`a9b375d8-5d9e-44b7-bbd7-a5b99bd2274c`, mismo código y sala rotada entre ambas.
El laboratorio temporal fue eliminado al terminar. El staging Rust quedó intacto.

## Interpretación

Los resultados no prueban que los 307 ms de otra fecha sean una regresión del port.
Son necesarios el mismo origen, carga y punto de medida; la interfaz y los cambios
de recorrido/ubicación de Cloudflare siguen siendo factores separados. Tampoco se
identifica la ubicación del Durable Object mediante el colo del punto de entrada.

Los `timing` del prototipo se conservan en cada ACK. Son tiempos de reloj de Workers
con sus restricciones, no un perfil preciso de CPU, y Rust no expone esos mismos
campos en su protocolo público. No se inventa una resta que convierta todo el
tiempo restante en «latencia WSS».

Evidencia completa: `experiments/backend-benchmark/paired-remote-results/`.
Reproducción en este workspace: preparar la copia con
`prepare-remote-prototype.mjs`, desplegar su configuración/secrets ignorados con
el Wrangler instalado y ejecutar `compare-remote-prototype.mjs` desde la raíz de
Ratchet-Rust. La preparación rechaza sobrescribir un laboratorio local existente.
