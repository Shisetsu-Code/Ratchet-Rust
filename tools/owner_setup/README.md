# Consola local Ratchet Rust

Interfaz de owner/administración conservada durante la migración. Su integración
completa con el servidor Rust sigue pendiente: todavía no usar para operar un
despliegue real. El origen predeterminado es `http://localhost:8797`; puede
cambiarse con `RATCHET_RUST_ORIGIN`.

La consola Rust no carga tokens, contraseñas ni llaves del staging SQLite o de
Ratchet Beta. El token de instalación se ingresa manualmente o mediante la
variable local `RATCHET_RUST_BOOTSTRAP_TOKEN`. El archivo `.ratchet-key` se
selecciona explícitamente y su contraseña se introduce en la consola.

Requiere Python con Tk y la dependencia fijada en `requirements.txt`. No se
instalan herramientas automáticamente. Una vez validada la integración local:

```powershell
& .\tools\owner_setup\abrir_rust_admin.ps1 -Owner
& .\tools\owner_setup\abrir_rust_admin.ps1
& .\tools\owner_setup\abrir_rust_admin.ps1 -Console
```

Los modos corresponden a crear owner, crear ADMIN y operar la consola exclusiva
del owner. Las operaciones de consola firman desafíos con el archivo de llave;
la llave privada y su contraseña permanecen en el equipo.

## Contraseñas independientes y llaves anteriores

Las altas de owner y ADMIN, y la recuperación de ADMIN, piden dos contraseñas:
la de la cuenta, enviada al servidor para el ingreso con contraseña, y una
contraseña local distinta para cifrar el archivo `.ratchet-key`. La contraseña
local debe tener de 15 a 256 caracteres y no se envía en ninguna solicitud.

La opción **Cambiar contraseña local de una llave…** de la ventana owner
descifra una llave existente y guarda una copia nueva con otra contraseña.
Conserva su identificador y clave de firma, verifica la copia nueva y mantiene
intacto el archivo anterior. La publicación del archivo no sobrescribe un
archivo existente, aunque aparezca después de seleccionarlo.

Las llaves anteriores siguen siendo compatibles con el importador. Volver a
cifrarlas sólo protege copias futuras: una copia antigua y su contraseña aún
permiten usar la clave anterior. Si hubo exposición, corresponde registrar una
clave nueva y revocar la anterior en el servidor, conservando primero una vía
de recuperación del owner. La recuperación de un ADMIN ya realiza esa rotación
y revoca sus sesiones; el cambio local de contraseña no hace esa operación.

Prueba local de cifrado, separación de secretos y conservación de archivos:

```sh
python -m unittest discover -s tools/owner_setup -p 'test_*.py'
```
