# Consola local Ratchet Rust

Interfaz de owner/administración conservada durante la migración. Su integración
completa con el servidor Rust sigue pendiente: todavía no usar para operar un
despliegue real. El origen predeterminado es `http://localhost:8787`.

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
