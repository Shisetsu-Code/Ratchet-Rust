# Ratchet · Consola local de cuentas

Esta aplicación local crea el primer owner y las cuentas ADMIN adicionales con sus archivos `.ratchet-key`. El token de instalación y las claves privadas no se colocan en una URL ni en la aplicación web.

La consola exclusiva del owner también permite recuperar cuentas CUSTOMER/ADMIN y consultar conversaciones del workspace con historial paginado. Para abrirla en el staging SQLite existente:

```powershell
& ".\tools\owner_setup\abrir_sqlite_admin.ps1" -Console
```

Este acceso usa el Python ya disponible y el origen del manifiesto local de SQLite. No necesita el token de instalación ni lee la contraseña guardada del owner. Elegí su `.ratchet-key` e ingresá su contraseña para cada operación. También se accede desde el botón de consola en las pantallas de alta, o con `ratchet_owner_setup.py --console` y el origen correspondiente.

En **Recuperar cuenta**, listá las cuentas, seleccioná el usuario y confirmá su ID/rol antes de establecer una contraseña nueva. El usuario de ingreso, la identidad y el historial se conservan. Las credenciales anteriores y las sesiones/dispositivos se revocan. Para ADMIN, elegí además un archivo nuevo donde guardar la llave cifrada: no se sobrescriben archivos. Su nueva contraseña también protege ese archivo. Si la red falla, conservá la llave generada y comprobá el estado antes de reintentar. La recuperación del propio owner no está incluida.

En **Consultar conversaciones**, seleccioná una conversación y usá **Leer seleccionada** y **Más historial**. Cada página reemplaza la anterior y muestra hasta 20 eventos. Las ediciones y eliminaciones se presentan como eventos identificados. Los adjuntos se indican, pero esta consola no descarga ni descifra sus archivos. El texto sólo se mantiene en memoria y no se guarda como registro ni exportación.

Cada solicitud verifica el origen, la llave, el propósito, el vencimiento y el hash de la operación antes de firmar el desafío. Se transmite únicamente la firma, junto con los datos públicos y la operación solicitada; la recuperación envía la contraseña nueva por HTTPS. La llave privada y su contraseña de desbloqueo nunca se envían. El servidor valida el rol OWNER vigente y el uso único del desafío. La autorización de supervisión no agrega al owner como participante de las conversaciones.

## Uso en Windows

1. Instalá Python 3.9 o posterior si todavía no está instalado.
2. Abrí PowerShell dentro de esta carpeta e instalá la única dependencia: `py -3 -m pip install -r requirements.txt`
3. Para crear un administrador, ejecutá `abrir_ratchet_admin.cmd`. Abre directamente **Crear cuenta ADMIN**, sin pasar por la pantalla del owner.
4. Usá `abrir_ratchet_owner.cmd` únicamente para crear el owner inicial.
5. En la consola ADMIN, elegí la llave del owner y completá las credenciales del nuevo administrador.
6. Entrá a Ratchet desde la pantalla normal e importá el archivo de la cuenta correspondiente. El primer navegador se habilita automáticamente.

Sólo el owner original puede crear cuentas ADMIN desde esta consola. Los ADMIN crean únicamente cuentas CUSTOMER desde el panel de Ratchet. No existe registro público de administradores ni de clientes.

La herramienta intenta leer `RATCHET_BETA_BOOTSTRAP_TOKEN` de las variables del usuario de Windows. Si no existe, se puede pegar el token directamente en la interfaz; nunca se escribe en el archivo de llave.

Desde PowerShell, la consola ADMIN se abre con:

```powershell
& ".\tools\owner_setup\abrir_ratchet_admin.cmd"
```
