"""Ratchet owner-controlled administrator provisioning GUI.

Creates the first owner or additional administrators and their encrypted
.ratchet-key files without exposing private signing keys to the web app.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import ssl
import sys
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, simpledialog, ttk
except ImportError as exc:  # pragma: no cover - depends on the Python distribution
    raise SystemExit("Esta instalación de Python no incluye Tkinter.") from exc

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror(
        "Falta un componente",
        "Instalá la dependencia con:\n\npython -m pip install -r requirements.txt",
    )
    root.destroy()
    raise SystemExit(2)


DEFAULT_URL = os.environ.get("RATCHET_RUST_ORIGIN", "http://localhost:8797")
KDF_ITERATIONS = 600_000
MAX_RESPONSE_BYTES = 65_536
MAX_KEY_FILE_BYTES = 65_536


class SetupError(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decode_b64url(value: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]*", value):
        raise SetupError("El archivo de llave contiene datos inválidos.")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise SetupError("El archivo de llave contiene datos inválidos.") from exc


def compact_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def normalize_origin(raw: str) -> str:
    parsed = urllib.parse.urlsplit(raw.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SetupError("La dirección del servidor no es válida.")
    if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise SetupError("El servidor debe usar HTTPS.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise SetupError("Usá solamente la dirección base del servidor.")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", "")).rstrip("/")


def key_filename(login_name: str, fallback: str) -> str:
    """Return a filesystem-safe key filename matching a valid Ratchet login."""
    login = login_name.strip()
    stem = login if re.fullmatch(r"[A-Za-z0-9._-]{3,64}", login) else fallback
    return f"{stem}.ratchet-key"


def read_saved_token() -> str:
    """Rust installation only: never import credentials from another deployment."""
    return os.environ.get("RATCHET_RUST_BOOTSTRAP_TOKEN", "").strip()


def validate_key_password(account_password: str, key_password: str | None) -> str:
    if not isinstance(key_password, str) or not 15 <= len(key_password) <= 256:
        raise SetupError("La contraseña local de la llave debe tener entre 15 y 256 caracteres.")
    if secrets.compare_digest(account_password.encode('utf-8'), key_password.encode('utf-8')):
        raise SetupError("Usá una contraseña local de llave diferente de la contraseña de la cuenta.")
    return key_password


def create_key_document(password: str) -> tuple[dict[str, object], Ed25519PrivateKey]:
    private_key = Ed25519PrivateKey.generate()
    return encrypt_key_document(private_key, str(uuid.uuid4()), password), private_key


def encrypt_key_document(private_key: Ed25519PrivateKey, key_id: str, password: str) -> dict[str, object]:
    seed = bytearray(private_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(12)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public_key_text = b64url(public_key)
    metadata = {
        "format": "ratchet-portable-key",
        "version": 1,
        "key_id": key_id,
        "public_key": public_key_text,
        "kdf": {"name": "PBKDF2-SHA256", "iterations": KDF_ITERATIONS, "salt": b64url(salt)},
        "cipher": {"name": "AES-256-GCM", "iv": b64url(iv)},
    }
    derived = bytearray(hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, KDF_ITERATIONS, dklen=32))
    plaintext = bytearray(compact_json({"private_seed": b64url(seed), "public_key": public_key_text}))
    try:
        ciphertext = AESGCM(bytes(derived)).encrypt(iv, bytes(plaintext), compact_json(metadata))
    finally:
        for index in range(len(seed)):
            seed[index] = 0
        for index in range(len(derived)):
            derived[index] = 0
        for index in range(len(plaintext)):
            plaintext[index] = 0
    document = {**metadata, "cipher": {**metadata["cipher"], "ciphertext": b64url(ciphertext)}}
    return document


def unlock_key_file(path: Path, password: str) -> tuple[str, Ed25519PrivateKey]:
    try:
        size = path.stat().st_size
        if size <= 0 or size > MAX_KEY_FILE_BYTES:
            raise SetupError("El archivo de llave está vacío o supera 64 KiB.")
        document = json.loads(path.read_text(encoding="utf-8"))
    except SetupError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SetupError("No se pudo leer un archivo .ratchet-key válido.") from exc
    try:
        if not isinstance(document, dict) or document.get("format") != "ratchet-portable-key" or document.get("version") != 1:
            raise ValueError("format")
        key_id = str(uuid.UUID(str(document["key_id"])))
        public_key_text = str(document["public_key"])
        kdf = document["kdf"]
        cipher = document["cipher"]
        if not isinstance(kdf, dict) or not isinstance(cipher, dict):
            raise ValueError("metadata")
        iterations = int(kdf["iterations"])
        if kdf.get("name") != "PBKDF2-SHA256" or not 600_000 <= iterations <= 5_000_000:
            raise ValueError("kdf")
        if cipher.get("name") != "AES-256-GCM":
            raise ValueError("cipher")
        salt = decode_b64url(str(kdf["salt"]))
        iv = decode_b64url(str(cipher["iv"]))
        ciphertext = decode_b64url(str(cipher["ciphertext"]))
        public_key = decode_b64url(public_key_text)
        if len(salt) != 16 or len(iv) != 12 or len(public_key) != 32 or not 64 <= len(ciphertext) <= 4096:
            raise ValueError("length")
        metadata = {
            "format": "ratchet-portable-key",
            "version": 1,
            "key_id": key_id,
            "public_key": public_key_text,
            "kdf": {"name": "PBKDF2-SHA256", "iterations": iterations, "salt": str(kdf["salt"])},
            "cipher": {"name": "AES-256-GCM", "iv": str(cipher["iv"])},
        }
    except (KeyError, TypeError, ValueError, SetupError) as exc:
        raise SetupError("El archivo no tiene un formato .ratchet-key válido.") from exc

    derived = bytearray(hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32))
    plaintext = bytearray()
    seed = bytearray()
    try:
        plaintext.extend(AESGCM(bytes(derived)).decrypt(iv, ciphertext, compact_json(metadata)))
        inner = json.loads(plaintext.decode("utf-8"))
        seed.extend(decode_b64url(str(inner["private_seed"])))
        if len(seed) != 32 or inner.get("public_key") != public_key_text:
            raise ValueError("key")
        private_key = Ed25519PrivateKey.from_private_bytes(bytes(seed))
        derived_public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        if derived_public_key != public_key:
            raise ValueError("key")
        return key_id, private_key
    except (InvalidTag, ValueError, KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SetupError("No se pudo descifrar la llave del owner. Revisá el archivo y su contraseña.") from exc
    finally:
        for buffer in (derived, plaintext, seed):
            for index in range(len(buffer)):
                buffer[index] = 0


def write_key_file(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(document, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temporary_name, 0o600)
        except OSError:
            pass
        try:
            # Same-directory hard linking publishes the fully flushed file
            # atomically and refuses to replace an existing recovery key.
            os.link(temporary_name, path)
        except FileExistsError as exc:
            raise SetupError("Ese archivo ya existe. Elegí otro para conservar la llave anterior.") from exc
        os.unlink(temporary_name)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise


def rewrap_key_file(path: Path, old_password: str, key_password: str, output: Path) -> None:
    validate_key_password(old_password, key_password)
    key_id, private_key = unlock_key_file(path, old_password)
    try:
        document = encrypt_key_document(private_key, key_id, key_password)
        write_key_file(output, document)
        # Verify the new file before reporting success, preserving the original.
        restored_id, restored = unlock_key_file(output, key_password)
        if restored_id != key_id or restored.sign(b'ratchet-local-key-migration') != private_key.sign(b'ratchet-local-key-migration'):
            raise SetupError("No se pudo verificar la copia cifrada de la llave.")
        del restored
    finally:
        del private_key


def rewrap_dialog(parent: tk.Misc) -> None:
    selected = filedialog.askopenfilename(parent=parent, title="Llave existente para cambiar su contraseña local", filetypes=[("Llave Ratchet", "*.ratchet-key")])
    if not selected:
        return
    old = simpledialog.askstring("Contraseña actual", "Contraseña que actualmente cifra este archivo:", show="•", parent=parent)
    if old is None:
        return
    new = simpledialog.askstring("Nueva contraseña local", "Nueva contraseña de llave (diferente de la contraseña de la cuenta):", show="•", parent=parent)
    if new is None:
        return
    confirmation = simpledialog.askstring("Confirmar contraseña local", "Repetí la nueva contraseña de la llave:", show="•", parent=parent)
    if new != confirmation:
        messagebox.showerror("Contraseñas distintas", "La confirmación no coincide.", parent=parent)
        return
    output = filedialog.asksaveasfilename(parent=parent, title="Guardar una nueva copia cifrada", defaultextension=".ratchet-key", filetypes=[("Llave Ratchet", "*.ratchet-key")])
    if not output:
        return
    try:
        rewrap_key_file(Path(selected), old, new, Path(output))
    except (SetupError, OSError) as exc:
        messagebox.showerror("No se completó el cambio local", str(exc), parent=parent)
        return
    messagebox.showinfo("Nueva copia verificada", "La copia nueva usa la nueva contraseña local y conserva la identidad de la llave. El original permanece intacto. Una copia anterior expuesta sigue siendo válida: en ese caso hay que rotar y revocar la llave en el servidor.", parent=parent)


def post_json(origin: str, path: str, payload: dict[str, object], *, max_response_bytes: int = MAX_RESPONSE_BYTES, safe_errors: bool = False) -> dict[str, object]:
    request = urllib.request.Request(
        origin + path,
        data=compact_json(payload),
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": origin,
            "User-Agent": "Ratchet-Owner-Setup/1",
        },
    )
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    try:
        with opener.open(request, timeout=20) as response:
            raw = response.read(max_response_bytes + 1)
            if len(raw) > max_response_bytes:
                raise SetupError("La respuesta del servidor es demasiado grande.")
    except urllib.error.HTTPError as exc:
        if safe_errors:
            raise SetupError(f"El servidor rechazó la operación (HTTP {exc.code}). Revisá la llave, el rol y los datos; volvé a listar antes de reintentar.") from exc
        raw = exc.read(MAX_RESPONSE_BYTES)
        try:
            problem = json.loads(raw.decode("utf-8"))
            detail = problem.get("detail") or problem.get("title") or f"Error HTTP {exc.code}"
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
            detail = f"Error HTTP {exc.code}"
        raise SetupError(str(detail)) from exc
    except urllib.error.URLError as exc:
        raise SetupError(f"No se pudo conectar con Ratchet: {exc.reason}") from exc
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SetupError("El servidor devolvió una respuesta inválida.") from exc
    if not isinstance(value, dict):
        raise SetupError("El servidor devolvió una respuesta inválida.")
    return value


def provision_owner(origin: str, token: str, login_name: str, password: str, output: Path, *, key_password: str | None = None) -> dict[str, object]:
    key_password = validate_key_password(password, key_password)
    document, private_key = create_key_document(key_password)
    write_key_file(output, document)
    challenge = post_json(origin, "/api/v1/bootstrap/portable-key/prepare", {
        "bootstrap_token": token,
        "key_id": document["key_id"],
        "public_key": document["public_key"],
    })
    required = ("challenge_id", "challenge", "origin", "key_id")
    if any(not isinstance(challenge.get(field), str) for field in required):
        raise SetupError("El servidor devolvió un desafío incompleto.")
    if challenge["origin"] != origin or challenge["key_id"] != document["key_id"]:
        raise SetupError("El servidor devolvió un desafío para otro origen o llave.")
    message = "\n".join([
        "ratchet-portable-key-v1",
        "BOOTSTRAP",
        str(challenge["challenge_id"]),
        str(challenge["challenge"]),
        str(challenge["origin"]),
        str(challenge["key_id"]),
    ]).encode("utf-8")
    signature = b64url(private_key.sign(message))
    return post_json(origin, "/api/v1/bootstrap/portable-key/complete", {
        "bootstrap_token": token,
        "challenge_id": challenge["challenge_id"],
        "signature": signature,
        "login_name": login_name,
        "master_password": password,
    })


def provision_admin(
    origin: str,
    token: str,
    owner_key_path: Path,
    owner_key_password: str,
    login_name: str,
    password: str,
    output: Path,
    *, key_password: str | None = None,
) -> dict[str, object]:
    key_password = validate_key_password(password, key_password)
    owner_key_id, owner_private_key = unlock_key_file(owner_key_path, owner_key_password)
    challenge = post_json(origin, "/api/v1/admin-provisioning/portable-key/prepare", {
        "bootstrap_token": token,
        "owner_key_id": owner_key_id,
    })
    required = ("challenge_id", "challenge", "origin", "key_id", "purpose")
    if any(not isinstance(challenge.get(field), str) for field in required):
        raise SetupError("El servidor devolvió un desafío incompleto.")
    if (
        challenge["origin"] != origin
        or challenge["key_id"] != owner_key_id
        or challenge["purpose"] != "ADMIN_PROVISIONING"
    ):
        raise SetupError("El servidor devolvió un desafío para otro origen o llave.")
    message = "\n".join([
        "ratchet-portable-key-v1",
        "ADMIN_PROVISIONING",
        str(challenge["challenge_id"]),
        str(challenge["challenge"]),
        str(challenge["origin"]),
        str(challenge["key_id"]),
    ]).encode("utf-8")
    signature = b64url(owner_private_key.sign(message))
    document, admin_private_key = create_key_document(key_password)
    write_key_file(output, document)
    del admin_private_key
    return post_json(origin, "/api/v1/admin-provisioning/portable-key/complete", {
        "bootstrap_token": token,
        "challenge_id": challenge["challenge_id"],
        "signature": signature,
        "key_id": document["key_id"],
        "public_key": document["public_key"],
        "login_name": login_name,
        "master_password": password,
    })


class OwnerSetupApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title("Ratchet · Consola de cuentas")
        root.resizable(False, False)
        self.server = tk.StringVar(value=DEFAULT_URL)
        self.token = tk.StringVar(value=read_saved_token())
        self.login = tk.StringVar(value="owner")
        self.password = tk.StringVar()
        self.confirmation = tk.StringVar()
        self.key_password = tk.StringVar()
        self.key_confirmation = tk.StringVar()
        self._automatic_output = Path.home() / "Documents" / key_filename(self.login.get(), "owner")
        self.output = tk.StringVar(value=str(self._automatic_output))
        self.login.trace_add("write", self._sync_output_name)
        self.status = tk.StringVar(value="La llave privada se creará y cifrará únicamente en este equipo.")
        self._build()

    def _build(self) -> None:
        frame = ttk.Frame(self.root, padding=20)
        frame.grid()
        ttk.Label(frame, text="Crear owner inicial", font=("Segoe UI", 16, "bold")).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 12))
        fields = [
            ("Servidor beta", self.server, False),
            ("Token de instalación", self.token, True),
            ("Usuario owner", self.login, False),
            ("Contraseña maestra", self.password, True),
            ("Confirmar contraseña de cuenta", self.confirmation, True),
            ("Contraseña local de la llave", self.key_password, True),
            ("Confirmar contraseña de llave", self.key_confirmation, True),
        ]
        for row, (label, variable, secret) in enumerate(fields, start=1):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=4)
            ttk.Entry(frame, textvariable=variable, width=58, show="•" if secret else "").grid(row=row, column=1, columnspan=2, sticky="ew", pady=4)
        ttk.Label(frame, text="Guardar llave en").grid(row=8, column=0, sticky="w", pady=4)
        ttk.Entry(frame, textvariable=self.output, width=48).grid(row=8, column=1, sticky="ew", pady=4)
        ttk.Button(frame, text="Elegir…", command=self._choose_output).grid(row=8, column=2, padx=(8, 0), pady=4)
        ttk.Label(frame, textvariable=self.status, wraplength=540).grid(row=9, column=0, columnspan=3, sticky="w", pady=(12, 8))
        self.submit = ttk.Button(frame, text="Crear owner y llave cifrada", command=self._start)
        self.submit.grid(row=10, column=0, columnspan=3, sticky="ew")
        ttk.Separator(frame).grid(row=11, column=0, columnspan=3, sticky="ew", pady=14)
        ttk.Button(frame, text="Cambiar contraseña local de una llave…", command=lambda: rewrap_dialog(self.root)).grid(row=14, column=0, columnspan=3, sticky="ew", pady=(8, 0))
        ttk.Button(frame, text="Crear una cuenta ADMIN adicional…", command=self._open_admin).grid(row=12, column=0, columnspan=3, sticky="ew")
        ttk.Button(frame, text="Recuperar cuentas y consultar conversaciones…", command=lambda: open_console(self.root, self.server.get())).grid(row=13, column=0, columnspan=3, sticky="ew", pady=(8, 0))

    def _open_admin(self) -> None:
        window = tk.Toplevel(self.root)
        AdminSetupApp(window)

    def _sync_output_name(self, *_args: object) -> None:
        if Path(self.output.get()).expanduser() != self._automatic_output:
            return
        self._automatic_output = Path.home() / "Documents" / key_filename(self.login.get(), "owner")
        self.output.set(str(self._automatic_output))

    def _choose_output(self) -> None:
        selected = filedialog.asksaveasfilename(
            title="Guardar llave privada cifrada",
            defaultextension=".ratchet-key",
            filetypes=[("Llave Ratchet", "*.ratchet-key"), ("Todos los archivos", "*.*")],
            initialfile=key_filename(self.login.get(), "owner"),
        )
        if selected:
            self.output.set(selected)

    def _start(self) -> None:
        try:
            origin = normalize_origin(self.server.get())
            token = self.token.get().strip()
            login = self.login.get().strip()
            password = self.password.get()
            key_password = validate_key_password(password, self.key_password.get())
            if key_password != self.key_confirmation.get():
                raise SetupError("Las contraseñas locales de la llave no coinciden.")
            output = Path(self.output.get()).expanduser()
            if not 32 <= len(token) <= 512:
                raise SetupError("El token de instalación no es válido.")
            if not re.fullmatch(r"[A-Za-z0-9._-]{3,64}", login):
                raise SetupError("El usuario owner debe tener entre 3 y 64 caracteres: letras, números, punto, guion o guion bajo.")
            if not 15 <= len(password) <= 256:
                raise SetupError("La contraseña maestra debe tener entre 15 y 256 caracteres.")
            if password != self.confirmation.get():
                raise SetupError("Las contraseñas no coinciden.")
            if output.suffix.lower() != ".ratchet-key":
                raise SetupError("El archivo debe terminar en .ratchet-key.")
            if output.exists():
                raise SetupError("Ese archivo ya existe. Elegí otro nombre para no sobrescribir una llave.")
        except SetupError as exc:
            messagebox.showerror("Revisá los datos", str(exc))
            return
        self.submit.state(["disabled"])
        self.status.set("Creando la llave y registrando el owner…")
        threading.Thread(target=self._run, args=(origin, token, login, password, output, key_password), daemon=True).start()

    def _run(self, origin: str, token: str, login: str, password: str, output: Path, key_password: str) -> None:
        try:
            result = provision_owner(origin, token, login, password, output, key_password=key_password)
            if not all(isinstance(result.get(field), str) for field in ("user_id", "workspace_id", "key_id")):
                raise SetupError("El alta terminó, pero la confirmación del servidor es inválida.")
            self.root.after(0, self._success, output)
        except Exception as exc:
            detail = str(exc) if isinstance(exc, SetupError) else "Ocurrió un error inesperado."
            self.root.after(0, self._failure, detail, output)

    def _success(self, output: Path) -> None:
        self.password.set("")
        self.confirmation.set("")
        self.key_password.set("")
        self.key_confirmation.set("")
        self.status.set(f"Owner creado. Llave guardada en: {output}")
        messagebox.showinfo("Owner creado", "El owner fue creado correctamente. Ya podés importar la llave en la pantalla normal de ingreso.")
        self.submit.state(["!disabled"])

    def _failure(self, detail: str, output: Path) -> None:
        self.status.set(f"No se completó el alta. Si se creó, conservá el archivo local: {output}")
        messagebox.showerror("No se pudo crear el owner", detail)
        self.submit.state(["!disabled"])


class AdminSetupApp:
    def __init__(self, root: tk.Misc) -> None:
        self.root = root
        root.title("Ratchet · Crear administrador")
        root.resizable(False, False)
        self.server = tk.StringVar(value=DEFAULT_URL)
        self.token = tk.StringVar(value=read_saved_token())
        self.owner_key = tk.StringVar()
        self.owner_password = tk.StringVar()
        self.login = tk.StringVar()
        self.password = tk.StringVar()
        self.confirmation = tk.StringVar()
        self.key_password = tk.StringVar()
        self.key_confirmation = tk.StringVar()
        self._automatic_output = Path.home() / "Documents" / key_filename(self.login.get(), "admin")
        self.output = tk.StringVar(value=str(self._automatic_output))
        self.login.trace_add("write", self._sync_output_name)
        self.status = tk.StringVar(value="Sólo el owner original puede autorizar una nueva cuenta ADMIN.")
        self._build()

    def _build(self) -> None:
        frame = ttk.Frame(self.root, padding=20)
        frame.grid()
        ttk.Label(frame, text="Crear cuenta ADMIN", font=("Segoe UI", 16, "bold")).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 12))
        fields = [
            ("Servidor beta", self.server, False),
            ("Token de instalación", self.token, True),
        ]
        for row, (label, variable, secret) in enumerate(fields, start=1):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=4)
            ttk.Entry(frame, textvariable=variable, width=58, show="•" if secret else "").grid(row=row, column=1, columnspan=2, sticky="ew", pady=4)
        ttk.Label(frame, text="Llave del owner").grid(row=3, column=0, sticky="w", pady=4)
        ttk.Entry(frame, textvariable=self.owner_key, width=48).grid(row=3, column=1, sticky="ew", pady=4)
        ttk.Button(frame, text="Elegir…", command=self._choose_owner_key).grid(row=3, column=2, padx=(8, 0), pady=4)
        ttk.Label(frame, text="Contraseña de llave owner").grid(row=4, column=0, sticky="w", pady=4)
        ttk.Entry(frame, textvariable=self.owner_password, width=58, show="•").grid(row=4, column=1, columnspan=2, sticky="ew", pady=4)
        for row, (label, variable, secret) in enumerate([
            ("Usuario ADMIN nuevo", self.login, False),
            ("Contraseña ADMIN nueva", self.password, True),
            ("Confirmar contraseña de cuenta", self.confirmation, True),
            ("Contraseña local de la llave", self.key_password, True),
            ("Confirmar contraseña de llave", self.key_confirmation, True),
        ], start=5):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=4)
            ttk.Entry(frame, textvariable=variable, width=58, show="•" if secret else "").grid(row=row, column=1, columnspan=2, sticky="ew", pady=4)
        ttk.Label(frame, text="Guardar llave ADMIN en").grid(row=10, column=0, sticky="w", pady=4)
        ttk.Entry(frame, textvariable=self.output, width=48).grid(row=10, column=1, sticky="ew", pady=4)
        ttk.Button(frame, text="Elegir…", command=self._choose_output).grid(row=10, column=2, padx=(8, 0), pady=4)
        ttk.Label(frame, textvariable=self.status, wraplength=580).grid(row=11, column=0, columnspan=3, sticky="w", pady=(12, 8))
        self.submit = ttk.Button(frame, text="Crear ADMIN y llave cifrada", command=self._start)
        self.submit.grid(row=12, column=0, columnspan=3, sticky="ew")
        ttk.Button(frame, text="Consola exclusiva del owner…", command=lambda: open_console(self.root, self.server.get(), self.owner_key.get())).grid(row=13, column=0, columnspan=3, sticky="ew", pady=(8, 0))

    def _choose_owner_key(self) -> None:
        selected = filedialog.askopenfilename(
            title="Elegir llave cifrada del owner",
            filetypes=[("Llave Ratchet", "*.ratchet-key"), ("Todos los archivos", "*.*")],
        )
        if selected:
            self.owner_key.set(selected)

    def _sync_output_name(self, *_args: object) -> None:
        if Path(self.output.get()).expanduser() != self._automatic_output:
            return
        self._automatic_output = Path.home() / "Documents" / key_filename(self.login.get(), "admin")
        self.output.set(str(self._automatic_output))

    def _choose_output(self) -> None:
        selected = filedialog.asksaveasfilename(
            title="Guardar llave cifrada del nuevo ADMIN",
            defaultextension=".ratchet-key",
            filetypes=[("Llave Ratchet", "*.ratchet-key"), ("Todos los archivos", "*.*")],
            initialfile=key_filename(self.login.get(), "admin"),
        )
        if selected:
            self.output.set(selected)

    def _start(self) -> None:
        try:
            origin = normalize_origin(self.server.get())
            token = self.token.get().strip()
            owner_key = Path(self.owner_key.get()).expanduser()
            owner_password = self.owner_password.get()
            login = self.login.get().strip()
            password = self.password.get()
            key_password = validate_key_password(password, self.key_password.get())
            if key_password != self.key_confirmation.get():
                raise SetupError("Las contraseñas locales de la llave no coinciden.")
            output = Path(self.output.get()).expanduser()
            if not 32 <= len(token) <= 512:
                raise SetupError("El token de instalación no es válido.")
            if not owner_key.is_file() or owner_key.suffix.lower() != ".ratchet-key":
                raise SetupError("Elegí el archivo .ratchet-key del owner.")
            if not owner_password:
                raise SetupError("Ingresá la contraseña de la llave del owner.")
            if not re.fullmatch(r"[A-Za-z0-9._-]{3,64}", login):
                raise SetupError("El usuario ADMIN debe tener entre 3 y 64 caracteres: letras, números, punto, guion o guion bajo.")
            if not 15 <= len(password) <= 256:
                raise SetupError("La contraseña ADMIN debe tener entre 15 y 256 caracteres.")
            if password != self.confirmation.get():
                raise SetupError("Las contraseñas del nuevo ADMIN no coinciden.")
            if output.suffix.lower() != ".ratchet-key":
                raise SetupError("El archivo debe terminar en .ratchet-key.")
            if output.exists():
                raise SetupError("Ese archivo ya existe. Elegí otro nombre para no sobrescribir una llave.")
        except SetupError as exc:
            messagebox.showerror("Revisá los datos", str(exc), parent=self.root)
            return
        self.submit.state(["disabled"])
        self.status.set("Verificando al owner y creando la cuenta ADMIN…")
        threading.Thread(
            target=self._run,
            args=(origin, token, owner_key, owner_password, login, password, output, key_password),
            daemon=True,
        ).start()

    def _run(self, origin: str, token: str, owner_key: Path, owner_password: str, login: str, password: str, output: Path, key_password: str) -> None:
        try:
            result = provision_admin(origin, token, owner_key, owner_password, login, password, output, key_password=key_password)
            if result.get("role") != "ADMIN" or not all(isinstance(result.get(field), str) for field in ("user_id", "workspace_id", "key_id")):
                raise SetupError("El alta terminó, pero la confirmación del servidor es inválida.")
            self.root.after(0, self._success, output)
        except Exception as exc:
            detail = str(exc) if isinstance(exc, SetupError) else "Ocurrió un error inesperado."
            self.root.after(0, self._failure, detail, output)

    def _success(self, output: Path) -> None:
        self.owner_password.set("")
        self.password.set("")
        self.confirmation.set("")
        self.key_password.set("")
        self.key_confirmation.set("")
        self.status.set(f"ADMIN creado. Llave guardada en: {output}")
        messagebox.showinfo("ADMIN creado", "La cuenta ADMIN fue creada por el owner. Entregale su usuario, contraseña y llave cifrada por canales seguros separados.", parent=self.root)
        self.submit.state(["!disabled"])

    def _failure(self, detail: str, output: Path) -> None:
        self.status.set(f"No se completó el alta. Si se creó, conservá el archivo local: {output}")
        messagebox.showerror("No se pudo crear el ADMIN", detail, parent=self.root)
        self.submit.state(["!disabled"])


def requested_mode(arguments: list[str]) -> str:
    if not arguments or arguments == ["--owner"]:
        return "owner"
    if arguments == ["--admin"]:
        return "admin"
    if arguments == ["--console"]:
        return "console"
    raise SetupError("Usá --owner para crear el owner inicial, --admin para crear una cuenta ADMIN o --console para la consola del owner.")


def open_console(parent: tk.Misc, origin: str, key_path: str = "") -> None:
    from owner_console import OwnerConsoleApp
    app = OwnerConsoleApp(tk.Toplevel(parent), origin)
    app.owner_key.set(key_path)


def main() -> None:
    try:
        mode = requested_mode(sys.argv[1:])
    except SetupError as exc:
        raise SystemExit(str(exc)) from exc
    root = tk.Tk()
    try:
        ttk.Style(root).theme_use("vista")
    except tk.TclError:
        pass
    if mode == "console":
        from owner_console import OwnerConsoleApp
        OwnerConsoleApp(root)
    elif mode == "admin":
        AdminSetupApp(root)
    else:
        OwnerSetupApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
