"""Local launcher for the existing independent staging; never submits automatically."""
import json
import sys
from pathlib import Path

import ratchet_owner_setup as gui

state = Path(__file__).resolve().parents[3] / "sqlite-clean-deployment"
origin = json.loads((state / "manifest.json").read_text(encoding="utf-8-sig"))["url"]
if origin.rstrip("/") != "https://ratchet-sqlite-clean-20260923.braian-n-l.workers.dev":
    raise SystemExit("El archivo local no corresponde al staging SQLite.")
key = state / "owner.ratchet-key"
if sys.argv[1:] == ["--console"]:
    from owner_console import OwnerConsoleApp
    root = gui.tk.Tk()
    app = OwnerConsoleApp(root, origin)
    if key.is_file():
        app.owner_key.set(str(key))
    root.mainloop()
    raise SystemExit(0)
if sys.argv[1:] not in ([], ["--check"]):
    raise SystemExit("Argumentos no reconocidos. Usá --console para recuperar cuentas y consultar conversaciones.")
token = json.loads((state / "private.json").read_text(encoding="utf-8-sig"))["BOOTSTRAP_TOKEN"]
owner = json.loads((state / "private-accounts.json").read_text(encoding="utf-8-sig"))["owner"]
if not key.is_file() or not token or not owner.get("password"):
    raise SystemExit("Faltan los datos locales del owner del staging.")
if sys.argv[1:] == ["--check"]:
    print("Staging, token local y archivos del owner disponibles. No se crearon cuentas.")
else:
    gui.DEFAULT_URL = origin
    gui.read_saved_token = lambda: token
    root = gui.tk.Tk()
    app = gui.AdminSetupApp(root)
    root.title("Ratchet SQLite staging - Crear administrador")
    app.owner_key.set(str(key))
    app.owner_password.set(owner["password"])
    root.mainloop()
