"""Local owner operations. Private signing material stays in process memory only."""
from __future__ import annotations

import hashlib
import json
import queue
import threading
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
import tkinter as tk

import ratchet_owner_setup as setup

PAGE_SIZE = 20
CHALLENGE_FIELDS = (
    'challenge_id', 'challenge', 'purpose', 'key_id', 'owner_user_id',
    'workspace_id', 'origin', 'operation_digest', 'expires_at',
)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')


def challenge_message(challenge: dict, origin: str, key_id: str, operation: dict) -> bytes:
    if any(not isinstance(challenge.get(field), str) or not challenge[field] for field in CHALLENGE_FIELDS):
        raise setup.SetupError('El servidor devolvió un desafío incompleto.')
    digest = hashlib.sha256(canonical(operation)).hexdigest()
    if (challenge['purpose'] != 'OWNER_CONSOLE' or challenge['origin'] != origin
            or challenge['key_id'] != key_id or challenge['operation_digest'] != digest):
        raise setup.SetupError('El desafío no corresponde al servidor, la llave o la operación seleccionada.')
    try:
        expiry = datetime.fromisoformat(challenge['expires_at'].replace('Z', '+00:00'))
        if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
            raise ValueError('expired')
    except (ValueError, OverflowError) as exc:
        raise setup.SetupError('El desafío venció o tiene una fecha inválida. Reintentá la operación.') from exc
    return canonical({field: challenge[field] for field in CHALLENGE_FIELDS})


def signed_operation(origin: str, key_path: Path, password: str, operation: dict) -> dict:
    # Snapshot before I/O: changing a selection cannot change what gets signed.
    operation = json.loads(canonical(operation))
    key_id, private_key = setup.unlock_key_file(key_path, password)
    try:
        challenge = setup.post_json(origin, '/api/v1/owner-console/prepare', {
            'owner_key_id': key_id, 'operation': operation,
        }, safe_errors=True)
        signature = setup.b64url(private_key.sign(challenge_message(challenge, origin, key_id, operation)))
        return setup.post_json(origin, '/api/v1/owner-console/complete', {
            'challenge_id': challenge['challenge_id'], 'signature': signature, 'operation': operation,
        }, max_response_bytes=32 * 1024 * 1024, safe_errors=True)
    finally:
        del private_key


def recovery_operation(account: dict, password: str, output: Path | None, *, key_password: str | None = None) -> dict:
    if account.get('role') not in {'CUSTOMER', 'ADMIN'} or not isinstance(account.get('user_id'), str):
        raise setup.SetupError('Sólo se pueden recuperar cuentas CUSTOMER o ADMIN seleccionadas.')
    if not 15 <= len(password) <= 256:
        raise setup.SetupError('La contraseña nueva debe tener entre 15 y 256 caracteres.')
    operation = {'type': 'account.recover', 'user_id': account['user_id'], 'new_password': password}
    if account['role'] == 'ADMIN':
        key_password = setup.validate_key_password(password, key_password)
        if output is None or output.suffix.lower() != '.ratchet-key':
            raise setup.SetupError('Elegí un archivo .ratchet-key nuevo para el ADMIN.')
        document, private_key = setup.create_key_document(key_password)
        del private_key
        setup.write_key_file(output, document)
        operation.update(new_key_id=document['key_id'], new_public_key=document['public_key'])
    return operation


def decode_body(envelope: object) -> str:
    if not isinstance(envelope, dict) or envelope.get('header') != 'server-sqlite-v1':
        return '[Formato de mensaje no compatible]'
    try:
        encoded = envelope.get('ciphertext')
        if not isinstance(encoded, str) or len(encoded) > 2_000_000:
            raise ValueError('size')
        body = json.loads(setup.decode_b64url(encoded).decode('utf-8'))
        if not isinstance(body, dict) or body.get('v') not in (1, 2) or not isinstance(body.get('text'), str):
            raise ValueError('body')
        attachments = body.get('attachments')
        if not isinstance(attachments, list) or len(attachments) > 16 or len(body['text']) > 200_000:
            raise ValueError('body')
        suffix = f'\n[{len(attachments)} adjunto(s); visualización no disponible en esta consola]' if attachments else ''
        return body['text'] + suffix
    except (ValueError, TypeError, UnicodeDecodeError, setup.SetupError):
        return '[No se pudo interpretar este mensaje]'


class OwnerConsoleApp:
    def __init__(self, root: tk.Misc, origin: str | None = None):
        self.root = root
        root.title('Ratchet · Consola exclusiva del owner')
        root.geometry('960x740')
        root.minsize(760, 580)
        self.server = tk.StringVar(value=origin or setup.DEFAULT_URL)
        self.owner_key = tk.StringVar()
        self.owner_password = tk.StringVar()
        self.status = tk.StringVar(value='Cada operación requiere la contraseña de la llave del owner. No se guarda el historial en disco.')
        self.busy = False
        self.events = queue.Queue()
        self.buttons = []
        self.accounts = {}
        self.conversations = {}
        self.account_cursor = None
        self.conversation_cursor = None
        self.history_cursor = None
        self.history_chat = None
        self._build()
        for variable in (self.server, self.owner_key):
            variable.trace_add('write', self._reset_context)
        self.root.after(100, self._poll)

    def _button(self, frame, label, command, **grid):
        button = ttk.Button(frame, text=label, command=command)
        button.grid(**grid)
        self.buttons.append(button)
        return button

    def _build(self):
        frame = ttk.Frame(self.root, padding=14)
        frame.pack(fill='both', expand=True)
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(4, weight=1)
        for row, (label, variable, secret) in enumerate([
            ('Servidor SQLite', self.server, False), ('Llave del owner', self.owner_key, False),
            ('Contraseña de la llave', self.owner_password, True),
        ]):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky='w', padx=(0, 12), pady=3)
            ttk.Entry(frame, textvariable=variable, show='•' if secret else '').grid(row=row, column=1, sticky='ew')
        self._button(frame, 'Elegir…', self._choose_key, row=1, column=2, padx=6)
        ttk.Label(frame, textvariable=self.status, wraplength=860).grid(row=3, column=0, columnspan=3, sticky='w', pady=10)
        notebook = ttk.Notebook(frame)
        notebook.grid(row=4, column=0, columnspan=3, sticky='nsew')
        accounts = ttk.Frame(notebook, padding=10)
        conversations = ttk.Frame(notebook, padding=10)
        notebook.add(accounts, text='Recuperar cuenta')
        notebook.add(conversations, text='Consultar conversaciones')
        for tab in (accounts, conversations):
            tab.columnconfigure(0, weight=1)
            tab.rowconfigure(1, weight=1)
        actions = ttk.Frame(accounts)
        actions.grid(row=0, column=0, sticky='w', pady=(0, 8))
        self._button(actions, 'Listar desde el inicio', lambda: self._list_accounts(None), row=0, column=0)
        self._button(actions, 'Página siguiente', self._next_accounts, row=0, column=1, padx=6)
        self._button(actions, 'Recuperar seleccionada…', self._recover, row=0, column=2)
        self.account_tree = self._tree(accounts, ('login_name', 'role', 'display_name', 'user_id'), ('Usuario', 'Rol', 'Nombre', 'ID'))
        actions = ttk.Frame(conversations)
        actions.grid(row=0, column=0, sticky='w', pady=(0, 8))
        self._button(actions, 'Listar desde el inicio', lambda: self._list_conversations(None), row=0, column=0)
        self._button(actions, 'Página siguiente', self._next_conversations, row=0, column=1, padx=6)
        self._button(actions, 'Leer seleccionada', self._read_selected, row=0, column=2)
        self._button(actions, 'Más historial', self._next_history, row=0, column=3, padx=6)
        self.conversation_tree = self._tree(conversations, ('chat_id', 'message_count', 'created_at', 'last_message_at'), ('Conversación', 'Mensajes', 'Creada', 'Último mensaje'))
        conversations.rowconfigure(2, weight=2)
        history_frame = ttk.Frame(conversations)
        history_frame.grid(row=2, column=0, sticky='nsew', pady=(10, 0))
        self.history = tk.Text(history_frame, wrap='word', state='disabled', height=15)
        scroll = ttk.Scrollbar(history_frame, command=self.history.yview)
        self.history.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right', fill='y')
        self.history.pack(fill='both', expand=True)

    def _tree(self, frame, columns, headings):
        tree_frame = ttk.Frame(frame)
        tree_frame.grid(row=1, column=0, sticky='nsew')
        tree = ttk.Treeview(tree_frame, columns=columns, show='headings', selectmode='browse', height=7)
        for column, heading in zip(columns, headings):
            tree.heading(column, text=heading)
            tree.column(column, width=190, minwidth=80)
        scroll = ttk.Scrollbar(tree_frame, command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right', fill='y')
        tree.pack(fill='both', expand=True)
        return tree

    def _choose_key(self):
        selected = filedialog.askopenfilename(parent=self.root, title='Llave cifrada del owner', filetypes=[('Llave Ratchet', '*.ratchet-key')])
        if selected:
            self.owner_key.set(selected)

    def _context(self):
        return (self.server.get(), self.owner_key.get())

    def _reset_context(self, *_args):
        self.accounts.clear()
        self.conversations.clear()
        self.account_cursor = self.conversation_cursor = self.history_cursor = self.history_chat = None
        self.account_tree.delete(*self.account_tree.get_children())
        self.conversation_tree.delete(*self.conversation_tree.get_children())
        self._show_history('')

    def _credentials(self):
        origin = setup.normalize_origin(self.server.get())
        path = Path(self.owner_key.get()).expanduser()
        password = self.owner_password.get()
        if path.suffix.lower() != '.ratchet-key' or not path.is_file() or not password:
            raise setup.SetupError('Elegí la llave del owner e ingresá su contraseña para esta operación.')
        return origin, path, password

    def _execute(self, make_operation, success):
        if self.busy:
            return
        try:
            credentials = self._credentials()
        except setup.SetupError as exc:
            messagebox.showerror('Revisá los datos', str(exc), parent=self.root)
            return
        context = self._context()
        self.owner_password.set('')
        self.busy = True
        for button in self.buttons:
            button.state(['disabled'])
        self.status.set('Autorizando la operación con la llave local del owner…')

        def run():
            try:
                operation = make_operation()
                result = signed_operation(*credentials, operation)
                self.events.put((context, success, result, None))
            except Exception as exc:
                detail = str(exc) if isinstance(exc, setup.SetupError) else 'No se pudo completar la operación.'
                self.events.put((context, success, None, detail))
        threading.Thread(target=run, daemon=True).start()

    def _poll(self):
        try:
            context, success, result, error = self.events.get_nowait()
        except queue.Empty:
            pass
        else:
            self.busy = False
            for button in self.buttons:
                button.state(['!disabled'])
            if context != self._context():
                self.status.set('La operación terminó en el servidor anterior. Volvé a listar para consultar el estado actual.')
            elif error:
                self.status.set('Operación no confirmada. Si se generó una llave nueva, conservala y comprobá el estado antes de reintentar.')
                messagebox.showerror('Operación no confirmada', error, parent=self.root)
            else:
                try:
                    success(result)
                except (KeyError, ValueError, TypeError, setup.SetupError):
                    self.status.set('Respuesta inválida. Comprobá el estado antes de reintentar una recuperación.')
                    messagebox.showerror('Respuesta inválida', 'No se pudo interpretar la confirmación del servidor.', parent=self.root)
        self.root.after(100, self._poll)

    def _list_accounts(self, after):
        operation = {'type': 'accounts.list', 'limit': PAGE_SIZE}
        if after:
            operation['after'] = after
        self._execute(lambda: operation, self._accounts_result)

    def _accounts_result(self, result):
        rows = result['accounts']
        if not isinstance(rows, list) or len(rows) > PAGE_SIZE:
            raise ValueError('rows')
        accounts = {row['user_id']: dict(row) for row in rows}
        self.account_tree.delete(*self.account_tree.get_children())
        self.accounts = accounts
        for user_id, row in accounts.items():
            self.account_tree.insert('', 'end', iid=user_id, values=[row.get(field, '') for field in ('login_name', 'role', 'display_name', 'user_id')])
        self.account_cursor = result.get('next_after')
        self.status.set(f'{len(rows)} cuentas. ' + ('Hay otra página.' if self.account_cursor else 'Fin de la lista.'))

    def _next_accounts(self):
        if self.account_cursor:
            self._list_accounts(self.account_cursor)

    def _list_conversations(self, after):
        operation = {'type': 'conversations.list', 'limit': PAGE_SIZE}
        if after:
            operation['after'] = after
        self._execute(lambda: operation, self._conversations_result)

    def _conversations_result(self, result):
        rows = result['conversations']
        if not isinstance(rows, list) or len(rows) > PAGE_SIZE:
            raise ValueError('rows')
        conversations = {row['chat_id']: dict(row) for row in rows}
        self.conversation_tree.delete(*self.conversation_tree.get_children())
        self.conversations = conversations
        for chat_id, row in conversations.items():
            self.conversation_tree.insert('', 'end', iid=chat_id, values=[row.get(field, '') for field in ('chat_id', 'message_count', 'created_at', 'last_message_at')])
        self.conversation_cursor = result.get('next_after')
        self.history_cursor = self.history_chat = None
        self._show_history('')
        self.status.set(f'{len(rows)} conversaciones. ' + ('Hay otra página.' if self.conversation_cursor else 'Fin de la lista.'))

    def _next_conversations(self):
        if self.conversation_cursor:
            self._list_conversations(self.conversation_cursor)

    def _read_selected(self):
        selected = self.conversation_tree.selection()
        if selected and selected[0] in self.conversations:
            self._read(selected[0], 0)

    def _next_history(self):
        if self.history_chat and self.history_cursor is not None:
            self._read(self.history_chat, self.history_cursor)

    def _read(self, chat_id, after):
        operation = {'type': 'conversation.read', 'chat_id': chat_id, 'after_revision': after, 'limit': PAGE_SIZE}
        self._execute(lambda: operation, lambda result: self._history_result(result, chat_id, after))

    def _history_result(self, result, chat_id, after):
        if result.get('chat_id') != chat_id or not isinstance(result.get('changes'), list) or len(result['changes']) > PAGE_SIZE:
            raise ValueError('history')
        revision = result.get('next_revision')
        if type(revision) is not int or revision < after or (result.get('has_more') and revision <= after):
            raise ValueError('cursor')
        lines = [f'Conversación {chat_id} · revisiones {after}–{revision}\n']
        for change in result['changes']:
            if change.get('type') != 'message':
                continue
            mutation = change.get('mutation')
            label = f" [{mutation.get('type')} → {mutation.get('target_message_id')}]" if isinstance(mutation, dict) else ''
            lines.append(f"{change.get('created_at', '')} · {change.get('sender_display_name') or change.get('sender_user_id', '')}{label}\n{decode_body(change.get('envelope'))}\n")
        self.history_chat = chat_id
        self.history_cursor = revision if result.get('has_more') else None
        self._show_history('\n'.join(lines))
        self.status.set('Página de historial cargada. ' + ('Hay más historial.' if self.history_cursor is not None else 'Fin del historial.'))

    def _show_history(self, text):
        self.history.configure(state='normal')
        self.history.delete('1.0', 'end')
        self.history.insert('1.0', text)
        self.history.configure(state='disabled')

    def _recover(self):
        selected = self.account_tree.selection()
        if not selected or selected[0] not in self.accounts:
            messagebox.showinfo('Seleccioná una cuenta', 'Listá las cuentas y seleccioná la que querés recuperar.', parent=self.root)
            return
        account = dict(self.accounts[selected[0]])
        if account.get('role') not in {'CUSTOMER', 'ADMIN'}:
            messagebox.showerror('Cuenta no recuperable', 'La recuperación del owner no está disponible.', parent=self.root)
            return
        dialog = tk.Toplevel(self.root)
        dialog.title('Confirmar recuperación de cuenta')
        dialog.transient(self.root)
        dialog.grab_set()
        frame = ttk.Frame(dialog, padding=20)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text=f"{account.get('login_name') or account.get('display_name') or 'Cuenta'} · {account['role']}\nID: {account['user_id']}\nSe revocarán las credenciales anteriores y las sesiones/dispositivos.\nLa identidad y el historial se conservarán.", wraplength=580).grid(row=0, column=0, columnspan=2, sticky='w', pady=10)
        password, confirmation, output = tk.StringVar(), tk.StringVar(), tk.StringVar()
        key_password, key_confirmation = tk.StringVar(), tk.StringVar()
        for row, (label, variable) in enumerate([('Nueva contraseña', password), ('Confirmar contraseña', confirmation)], start=1):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky='w', pady=4)
            ttk.Entry(frame, textvariable=variable, show='•', width=45).grid(row=row, column=1)
        if account['role'] == 'ADMIN':
            for row, (label, variable) in enumerate([('Contraseña local de llave ADMIN', key_password), ('Confirmar contraseña de llave', key_confirmation)], start=3):
                ttk.Label(frame, text=label).grid(row=row, column=0, sticky='w', pady=4)
                ttk.Entry(frame, textvariable=variable, show='•', width=45).grid(row=row, column=1)
            ttk.Label(frame, text='Nueva llave ADMIN cifrada').grid(row=5, column=0, sticky='w')
            ttk.Entry(frame, textvariable=output, width=45).grid(row=5, column=1)

            def choose():
                path = filedialog.asksaveasfilename(parent=dialog, defaultextension='.ratchet-key', filetypes=[('Llave Ratchet', '*.ratchet-key')], initialfile=setup.key_filename(account.get('login_name', ''), 'admin-recuperado'))
                if path:
                    output.set(path)
            ttk.Button(frame, text='Elegir archivo nuevo…', command=choose).grid(row=6, column=1, sticky='e')
        ttk.Label(frame, text='Contraseña de llave owner').grid(row=7, column=0, sticky='w', pady=8)
        ttk.Entry(frame, textvariable=self.owner_password, show='•', width=45).grid(row=7, column=1)

        def confirm():
            secret = password.get()
            local_secret = key_password.get()
            key_output = Path(output.get()).expanduser() if output.get() else None
            if secret != confirmation.get() or not 15 <= len(secret) <= 256:
                messagebox.showerror('Revisá los datos', 'Las contraseñas deben coincidir y tener entre 15 y 256 caracteres.', parent=dialog)
                return
            if account['role'] == 'ADMIN':
                try:
                    setup.validate_key_password(secret, local_secret)
                    if local_secret != key_confirmation.get():
                        raise setup.SetupError('Las contraseñas locales de llave no coinciden.')
                except setup.SetupError as exc:
                    messagebox.showerror('Revisá la contraseña local', str(exc), parent=dialog)
                    return
            if account['role'] == 'ADMIN' and (key_output is None or key_output.suffix.lower() != '.ratchet-key' or key_output.exists()):
                messagebox.showerror('Revisá el archivo', 'Elegí un archivo .ratchet-key que todavía no exista.', parent=dialog)
                return
            try:
                self._credentials()
            except setup.SetupError as exc:
                messagebox.showerror('Llave del owner', str(exc), parent=dialog)
                return
            password.set('')
            confirmation.set('')
            key_password.set('')
            key_confirmation.set('')
            dialog.destroy()

            def recovered(result):
                if result.get('recovered') is not True or result.get('user_id') != account['user_id']:
                    raise ValueError('recovery')
                self.status.set('Cuenta recuperada; credenciales anteriores y sesiones revocadas.' + (f' Nueva llave: {key_output}' if key_output else ''))
                messagebox.showinfo('Cuenta recuperada', 'Entregá las nuevas credenciales por canales seguros. La contraseña de cuenta y la contraseña local de la nueva llave ADMIN son independientes.', parent=self.root)
            self._execute(lambda: recovery_operation(account, secret, key_output, key_password=local_secret), recovered)

        ttk.Button(frame, text='Recuperar esta cuenta y revocar sesiones', command=confirm).grid(row=8, column=0, columnspan=2, sticky='ew', pady=14)
