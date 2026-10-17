"""Exercise real encrypted key files while replacing only network transport."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import ratchet_owner_setup as setup
import owner_console

ACCOUNT_PASSWORD = 'Server account password 2026!'
LOCAL_PASSWORD = 'Different offline key passphrase!'


class KeySeparationTests(unittest.TestCase):
    def test_key_writer_never_overwrites_an_existing_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'backup.ratchet-key'
            path.write_text('existing encrypted backup')
            with self.assertRaises(setup.SetupError):
                setup.write_key_file(path, {'new': 'document'})
            self.assertEqual(path.read_text(), 'existing encrypted backup')

    def test_owner_provisioning_requires_an_independent_local_passphrase(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'owner.ratchet-key'
            with self.assertRaises(setup.SetupError):
                setup.provision_owner('https://ratchet.test', 't' * 32, 'owner', ACCOUNT_PASSWORD, path)
            self.assertFalse(path.exists())

    def test_owner_file_unlocks_only_locally_and_local_secret_is_never_sent(self):
        sent = []
        def transport(origin, route, body, **kwargs):
            sent.append(body)
            if route.endswith('/prepare'):
                return {'challenge_id': 'id', 'challenge': 'challenge', 'origin': origin, 'key_id': body['key_id']}
            return {'created': True}
        with tempfile.TemporaryDirectory() as directory, patch.object(setup, 'post_json', transport):
            path = Path(directory) / 'owner.ratchet-key'
            setup.provision_owner('https://ratchet.test', 't' * 32, 'owner', ACCOUNT_PASSWORD, path, key_password=LOCAL_PASSWORD)
            setup.unlock_key_file(path, LOCAL_PASSWORD)
            with self.assertRaises(setup.SetupError):
                setup.unlock_key_file(path, ACCOUNT_PASSWORD)
            self.assertNotIn(LOCAL_PASSWORD, json.dumps(sent))
            self.assertEqual(sent[-1]['master_password'], ACCOUNT_PASSWORD)

    def test_admin_recovery_separates_local_key_password_from_account_password(self):
        account = {'role': 'ADMIN', 'user_id': 'admin-id'}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'admin.ratchet-key'
            with self.assertRaises(setup.SetupError):
                owner_console.recovery_operation(account, ACCOUNT_PASSWORD, path)
            self.assertFalse(path.exists())
            operation = owner_console.recovery_operation(account, ACCOUNT_PASSWORD, path, key_password=LOCAL_PASSWORD)
            setup.unlock_key_file(path, LOCAL_PASSWORD)
            with self.assertRaises(setup.SetupError):
                setup.unlock_key_file(path, ACCOUNT_PASSWORD)
            self.assertEqual(operation['new_password'], ACCOUNT_PASSWORD)
            self.assertNotIn(LOCAL_PASSWORD, json.dumps(operation))

    def test_admin_provisioning_keeps_both_local_key_passwords_off_the_wire(self):
        sent = []
        owner_password = 'Owner signing key local password!'
        def transport(origin, route, body, **kwargs):
            sent.append(body)
            if route.endswith('/prepare'):
                return {'challenge_id': 'id', 'challenge': 'challenge', 'origin': origin, 'key_id': body['owner_key_id'], 'purpose': 'ADMIN_PROVISIONING'}
            return {'role': 'ADMIN'}
        with tempfile.TemporaryDirectory() as directory, patch.object(setup, 'post_json', transport):
            owner = Path(directory) / 'owner.ratchet-key'
            admin = Path(directory) / 'admin.ratchet-key'
            document, _ = setup.create_key_document(owner_password)
            setup.write_key_file(owner, document)
            setup.provision_admin('https://ratchet.test', 't' * 32, owner, owner_password, 'admin', ACCOUNT_PASSWORD, admin, key_password=LOCAL_PASSWORD)
            setup.unlock_key_file(admin, LOCAL_PASSWORD)
            with self.assertRaises(setup.SetupError):
                setup.unlock_key_file(admin, ACCOUNT_PASSWORD)
            self.assertNotIn(LOCAL_PASSWORD, json.dumps(sent))
            self.assertNotIn(owner_password, json.dumps(sent))
            self.assertEqual(sent[-1]['master_password'], ACCOUNT_PASSWORD)

    def test_rewrapping_preserves_key_identity_and_leaves_original_backup_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / 'original.ratchet-key'
            replacement = Path(directory) / 'separate.ratchet-key'
            document, key = setup.create_key_document(ACCOUNT_PASSWORD)
            setup.write_key_file(original, document)
            original_bytes = original.read_bytes()
            setup.rewrap_key_file(original, ACCOUNT_PASSWORD, LOCAL_PASSWORD, replacement)
            key_id, restored = setup.unlock_key_file(replacement, LOCAL_PASSWORD)
            self.assertEqual(key_id, document['key_id'])
            self.assertEqual(restored.sign(b'migration'), key.sign(b'migration'))
            self.assertEqual(original.read_bytes(), original_bytes)
            with self.assertRaises(setup.SetupError):
                setup.unlock_key_file(replacement, ACCOUNT_PASSWORD)


if __name__ == '__main__':
    unittest.main()
