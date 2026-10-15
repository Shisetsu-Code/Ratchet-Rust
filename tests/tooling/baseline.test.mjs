import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { captureBaseline } from '../../scripts/capture-baseline.mjs';

test('captures local changes and excludes secrets, caches and runtime backend copies', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ratchet-baseline-'));
  try {
    const source = join(root, 'source');
    const output = join(root, 'output');
    for (const dir of ['src/client', 'src/worker', 'src/shared', 'public', 'node_modules', 'tools/owner_setup']) await mkdir(join(source, dir), { recursive: true });
    for (const [path, content] of Object.entries({
      'src/client/app.ts': 'local edit',
      'src/worker/index.ts': "import { chats } from './routes';\napp.route('/api/v1/chats', chats);",
      'src/worker/routes.ts': "export const chats = new Hono();\nchats.get('/:id', handler);\nchats.post('/', handler);",
      'src/shared/example.ts': 'contract',
      '.dev.vars': 'TOP_SECRET',
      'public/private.json': 'TOP_SECRET',
      'node_modules/example': 'TOP_SECRET',
      'tools/owner_setup/password.txt': 'TOP_SECRET',
    })) await writeFile(join(source, path), content);
    await captureBaseline(source, output);
    assert.equal(await readFile(join(output, 'src/client/app.ts'), 'utf8'), 'local edit');
    const manifest = JSON.parse(await readFile(join(output, 'baseline/source-manifest.json'), 'utf8'));
    assert.equal(manifest.files.find(f => f.path === 'src/worker/routes.ts').sha256.length, 64);
    assert.ok(!manifest.files.some(f => /dev.vars|private.json|node_modules|password.txt/.test(f.path)));
    await assert.rejects(readFile(join(output, 'src/worker/index.ts')), { code: 'ENOENT' });
    const routes = JSON.parse(await readFile(join(output, 'baseline/routes.json'), 'utf8'));
    assert.ok(routes.some(r => r.method === 'GET' && r.path === '/api/v1/chats/:id'));
    await writeFile(join(source, 'src/client/app.ts'), 'new local edit');
    await captureBaseline(source, output);
    const changed = JSON.parse(await readFile(join(output, 'baseline/source-manifest.json'), 'utf8'));
    assert.notEqual(manifest.files.find(f => f.path === 'src/client/app.ts').sha256, changed.files.find(f => f.path === 'src/client/app.ts').sha256);
  } finally { await rm(root, { recursive: true, force: true }); }
});
