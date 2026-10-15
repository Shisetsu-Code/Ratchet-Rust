import { createHash } from 'node:crypto';
import { readdir, readFile, mkdir, writeFile, copyFile } from 'node:fs/promises';
import { dirname, join, posix, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const roots = ['src/client', 'src/shared', 'src/worker', 'public', 'migrations', 'crypto-wasm', 'tools/owner_setup'];
const extensions = /\.(?:ts|tsx|js|mjs|css|html|svg|png|webp|gif|ico|wasm|sql|rs|toml|lock|json|py|ps1|md)$/i;
const forbidden = /(?:^|\/)(?:node_modules|target|dist|\.git|\.wrangler|__pycache__)(?:\/|$)|(?:private|secret|password|credential|\.dev\.vars|\.env)(?:\.|$)/i;

async function filesUnder(root, path) {
  const found = [];
  let entries;
  try { entries = await readdir(join(root, path), { withFileTypes: true }); }
  catch (error) { if (error.code === 'ENOENT') return found; throw error; }
  for (const entry of entries) {
    const file = `${path}/${entry.name}`;
    if (entry.isSymbolicLink() || forbidden.test(file)) continue;
    if (entry.isDirectory()) found.push(...await filesUnder(root, file));
    else if (entry.isFile() && extensions.test(file)) found.push(file);
  }
  return found.sort();
}

function inventory(sources) {
  const modules = new Map();
  for (const [file, body] of sources) {
    const imports = new Map();
    for (const match of body.matchAll(/import\s*\{([^}]+)\}\s*from\s*['"]([^'"]+)['"]/g)) {
      if (!match[2].startsWith('.')) continue;
      const target = posix.normalize(posix.join(posix.dirname(file), `${match[2]}.ts`));
      for (const item of match[1].split(',')) {
        const [name, local = name] = item.trim().split(/\s+as\s+/);
        imports.set(local, { file: target, name });
      }
    }
    const declarations = [...body.matchAll(/^\s*([\w]+)\.(get|post|put|patch|delete|all|route)\(\s*['"]([^'"]*)['"]\s*(?:,\s*([\w]+))?/gm)]
      .map(match => ({ router: match[1], method: match[2], path: match[3], child: match[4], line: body.slice(0, match.index).split('\n').length }));
    modules.set(file, { imports, declarations });
  }
  const routes = [];
  const seen = new Set();
  function visit(file, router, prefix, chain = []) {
    const identity = `${file}#${router}`;
    if (chain.includes(identity)) throw new Error(`Router cycle: ${identity}`);
    const module = modules.get(file);
    if (!module) throw new Error(`Missing route source ${file}`);
    for (const route of module.declarations.filter(r => r.router === router)) {
      const path = `${prefix}/${route.path}`.replace(/\/+/g, '/').replace(/\/$/, '') || '/';
      if (route.method === 'route') {
        const child = module.imports.get(route.child) ?? { file, name: route.child };
        visit(child.file, child.name, path, [...chain, identity]);
      } else {
        const key = `${route.method}:${path}`;
        routes.push({ method: route.method.toUpperCase(), path, source: file, line: route.line, shadowed: seen.has(key), implementation: 'pending' });
        seen.add(key);
      }
    }
  }
  visit('src/worker/index.ts', 'app', '');
  return routes;
}

export async function captureBaseline(source, output) {
  source = resolve(source); output = resolve(output);
  if (source === output || output.startsWith(`${source}/`) || output.startsWith(`${source}\\`)) throw new Error('Output must be outside source');
  const files = [];
  const workerSources = new Map();
  for (const root of roots) {
    for (const path of await filesUnder(source, root)) {
      const data = await readFile(join(source, path));
      files.push({ path, sha256: createHash('sha256').update(data).digest('hex'), bytes: data.length });
      if (path.startsWith('src/worker/')) { workerSources.set(path, data.toString('utf8')); continue; }
      // Historical migrations are provenance only; Rust starts with its own consolidated schema.
      if (path.startsWith('migrations/')) continue;
      // The Rust console has its own launcher and must not restore old deployment defaults.
      if (path.startsWith('tools/owner_setup/')) continue;
      await mkdir(dirname(join(output, path)), { recursive: true });
      await copyFile(join(source, path), join(output, path));
    }
  }
  for (const path of ['index.html', 'tsconfig.json', 'tsconfig.base.json', 'tsconfig.client.json']) {
    let data;
    try { data=await readFile(join(source,path)); } catch(error) {if(error.code==='ENOENT')continue;throw error;}
    files.push({path,sha256:createHash('sha256').update(data).digest('hex'),bytes:data.length});
    await copyFile(join(source,path),join(output,path));
  }
  await mkdir(join(output, 'baseline'), { recursive: true });
  await writeFile(join(output, 'baseline/source-manifest.json'), JSON.stringify({ format: 1, source: 'Ratchet-SQLite local working tree', files }, null, 2) + '\n');
  await writeFile(join(output, 'baseline/routes.json'), JSON.stringify(inventory(workerSources), null, 2) + '\n');
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (!process.argv[2]) throw new Error('Usage: node scripts/capture-baseline.mjs SOURCE [OUTPUT]');
  await captureBaseline(process.argv[2], process.argv[3] ?? process.cwd());
  console.log('Baseline captured without private data or TypeScript backend runtime.');
}
