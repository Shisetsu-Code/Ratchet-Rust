import {readFile,writeFile,mkdir,readdir,copyFile} from 'node:fs/promises';
import {resolve,join,dirname,sep} from 'node:path';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import assert from 'node:assert/strict';

const output=resolve(process.argv[2]??'');
assert.ok(output.startsWith(resolve('.wrangler')+sep),'Choose a fresh artifact directory inside .wrangler');
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const build=resolve('crates/worker/build');
const entry=await readFile(join(build,'index.js')),wasm=await readFile(join(build,'index_bg.wasm'));
const files=(await readdir('crates',{recursive:true})).filter(path=>/^(core|worker)[\\/]src[\\/].*\.(rs|sql)$/.test(path)).sort();
const hashes=await Promise.all(files.map(async path=>[path.replaceAll('\\','/'),sha(await readFile(join('crates',path)))]));
const artifact={commit:execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim(),wasm_sha256:sha(wasm),entry_sha256:sha(entry),rust_source_files:Object.fromEntries(hashes),rust_source_sha256:sha(JSON.stringify(hashes))};
await mkdir(dirname(output),{recursive:true});
await mkdir(output); // Refuse to overwrite an existing comparison artifact.
for(const file of ['index.js','index_bg.wasm'])await copyFile(join(build,file),join(output,file));
await writeFile(join(output,'artifact.json'),JSON.stringify(artifact,null,2)+'\n');
console.log('Captured built Rust artifact:',artifact.commit,artifact.wasm_sha256);
