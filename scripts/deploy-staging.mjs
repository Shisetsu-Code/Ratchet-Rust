import {spawnSync} from 'node:child_process';
import {readFile} from 'node:fs/promises';
const config='wrangler.staging.jsonc';
const target=JSON.parse(await readFile(config,'utf8'));
if(!target.name.startsWith('ratchet-rust-staging-')||target.d1_databases.some(b=>!b.database_name.startsWith('ratchet-rust-staging-'))||target.r2_buckets.some(b=>!b.bucket_name.startsWith('ratchet-rust-staging-')))throw Error('Only the isolated Ratchet-Rust staging may be deployed by this script.');
function run(command,args){const r=spawnSync(command,args,{stdio:'inherit',windowsHide:true});if(r.error)throw r.error;if(r.status!==0)throw Error(`${command} failed (${r.status})`);}
const node=process.execPath,wrangler='node_modules/wrangler/bin/wrangler.js';
run(node,['scripts/check-toolchain.mjs']);
if(!process.argv.includes('--skip-build')){
 run(node,['scripts/build-crypto.mjs']);
 run(node,['node_modules/vite/bin/vite.js','build']);
 run(node,['scripts/build-worker.mjs']);
}
run(node,['scripts/create-staging-secrets.mjs']);
run(node,[wrangler,'deploy','--dry-run','--config',config,'--outdir','.wrangler/staging-dry-run']);
run(node,[wrangler,'d1','migrations','apply','DB','--remote','--config',config]);
run(node,[wrangler,'deploy','--config',config,'--secrets-file','.dev.vars.staging.json']);
