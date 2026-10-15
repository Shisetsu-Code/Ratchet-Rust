import {readFileSync,existsSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {join} from 'node:path';
import {homedir} from 'node:os';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('../',import.meta.url));
const manifest=readFileSync(new URL('../crypto-wasm/Cargo.toml',import.meta.url),'utf8');
const version=manifest.match(/^wasm-bindgen\s*=\s*"=([^"]+)"/m)?.[1];
if(!version)throw Error('wasm-bindgen must be pinned');
const windows=process.platform==='win32';
const cache=windows?join(process.env.LOCALAPPDATA??join(homedir(),'AppData','Local'),'worker-build',`wasm-bindgen-x86_64-pc-windows-msvc-${version}`,'wasm-bindgen.exe'):'';
const cli=process.env.WASM_BINDGEN_CLI||(cache&&existsSync(cache)?cache:'wasm-bindgen');
const check=spawnSync(cli,['--version'],{cwd:root,encoding:'utf8',windowsHide:true});
if(check.status!==0||check.stdout.trim()!==`wasm-bindgen ${version}`)throw Error(`Matching wasm-bindgen ${version} is required; set WASM_BINDGEN_CLI to an existing executable. No tool was installed.`);
function run(command,args){const result=spawnSync(command,args,{cwd:root,stdio:'inherit',windowsHide:true});if(result.error)throw result.error;if(result.status!==0)throw Error(`${command} exited ${result.status}`);}
run('cargo',['build','--manifest-path','crypto-wasm/Cargo.toml','--target','wasm32-unknown-unknown','--release','--locked']);
run(cli,['crypto-wasm/target/wasm32-unknown-unknown/release/ratchet_crypto_wasm.wasm','--target','web','--out-dir','src/client/crypto/wasm/generated','--out-name','ratchet_crypto_wasm']);
