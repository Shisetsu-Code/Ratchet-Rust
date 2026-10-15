import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const result=spawnSync('worker-build',['--release','--no-opt'],{cwd:fileURLToPath(new URL('../crates/worker/',import.meta.url)),stdio:'inherit',windowsHide:true});
if(result.error)throw result.error;
process.exitCode=result.status??1;
