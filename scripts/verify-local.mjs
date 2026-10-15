import {spawn} from 'node:child_process';

// Local acceptance only: no package installation, remote services, or deployments.
const commands=[
 [process.execPath,['scripts/check-toolchain.mjs']],
 ['cargo',['fmt','--all','--check']],
 ['cargo',['clippy','--workspace','--all-targets','--locked','--offline','--','-D','warnings']],
 ['cargo',['clippy','-p','ratchet-worker','--target','wasm32-unknown-unknown','--locked','--offline','--','-D','warnings']],
 ['cargo',['test','--workspace','--locked','--offline']],
 ['cargo',['test','--manifest-path','crypto-wasm/Cargo.toml','--locked','--offline']],
 [process.execPath,['--test','tests/tooling/*.test.mjs']],
 [process.execPath,['node_modules/typescript/bin/tsc','-p','tsconfig.client.json','--noEmit']],
 [process.execPath,['scripts/build-crypto.mjs']],
 [process.execPath,['node_modules/vite/bin/vite.js','build']],
 [process.execPath,['scripts/build-worker.mjs']],
 [process.execPath,['scripts/run-contracts.mjs']],
];
for(const[command,args]of commands){
 console.log('VERIFY '+[command,...args].join(' '));
 const child=spawn(command,args,{stdio:'inherit',windowsHide:true});
 const code=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',resolve);});
 if(code!==0)process.exit(code??1);
}
console.log('Local acceptance passed. No deployment performed.');
