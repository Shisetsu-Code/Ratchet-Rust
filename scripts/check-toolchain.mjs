import {spawnSync} from 'node:child_process';

const run=(command,args)=>{
  const result=spawnSync(command,args,{encoding:'utf8',windowsHide:true,timeout:15000});
  return {ok:result.status===0,text:(result.stdout??'').trim()};
};
const installed=run('rustup',['toolchain','list']);
const hasRust=installed.ok&&installed.text.split('\n').some(line=>line.startsWith('1.99.0-'));
const builder=run('worker-build',['--version']);
const missing=[];
if(!hasRust)missing.push('Rust 1.99.0');
if(!builder.ok||!/\b0\.8\.7\b/.test(builder.text))missing.push('worker-build 0.8.7');
if(hasRust){
  const targets=run('rustup',['target','list','--installed','--toolchain','1.99.0']);
  if(!targets.ok||!targets.text.includes('wasm32-unknown-unknown'))missing.push('wasm32-unknown-unknown for Rust 1.99.0');
  const components=run('rustup',['component','list','--installed','--toolchain','1.99.0']);
  for(const component of ['clippy','rustfmt'])if(!components.ok||!components.text.includes(component))missing.push(component+' for Rust 1.99.0');
}
console.log(JSON.stringify({ready:missing.length===0,missing,installsPerformed:false},null,2));
if(missing.length)process.exitCode=2;
