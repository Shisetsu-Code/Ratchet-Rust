import {generateKeyPairSync,randomBytes} from 'node:crypto';
import {writeFile,readFile} from 'node:fs/promises';
const path='.dev.vars.staging.json';
try{JSON.parse(await readFile(path,'utf8'));console.log('Existing staging secrets preserved.');}
catch(error){
  if(error.code!=='ENOENT')throw error;
  const pair=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),key=pair.privateKey.export({format:'jwk'});
  const values={BOOTSTRAP_TOKEN:randomBytes(32).toString('hex'),MESSAGE_STORAGE_KEY:randomBytes(32).toString('base64url'),VAPID_PRIVATE_KEY:key.d,VAPID_PUBLIC_KEY:Buffer.concat([Buffer.from([4]),Buffer.from(key.x,'base64url'),Buffer.from(key.y,'base64url')]).toString('base64url'),VAPID_SUBJECT:'https://github.com/Shisetsu-Code/Ratchet-Rust'};
  await writeFile(path,JSON.stringify(values,null,2)+'\n',{flag:'wx',mode:0o600});
  console.log('New staging secrets saved locally; values are not printed.');
}
