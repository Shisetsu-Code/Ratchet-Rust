import { DatabaseSync } from 'node:sqlite';
import { readdir,readFile,mkdir,writeFile,access } from 'node:fs/promises';
import { join,resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

// Reads definitions only into an in-memory empty database. Never opens user data.
export async function freshSchema(source) {
  const db=new DatabaseSync(':memory:');
  try {
    for(const file of (await readdir(join(source,'migrations'))).filter(f=>/^\d+.*\.sql$/.test(f)).sort()) {
      db.exec(await readFile(join(source,'migrations',file),'utf8'));
    }
    const retired=new Set(['messages','message_device_envelopes','message_recovery_envelopes','message_mutations',
      'message_receipts','message_attachment_claims','chat_sender_sequences','chat_event_outbox',
      'bootstrap_webauthn_challenges','account_recovery_keys']);
    const rows=db.prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY CASE type WHEN 'table' THEN 0 WHEN 'index' THEN 1 WHEN 'view' THEN 2 ELSE 3 END,name").all();
    const statements=rows.filter(row=>!retired.has(row.name)&&!retired.has(row.tbl_name)).map(row=>row.sql.replace(/\s+REFERENCES messages\(message_id\)/g,'')+';');
    return '-- Fresh Ratchet Rust installation. No history import or legacy D1 message storage.\nPRAGMA foreign_keys=ON;\n\n'+statements.join('\n\n')+'\n';
  }finally{db.close();}
}

if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  if(!process.argv[2])throw new Error('Usage: node scripts/prepare-fresh-schema.mjs SOURCE');
  // This is the initial capture tool, never a regeneration of the maintained Rust schema.
  try{await access('db/migrations/0001_ratchet_rust.sql');throw new Error('Rust schema already exists; edit its maintained migration instead.');}
  catch(error){if(error.code!=='ENOENT')throw error;}
  const schema=await freshSchema(resolve(process.argv[2]));
  await mkdir('db/migrations',{recursive:true});
  await writeFile('db/migrations/0001_ratchet_rust.sql',schema);
  console.log('Fresh schema generated from definitions; no user data copied.');
}
