import {readdir} from 'node:fs/promises';
import {join} from 'node:path';
import {DatabaseSync} from 'node:sqlite';

/** Verify durable local state rather than trusting a successful Wrangler exit. */
export async function assertLocalMigrations(state,expectedNames){
  if(expectedNames.length===0)throw new Error('No expected local migrations were found');
  const directory=join(state,'v3','d1','miniflare-D1DatabaseObject');
  const databases=[];
  for(const name of(await readdir(directory)).filter(name=>name.endsWith('.sqlite'))){
    const path=join(directory,name),db=new DatabaseSync(path,{readOnly:true});
    try{
      if(!db.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='d1_migrations'").get())continue;
      databases.push({path,names:db.prepare('SELECT name FROM d1_migrations ORDER BY id').all().map(row=>row.name)});
    }finally{db.close();}
  }
  if(databases.length!==1)throw new Error(`Expected one migrated local D1 database; found ${databases.length}`);
  const {names}=databases[0],applied=new Set(names),expected=new Set(expectedNames);
  const missing=expectedNames.filter(name=>!applied.has(name));
  const unexpected=names.filter(name=>!expected.has(name));
  if(missing.length||unexpected.length)throw new Error(`Local migration postcondition failed: missing [${missing.join(', ')}]; unexpected [${unexpected.join(', ')}]. Wrangler success is not sufficient; inspect ${join(state,'migrations.log')}`);
  return names;
}
