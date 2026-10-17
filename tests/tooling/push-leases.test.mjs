import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {DatabaseSync} from 'node:sqlite';

async function queue(){
  const source=await readFile('crates/worker/src/files/push.rs','utf8');
  const claim=source.match(/changed\(&?db,"(UPDATE push_wakeups SET lease_token=\?2[^"]+)"/)[1];
  const remove=source.match(/db\.statement\("(DELETE FROM push_wakeups WHERE subscription_id=\?1[^"]+)"/)[1];
  const release=source.match(/db\.statement\("(UPDATE push_wakeups SET lease_token=NULL[^"]+)"/)[1];
  const db=new DatabaseSync(':memory:');
  db.exec('CREATE TABLE push_wakeups(subscription_id TEXT PRIMARY KEY,generation INTEGER DEFAULT 1,lease_token TEXT,lease_until INTEGER DEFAULT 0,next_attempt_at INTEGER DEFAULT 0,attempts INTEGER DEFAULT 0,requested_at INTEGER DEFAULT 0)');
  for(let id=0;id<40;id++)db.prepare('INSERT INTO push_wakeups(subscription_id) VALUES(?)').run(String(id));
  return{db,claim:db.prepare(claim),remove:db.prepare(remove),release:db.prepare(release)};
}

test('slow later waves retain their leases while two other dispatchers compete for eight global slots',async()=>{
  const{db,claim,release}=await queue();
  const providers=new Map();
  const start=(id,now)=>{
    const token=`${id}:${now}`;
    const accepted=claim.run({'?1':String(id),'?2':token,'?3':now+30000,'?4':now}).changes;
    if(accepted)providers.set(id,{token,ends:now+9000});
    return accepted;
  };
  const finish=now=>{
    for(const[id,provider]of providers)if(provider.ends<=now){
      release.run({'?1':String(id),'?2':provider.token,'?3':now});providers.delete(id);
    }
  };
  try{
    for(const now of [0,9000,18000,27000]){
      finish(now);
      for(let id=0;id<4;id++)assert.equal(start(now/9000*4+id,now),1);
    }
    // The fourth wave still runs until36s. At31s neither the same rows nor
    // more than four other provider calls can be admitted by competing jobs.
    for(let id=12;id<16;id++)assert.equal(start(id,31000),0);
    for(let id=16;id<20;id++)assert.equal(start(id,31000),1);
    for(let id=20;id<32;id++)assert.equal(start(id,31000),0);
    assert.equal(providers.size,8);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM push_wakeups WHERE lease_until>?').get(31000).n,8);
    finish(36000);
    for(let id=20;id<24;id++)assert.equal(start(id,36000),1);
    assert.equal(providers.size,8);
  }finally{db.close();}
});

test('a resumed stale owner cannot delete or release a newly reclaimed push lease',async()=>{
  const{db,claim,remove,release}=await queue();
  try{
    assert.equal(claim.run({'?1':'0','?2':'old','?3':30000,'?4':0}).changes,1);
    assert.equal(claim.run({'?1':'0','?2':'new','?3':61000,'?4':31000}).changes,1);
    assert.equal(remove.run({'?1':'0','?2':'old','?3':1}).changes,0);
    assert.equal(release.run({'?1':'0','?2':'old','?3':31001}).changes,0);
    assert.deepEqual({...db.prepare("SELECT lease_token,lease_until FROM push_wakeups WHERE subscription_id='0'").get()},{lease_token:'new',lease_until:61000});
  }finally{db.close();}
});
