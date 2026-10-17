import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {DatabaseSync} from 'node:sqlite';

async function budgets() {
  const db=new DatabaseSync(':memory:');
  db.exec(await readFile('crates/worker/src/chat/realtime-limits.sql','utf8'));
  const insert=db.prepare(await readFile('crates/worker/src/chat/admit-frame.sql','utf8'));
  const source=await readFile('crates/worker/src/chat/realtime_limits.rs','utf8');
  const cleanup=db.prepare(source.match(/"(DELETE FROM websocket_frame_budgets WHERE expires_at<=\?)"/)[1]);
  const admit=(user,device,bytes=15,now=1000)=>{
    cleanup.run(now);
    return insert.all({'?1':JSON.stringify(['device',user,device]),'?2':JSON.stringify(['user',user]),'?3':now,'?4':bytes}).length===3;
  };
  const snapshot=()=>db.prepare('SELECT * FROM websocket_frame_budgets ORDER BY scope').all();
  return {db,admit,snapshot};
}

test('frame admission is atomic across device, user and room budgets',async()=>{
  const {db,admit,snapshot}=await budgets();
  try {
    for(let i=0;i<240;i++)assert.equal(admit('user','device'),true);
    const before=snapshot();
    assert.equal(admit('user','device'),false);
    assert.deepEqual(snapshot(),before,'denial must not partially debit other scopes');
    assert.equal(admit('user','another-device'),true);
  }finally{db.close();}
});

test('the byte budget applies independently of frame count',async()=>{
  const {db,admit,snapshot}=await budgets();
  try {
    for(let i=0;i<8;i++)assert.equal(admit('user','device',1024*1024),true);
    const before=snapshot();
    assert.equal(admit('user','device',1),false);
    assert.deepEqual(snapshot(),before);
  }finally{db.close();}
});

test('rotating devices cannot evade the user budget and room traffic is bounded',async()=>{
  const {db,admit}=await budgets();
  try {
    for(const device of ['one','two'])for(let i=0;i<240;i++)assert.equal(admit('user',device),true);
    assert.equal(admit('user','three'),false);
    let accepted=480;
    for(let user=0;user<20;user++)for(let i=0;i<200;i++)if(admit('other-'+user,'device'))accepted++;
    assert.equal(accepted,4096);
    assert.equal(admit('final-user','new-device'),false);
  }finally{db.close();}
});

test('identity churn cannot grow retained counters and expiry restores admission',async()=>{
  const {db,admit,snapshot}=await budgets();
  try {
    for(let i=0;i<511;i++)assert.equal(admit('user-'+i,'device'),true);
    assert.equal(snapshot().length,1023);
    assert.equal(admit('overflow','device'),false);
    assert.equal(snapshot().length,1023);
    assert.equal(admit('user-0','device'),true,'live counters remain usable at the row ceiling');
    assert.equal(admit('overflow','device',15,11000),true);
    assert.equal(snapshot().length,3);
  }finally{db.close();}
});
