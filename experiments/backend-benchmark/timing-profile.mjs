import assert from 'node:assert/strict';
function summary(values,unit='ms'){
 const a=[...values].sort((x,y)=>x-y),at=p=>a[Math.max(0,Math.ceil(a.length*p)-1)]??null;
 return{count:a.length,['mean'+(unit?'_'+unit:'')]:a.length?a.reduce((x,y)=>x+y,0)/a.length:null,['p50'+(unit?'_'+unit:'')]:at(.5),['p95'+(unit?'_'+unit:'')]:at(.95),['p99'+(unit?'_'+unit:'')]:at(.99),['max'+(unit?'_'+unit:'')]:a.at(-1)??null};
}
function nonnegative(value,label){assert.ok(typeof value==='number'&&Number.isFinite(value)&&value>=0,'Invalid '+label);}
function phases(record){assert.ok(record.phases_ms&&typeof record.phases_ms==='object'&&!Array.isArray(record.phases_ms));assert.ok(Object.keys(record.phases_ms).length>0);for(const [key,value]of Object.entries(record.phases_ms))nonnegative(value,key);return record.phases_ms;}
function phaseStats(samples){const keys=new Set(samples.flatMap(s=>Object.keys(s.phases_ms)));return Object.fromEntries([...keys].map(key=>{assert.ok(samples.every(s=>Object.hasOwn(s.phases_ms,key)),'Inconsistent phase '+key);return[key,summary(samples.map(s=>s.phases_ms[key]))];}));}
export function timingProfile(log,frames,expectedCount){
 const byId=new Map(frames.map(f=>[f.id,f])),chats=new Set(frames.map(f=>f.chat)),seen=new Set(),samples=[],batches=[];
 for(const line of log.split(/\r?\n/)){
  const marker=line.indexOf('RATCHET_TIMING ');if(marker<0)continue;
  const record=JSON.parse(line.slice(marker+'RATCHET_TIMING '.length).replace(/\u001b\[[0-9;]*m/g,''));
  if(!chats.has(record.chat_id))continue;
  if(record.kind==='message'){
   const f=byId.get(record.client_message_id);assert.ok(f,'Unknown message in case chat');assert.equal(record.sender_sequence,f.sequence);assert.ok(f.sequence>=2&&(f.sequence-1)%10===0,'Unsampled sequence');assert.ok(!seen.has(f.id),'Duplicate timing record');seen.add(f.id);
   nonnegative(record.total_ms,'total_ms');nonnegative(record.fanout,'fanout');nonnegative(f.ack_ms,'external ACK');
   samples.push({client_message_id:f.id,chat_id:f.chat,sender_sequence:f.sequence,phases_ms:phases(record),total_ms:record.total_ms,fanout:record.fanout,external_ack_ms:f.ack_ms,external_ack_residual_ms:f.ack_ms-record.total_ms});
  }else if(record.kind==='batch'){
   assert.ok(Number.isInteger(record.batch_size)&&record.batch_size>0,'Invalid batch size');batches.push({chat_id:record.chat_id,batch_size:record.batch_size,phases_ms:phases(record)});
  }else assert.fail('Unknown timing kind');
 }
 assert.equal(samples.length,expectedCount,'Expected exact sampled message count');
 assert.equal(frames.filter(f=>f.sequence>=2&&(f.sequence-1)%10===0).length,expectedCount,'Expected sampling schedule');
 return{count:samples.length,expected_count:expectedCount,sampling:'sender_sequence >= 2 and (sender_sequence - 1) % 10 == 0',phases_ms:phaseStats(samples),total_ms:summary(samples.map(s=>s.total_ms)),external_ack_ms:summary(samples.map(s=>s.external_ack_ms)),external_ack_residual_ms:summary(samples.map(s=>s.external_ack_residual_ms)),residual_tolerance_ms:1,residual_below_tolerance_count:samples.filter(s=>s.external_ack_residual_ms < -1).length,samples,batches:{count:batches.length,batch_size:summary(batches.map(b=>b.batch_size),''),phases_ms:phaseStats(batches),scope_note:'Case chat IDs only; batch records can include warmup or unsampled jobs sharing a sampled batch. Batch phase durations are shared and must not be added to message timings.',samples:batches}};
}
