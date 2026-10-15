import test from 'node:test';
import assert from 'node:assert/strict';
import {timingProfile} from './timing-profile.mjs';
const message={kind:'message',client_message_id:'m',chat_id:'c',sender_sequence:11,phases_ms:{decode:2,commit:4},total_ms:8,fanout:21};
const batch={kind:'batch',chat_id:'c',batch_size:4,phases_ms:{lane_wait:1,projection:2,durable_sync:3,publication_barrier:4}};
const frames=[{id:'m',chat:'c',sequence:11,ack_ms:12},{id:'u',chat:'c',sequence:2,ack_ms:10}];
const log=(...values)=>'ordinary log\n'+values.map(v=>'[worker] RATCHET_TIMING '+JSON.stringify(v)).join('\n');
test('joins sampled IDs to real ACKs and excludes other cases',()=>{
 const p=timingProfile(log(message,batch,{...message,client_message_id:'other',chat_id:'other'}),frames,1);
 assert.equal(p.count,1);assert.equal(p.phases_ms.commit.mean_ms,4);assert.equal(p.external_ack_residual_ms.mean_ms,4);assert.equal(p.samples[0].external_ack_ms,12);assert.equal(p.batches.count,1);assert.equal(p.batches.batch_size.mean,4);
});
test('rejects missing, duplicate, invalid, or unsampled records',()=>{
 for(const records of [[],[message,message],[{...message,total_ms:-1}],[{...message,phases_ms:{decode:null}}],[{...message,client_message_id:'u',sender_sequence:2}]])assert.throws(()=>timingProfile(log(...records),frames,1));
});
test('retains small negative clock residuals and reports tolerance violations',()=>{
 const p=timingProfile(log({...message,total_ms:12.5}),frames,1);
 assert.equal(p.samples[0].external_ack_residual_ms,-0.5);assert.equal(p.residual_below_tolerance_count,0);
 assert.equal(timingProfile(log({...message,total_ms:15}),frames,1).residual_below_tolerance_count,1);
});
test('rejects malformed timing JSON and batch numeric values',()=>{
 assert.throws(()=>timingProfile('RATCHET_TIMING {bad}',frames,1));
 assert.throws(()=>timingProfile(log(message,{...batch,batch_size:0}),frames,1));
});
