import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createRecoveryPump} from '../../src/client/chat/recovery-pump.ts';
function clock(){const jobs=new Map(),delays=[];let next=0;return{jobs,delays,schedule(fn,ms){jobs.set(++next,fn);delays.push(ms);return next;},cancel(id){jobs.delete(id);},async tick(){const [id,fn]=jobs.entries().next().value; jobs.delete(id);await fn();}};}
test('automatically retries pending work with bounded backoff and stops when committed',async()=>{
 const c=clock();let calls=0;const pump=createRecoveryPump(async()=>++calls<7,assert.fail,c.schedule,c.cancel);
 pump.request();pump.request();assert.equal(c.jobs.size,1);
 while(c.jobs.size)await c.tick();assert.equal(calls,7);assert.deepEqual(c.delays,[2000,4000,8000,16000,30000,30000,30000]);
});
test('does not overlap runs and disposal prevents rescheduling in-flight work',async()=>{
 const c=clock();let finish,calls=0;const pump=createRecoveryPump(()=>{calls++;return new Promise(resolve=>{finish=resolve;});},assert.fail,c.schedule,c.cancel);
 pump.request();const pending=c.tick();pump.request();pump.request();assert.equal(calls,1);assert.equal(c.jobs.size,0);pump.stop();finish(true);await pending;assert.equal(c.jobs.size,0);pump.request();assert.equal(c.jobs.size,0);
});
test('unexpected errors are reported once rather than retried forever',async()=>{
 const c=clock(),errors=[];const failure=Error('permanent');const pump=createRecoveryPump(async()=>{throw failure;},error=>errors.push(error),c.schedule,c.cancel);
 pump.request();await c.tick();assert.deepEqual(errors,[failure]);assert.equal(c.jobs.size,0);
});
test('a new request arriving during completion is not lost',async()=>{
 const c=clock();let finish;const pump=createRecoveryPump(()=>new Promise(resolve=>{finish=resolve;}),assert.fail,c.schedule,c.cancel);
 pump.request();const pending=c.tick();pump.request();finish(false);await pending;assert.equal(c.jobs.size,1);pump.stop();assert.equal(c.jobs.size,0);
});
