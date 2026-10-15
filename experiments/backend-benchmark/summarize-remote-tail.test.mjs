import {test} from 'node:test';
import assert from 'node:assert/strict';
import {parseTail} from './summarize-remote-tail.mjs';
test('parses concatenated multiline records and braces inside escaped strings',()=>{
 const event={cpuTime:2,wallTime:4,outcome:'ok',event:{request:{url:'https://example.test/api?secret=hidden'}},logs:[{message:['quoted " } { \\ string']}]};
 const parsed=parseTail(JSON.stringify(event,null,2)+'\n'+JSON.stringify(event));assert.equal(parsed.length,2);assert.equal(parsed[0].cpu_ms,2);assert.equal(parsed[0].path,'/api');assert.ok(!JSON.stringify(parsed).includes('hidden'));
});
test('ignores an incomplete final record while tail is still writing',()=>{assert.equal(parseTail('{"cpuTime":1}\n{"cpuTime":').length,1);});
