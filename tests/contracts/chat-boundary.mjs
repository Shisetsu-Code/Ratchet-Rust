import {test} from 'node:test';
import assert from 'node:assert/strict';
test('Rust chat routes enforce authentication before chat lookup',async()=>{
  const base=process.env.RATCHET_TEST_BASE;
  const response=await fetch(base+'/api/v1/chats/11111111-1111-4111-8111-111111111111/messages/sender-sequence');
  assert.equal(response.status,401);
  assert.equal((await response.json()).type,'SESSION_REQUIRED');
});
