import { test } from 'node:test';
import assert from 'node:assert/strict';
import { boundVisibleMessages, rememberVisibleChat } from '../../src/client/chat/message-window.ts';

test('a long live conversation keeps only a bounded plaintext window', () => {
  let current = [];
  for (let revision = 1; revision <= 20_000; revision++) current = boundVisibleMessages([...current, { revision, text: 'message', attachments: [] }]);
  assert.ok(current.length <= 80);
  assert.equal(current.at(-1).revision, 20_000);
  assert.deepEqual(current.map(message => message.revision), Array.from({ length: current.length }, (_, index) => 20_001 - current.length + index));
});

test('plaintext byte limits apply even when every message is a valid large text', () => {
  const current = boundVisibleMessages(Array.from({ length: 80 }, (_, revision) => ({ revision, text: 'x'.repeat(100_000), attachments: [] })));
  assert.ok(current.length < 80);
  assert.ok(current.reduce((bytes, message) => bytes + message.text.length * 2, 0) <= 2 * 1024 * 1024);
  assert.equal(current.at(-1).revision, 79);
});

test('switching many chats evicts old plaintext views while retaining recent windows', () => {
  const cache = new Map();
  for (let chat = 0; chat < 100; chat++) rememberVisibleChat(cache, String(chat), [{ revision: chat, text: 'message', attachments: [] }]);
  assert.ok(cache.size <= 2);
  assert.ok(cache.has('99'));
  rememberVisibleChat(cache, '98', [{ revision: 1, text: 'updated', attachments: [] }]);
  rememberVisibleChat(cache, '100', []);
  assert.deepEqual([...cache.keys()], ['98', '100']);
});
