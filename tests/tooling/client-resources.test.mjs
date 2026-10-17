import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'vite';
import { chromium } from '@playwright/test';

let server, browser, origin;
before(async () => {
  server = await createServer({ server: { host: '127.0.0.1', port: 0 }, plugins: [{
    name: 'isolated-client-tests',
    configureServer(vite) {
      vite.middlewares.use('/__client-tests__', async (_request, response) => {
        response.setHeader('Content-Type', 'text/html');
        response.end(await vite.transformIndexHtml('/__client-tests__', '<!doctype html><html><body><div id="test-root"></div></body></html>'));
      });
    },
  }] });
  await server.listen();
  origin = `http://127.0.0.1:${server.httpServer.address().port}`;
  browser = await chromium.launch({ channel: 'chrome', headless: true });
});
after(async () => { await browser?.close(); await server?.close(); });

async function inBrowser(run) {
  const context = await browser.newContext();
  const page = await context.newPage();
  try {
    await page.goto(`${origin}/__client-tests__`);
    return await page.evaluate(run);
  } finally { await context.close(); }
}

test('a cached chat load limits records before decrypting a long history', { timeout: 60_000 }, async () => {
  const result = await inBrowser(async () => {
    const { openLocalDatabase } = await import('/src/client/storage/db.ts');
    const { sealMessageCacheRecord, loadCachedMessagesResilient } = await import('/src/client/storage/message-cache.ts');
    const db = await openLocalDatabase();
    const master = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const chat = crypto.randomUUID(), sender = crypto.randomUUID(), device = crypto.randomUUID();
    for (let revision = 1; revision <= 250; revision++) {
      const id = crypto.randomUUID();
      const sealed = await sealMessageCacheRecord(master, chat, `message:${id}`, {
        direction: 'INCOMING', message_id: id, client_message_id: id,
        sender_user_id: sender, sender_device_id: device,
        revision, created_at: new Date().toISOString(),
      }, new TextEncoder().encode(`message ${revision}`));
      await db.put('encrypted_cache', sealed);
    }
    const calls = [];
    const boundedDb = new Proxy(db, { get(target, name) {
      if (name === 'getAllFromIndex') return async (...args) => { calls.push(args); return target.getAllFromIndex(...args); };
      const value = target[name]; return typeof value === 'function' ? value.bind(target) : value;
    } });
    const loaded = await loadCachedMessagesResilient(boundedDb, master, chat);
    db.close();
    return { count: loaded.messages.length, last: loaded.messages.at(-1)?.revision, unboundedReads: calls.filter(args => args[3] === undefined).length };
  });
  assert.ok(result.count <= 80, `loaded ${result.count} plaintext messages`);
  assert.equal(result.last, 250);
  assert.equal(result.unboundedReads, 0);
});

test('mounting remote attachments does not download their complete encrypted files', { timeout: 60_000 }, async () => {
  const result = await inBrowser(async () => {
    const reactModule = await import('/node_modules/.vite/deps/react.js');
    const React = reactModule.default ?? reactModule;
    const domModule = await import('/node_modules/.vite/deps/react-dom_client.js');
    const { createRoot } = domModule.default ?? domModule;
    const { MessageBubble } = await import('/src/client/app/MessageBubble.tsx');
    const { ATTACHMENT_CHUNK_PLAINTEXT_BYTES } = await import('/src/shared/contracts/attachments.ts');
    let requests = 0;
    const originalFetch = window.fetch;
    window.fetch = async (...args) => {
      if (String(args[0]).includes('/api/v1/attachments/')) {
        requests++;
        return new Response(JSON.stringify({ type: 'NOT_FOUND', title: 'fixture', status: 404, retryable: false }), { status: 404, headers: { 'Content-Type': 'application/json' } });
      }
      return originalFetch(...args);
    };
    const attachments = Array.from({ length: 16 }, () => ({ version: 1, file_id: crypto.randomUUID(), file_key: 'A'.repeat(43), nonce_prefix: 'A'.repeat(22), plaintext_size: 10 * 1024 * 1024, chunk_plaintext_bytes: ATTACHMENT_CHUNK_PLAINTEXT_BYTES }));
    const root = createRoot(document.getElementById('test-root'));
    root.render(React.createElement(MessageBubble, { message: {
      cache_key: 'fixture', chat_id: crypto.randomUUID(), client_message_id: crypto.randomUUID(),
      message_id: crypto.randomUUID(), sender_user_id: crypto.randomUUID(), sender_device_id: crypto.randomUUID(),
      revision: 1, direction: 'INCOMING', text: 'many attachments', attachments,
      mutation: null, reply_to_message_id: null, receipt_state: null, created_at: new Date().toISOString(),
    }, senderLabel: 'Fixture', isCustomer: true, localFiles: new Map(), onReply() {}, onMutate() {}, onPreview() {} }));
    await new Promise(resolve => setTimeout(resolve, 100));
    const buttons = document.querySelectorAll('.attachment-inline-preview').length;
    root.unmount();
    return { requests, buttons };
  });
  assert.equal(result.buttons, 16);
  assert.equal(result.requests, 0);
});

test('history pages apply later edits and deletions and keep the sync cursor independent', { timeout: 60_000 }, async () => {
  const result = await inBrowser(async () => {
    const { openLocalDatabase } = await import('/src/client/storage/db.ts');
    const cache = await import('/src/client/storage/message-cache.ts');
    const content = await import('/src/client/chat/content.ts');
    const timeline = await import('/src/client/storage/message-timeline.ts');
    const db = await openLocalDatabase();
    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const chat = crypto.randomUUID(), user = crypto.randomUUID(), device = crypto.randomUUID();
    const ids = Array.from({ length: 120 }, () => crypto.randomUUID());
    async function put(revision, text, mutation = null, reply_to_message_id = null) {
      const id = ids[revision - 1];
      const metadata = { direction: 'INCOMING', message_id: id, client_message_id: id,
        sender_user_id: user, sender_device_id: device, revision, created_at: new Date().toISOString(), mutation, reply_to_message_id };
      const plaintext = content.frameAuthenticatedMessageContent(content.encodeMessageContent(text), { ...metadata, chat_id: chat });
      await db.put('encrypted_cache', await cache.sealMessageCacheRecord(key, chat, `message:${id}`, metadata, plaintext));
      plaintext.fill(0);
    }
    for (let revision = 1; revision <= 117; revision++) await put(revision, `message ${revision}`, null, revision === 4 ? ids[1] : null);
    await put(118, 'edited message 3', { type: 'EDIT', target_message_id: ids[2] });
    await put(119, '', { type: 'TOMBSTONE', target_message_id: ids[1] });
    await put(120, 'must stay deleted', { type: 'EDIT', target_message_id: ids[1] });
    await cache.advanceChatSyncCursor(db, chat, 120);
    const batches = [];
    let complete = false;
    while (!complete) {
      const batch = await timeline.projectChatHistoryBatch(db, key, chat, 120);
      batches.push(batch.processed); complete = batch.complete;
    }
    const first = await timeline.loadMessageTimelineWindow(db, key, chat, { beforeRevision: 10 });
    const latest = await timeline.loadMessageTimelineWindow(db, key, chat);
    const oldest = await timeline.loadMessageTimelineWindow(db, key, chat, { beforeRevision: latest.oldestRevision });
    const middleAgain = await timeline.loadMessageTimelineWindow(db, key, chat, { afterRevision: oldest.newestRevision });
    const cursor = await cache.readChatSyncCursor(db, chat);
    const texts = first.messages.map(message => content.decodeMessageContent(cache.cachedMessagePlaintext(message)).text);
    const reply = first.messages.find(message => message.message_id === ids[3]);
    const summary = { batches, maxBatch: timeline.HISTORY_PROJECTION_BATCH, texts, replyTarget: reply.reply_to_message_id,
      cursor, latest: latest.messages.map(message => message.revision), oldest: oldest.messages.map(message => message.revision),
      middle: middleAgain.messages.map(message => message.revision), hasOlder: latest.hasOlder, hasNewer: oldest.hasNewer };
    db.close(); return summary;
  });
  assert.ok(result.batches.length > 1);
  assert.ok(result.batches.every(count => count <= result.maxBatch));
  assert.equal(result.cursor, 120);
  assert.ok(result.texts.includes('edited message 3'));
  assert.ok(!result.texts.includes('message 2'));
  assert.ok(!result.texts.includes('must stay deleted'));
  assert.equal(result.replyTarget, null);
  assert.equal(result.hasOlder, true);
  assert.equal(result.hasNewer, true);
  assert.ok(result.oldest.at(-1) < result.latest[0]);
  assert.deepEqual(result.middle, result.latest);
});

test('initial synchronization consumes one ordered page and never skips unseen events', { timeout: 60_000 }, async () => {
  const result = await inBrowser(async () => {
    const { openLocalDatabase } = await import('/src/client/storage/db.ts');
    const { generateDeviceIdentity, persistGeneratedDeviceIdentity, disposeDeviceIdentity } = await import('/src/client/crypto/key-vault/identity.ts');
    const { frameAuthenticatedMessageContent, encodeMessageContent } = await import('/src/client/chat/content.ts');
    const { bytesToBase64Url } = await import('/src/client/crypto/local-state/base64url.ts');
    const { synchronizeChat } = await import('/src/client/chat/sync.ts');
    const { readChatSyncCursor } = await import('/src/client/storage/message-cache.ts');
    const db = await openLocalDatabase(), identity = await generateDeviceIdentity();
    const device = crypto.randomUUID(), user = crypto.randomUUID(), chat = crypto.randomUUID();
    await persistGeneratedDeviceIdentity(db, device, identity); disposeDeviceIdentity(identity);
    const remoteUser = crypto.randomUUID(), remoteDevice = crypto.randomUUID();
    const changes = Array.from({ length: 100 }, (_, index) => {
      const id = crypto.randomUUID();
      const metadata = { chat_id: chat, client_message_id: id, sender_user_id: remoteUser, sender_device_id: remoteDevice, mutation: null, reply_to_message_id: null };
      const plaintext = frameAuthenticatedMessageContent(encodeMessageContent(`sync ${index + 1}`), metadata);
      return { type: 'message', revision: index + 1, message_id: id, ...metadata, sender_display_name: 'Sender', protocol: 'secure-messaging', protocol_version: 2,
        created_at: new Date().toISOString(), envelope: { header: 'server-sqlite-v1', ciphertext: bytesToBase64Url(plaintext) } };
    });
    let requests = 0;
    window.fetch = async path => {
      if (!String(path).includes('/sync?')) return new Response('{}', { status: 404 });
      requests++;
      return new Response(JSON.stringify({ chat_id: chat, revision: 200, sender_profiles: [],
        changes: requests === 1 ? changes : [], next_revision: requests === 1 ? 100 : 200, has_more: requests === 1 }), { headers: { 'Content-Type': 'application/json' } });
    };
    const loaded = await synchronizeChat(db, { user_id: user, device_id: device }, chat);
    const cursor = await readChatSyncCursor(db, chat);
    const result = { requests, cursor, revision: loaded.revision, count: loaded.messages.length, last: loaded.messages.at(-1)?.revision };
    loaded.messages.forEach(message => message.plaintext.fill(0)); db.close(); return result;
  });
  assert.equal(result.requests, 1);
  assert.equal(result.cursor, 100);
  assert.equal(result.revision, 100);
  assert.ok(result.count <= 80);
  assert.equal(result.last, 100);
});

test('late outgoing ACK repair invalidates only the projection and remains visible after reload', { timeout: 60_000 }, async () => {
  const result = await inBrowser(async () => {
    const { openLocalDatabase } = await import('/src/client/storage/db.ts');
    const vault = await import('/src/client/crypto/key-vault/identity.ts');
    const cache = await import('/src/client/storage/message-cache.ts');
    const timeline = await import('/src/client/storage/message-timeline.ts');
    const content = await import('/src/client/chat/content.ts');
    const db = await openLocalDatabase(), identity = await vault.generateDeviceIdentity();
    const device = crypto.randomUUID(), user = crypto.randomUUID(), chat = crypto.randomUUID(), id = crypto.randomUUID(), originalId = crypto.randomUUID();
    await vault.persistGeneratedDeviceIdentity(db, device, identity);
    const metadata = { direction: 'OUTGOING', message_id: null, client_message_id: id, sender_user_id: user, sender_device_id: device, revision: 0, created_at: new Date().toISOString() };
    await db.put('encrypted_cache', await cache.sealMessageCacheRecord(identity.masterKey, chat, `outgoing:${id}`, metadata, new TextEncoder().encode('late ACK')));
    const editId = crypto.randomUUID();
    const edit = { direction: 'INCOMING', message_id: editId, client_message_id: editId, sender_user_id: user, sender_device_id: device, revision: 8, created_at: new Date().toISOString(), mutation: { type: 'EDIT', target_message_id: originalId } };
    const editedContent = content.frameAuthenticatedMessageContent(content.encodeMessageContent('edited before ACK'), { ...edit, chat_id: chat, reply_to_message_id: null });
    await db.put('encrypted_cache', await cache.sealMessageCacheRecord(identity.masterKey, chat, `message:${editId}`, edit, editedContent));
    await cache.advanceChatSyncCursor(db, chat, 10);
    await timeline.projectChatHistoryBatch(db, identity.masterKey, chat, 10);
    await cache.promoteOutgoingCache(db, device, chat, id, originalId, 5);
    const window = await timeline.loadMessageTimelineWindow(db, identity.masterKey, chat);
    const cursor = await cache.readChatSyncCursor(db, chat);
    vault.disposeDeviceIdentity(identity); db.close();
    return { cursor, revisions: window.messages.map(message => message.revision), texts: window.messages.map(message => content.decodeMessageContent(cache.cachedMessagePlaintext(message)).text) };
  });
  assert.equal(result.cursor, 10);
  assert.deepEqual(result.revisions, [5]);
  assert.deepEqual(result.texts, ['edited before ACK']);
});

test('outbox recovery does not read committed historical payloads', { timeout: 60_000 }, async () => {
  const result = await inBrowser(async () => {
    const { openLocalDatabase } = await import('/src/client/storage/db.ts');
    const { resumePendingOutboxWsFirst } = await import('/src/client/chat/ws-first-send.ts');
    const db = await openLocalDatabase(), chat = crypto.randomUUID(), device = crypto.randomUUID();
    const tx = db.transaction('pending_outbox', 'readwrite');
    for (let index = 0; index < 1000; index++) await tx.store.put({ client_message_id: crypto.randomUUID(), chat_id: chat, sender_device_id: device,
      request: { sender_sequence: index + 1 }, status: 'COMMITTED', attempts: 1, created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
    await tx.done;
    let historicalPayloads = 0;
    const instrumented = new Proxy(db, { get(target, name) {
      if (name === 'getAllFromIndex') return async (...args) => {
        const rows = await target.getAllFromIndex(...args);
        historicalPayloads += rows.filter(row => row.status === 'COMMITTED').length;
        return rows;
      };
      const value = target[name]; return typeof value === 'function' ? value.bind(target) : value;
    } });
    await resumePendingOutboxWsFirst(instrumented, null, chat);
    db.close(); return historicalPayloads;
  });
  assert.equal(result, 0);
});

test('the actual chat UI pages older and newer messages without growing its mounted history', { timeout: 60_000 }, async () => {
  const result = await inBrowser(async () => {
    const reactModule = await import('/node_modules/.vite/deps/react.js');
    const React = reactModule.default ?? reactModule;
    const domModule = await import('/node_modules/.vite/deps/react-dom_client.js');
    const { createRoot } = domModule.default ?? domModule;
    const { SecureApp } = await import('/src/client/app/SecureApp.tsx');
    const { openLocalDatabase } = await import('/src/client/storage/db.ts');
    const vault = await import('/src/client/crypto/key-vault/identity.ts');
    const cache = await import('/src/client/storage/message-cache.ts');
    const { encodeMessageContent } = await import('/src/client/chat/content.ts');
    const db = await openLocalDatabase(), identity = await vault.generateDeviceIdentity();
    const device = crypto.randomUUID(), user = crypto.randomUUID(), chat = crypto.randomUUID(), workspace = crypto.randomUUID();
    await vault.persistGeneratedDeviceIdentity(db, device, identity);
    for (let revision = 1; revision <= 250; revision++) {
      const id = crypto.randomUUID();
      const metadata = { direction: 'OUTGOING', message_id: id, client_message_id: id, sender_user_id: user, sender_device_id: device, revision, created_at: new Date().toISOString() };
      await db.put('encrypted_cache', await cache.sealMessageCacheRecord(identity.masterKey, chat, `message:${id}`, metadata, encodeMessageContent(`visible ${revision}`)));
    }
    await cache.advanceChatSyncCursor(db, chat, 250);
    vault.disposeDeviceIdentity(identity);
    const json = value => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
    const requests = [];
    window.fetch = async path => {
      const url = String(path); requests.push(url);
      if (url === '/api/v1/sessions/current') return json({ session_id: 'fixture', user_id: user, role: 'CUSTOMER', device_id: device, device_authorized: true, webauthn_verified_at: null, authenticator_verified_at: null, workspace_ids: [workspace], staff_memberships: [] });
      if (url === '/api/v1/crypto/prekeys/status') return json({ device_id: device, bundle_present: true, ec_available: 40, pq_available: 40 });
      if (url === '/api/v1/chats') return json({ chats: [{ chat_id: chat, workspace_id: workspace, created_at: new Date().toISOString(), revision: 250, message_revision: 250, receipt_revision: 0, mutation_revision: 0, device_revision: 0, customer_user_id: user, customer_has_account: true, referred_by_user_id: null, referred_by_display_name: null, referred_by_staff_role: null, support_display_name: 'Fixture support', customer_display_name: 'Fixture customer' }] });
      if (url.endsWith('/wallpaper')) return json({ kind: 'preset', preset: 'default', can_manage: false, can_distribute: false, updated_at: null });
      if (url.includes('/sync?')) return json({ chat_id: chat, revision: 250, changes: [], sender_profiles: [], next_revision: 250, has_more: false });
      if (url.endsWith('/messages/sender-sequence')) return json({ next_sequence: 1 });
      return new Response('{}', { status: 404 });
    };
    // Keep this integration test entirely local, including realtime startup.
    window.WebSocket = class extends EventTarget {
      static CONNECTING = 0; static OPEN = 1; static CLOSING = 2; static CLOSED = 3;
      readyState = 0; close() { this.readyState = 3; } send() {}
    };
    const root = createRoot(document.getElementById('test-root'));
    const values = () => [...document.querySelectorAll('.bubble > p')].map(element => element.textContent);
    const until = async predicate => {
      const deadline = Date.now() + 10_000;
      while (!predicate()) {
        if (Date.now() > deadline) throw new Error(`Chat fixture timed out: ${document.body.innerText}; requests: ${requests}`);
        await new Promise(resolve => setTimeout(resolve, 10));
      }
    };
    const click = label => [...document.querySelectorAll('.history-navigation button')].find(button => button.textContent === label && !button.disabled)?.click();
    root.render(React.createElement(SecureApp));
    await until(() => values().at(-1) === 'visible 250' && !!document.querySelector('.history-navigation button'));
    const latest = values();
    click('Mensajes anteriores');
    await until(() => values().at(-1) === 'visible 170');
    const older = values();
    click('Mensajes siguientes');
    await until(() => values().at(-1) === 'visible 250');
    const forward = values();
    const cursor = await cache.readChatSyncCursor(db, chat);
    root.unmount(); db.close();
    return { latest, older, forward, cursor };
  });
  assert.equal(result.latest.length, 80);
  assert.equal(result.older.length, 80);
  assert.equal(result.latest[0], 'visible 171');
  assert.equal(result.older[0], 'visible 91');
  assert.deepEqual(result.forward, result.latest);
  assert.equal(result.cursor, 250);
});

test('cancelling a history rebuild leaves a resumable projection watermark and the receive cursor intact', { timeout: 60_000 }, async () => {
  const result = await inBrowser(async () => {
    const { openLocalDatabase } = await import('/src/client/storage/db.ts');
    const cache = await import('/src/client/storage/message-cache.ts');
    const timeline = await import('/src/client/storage/message-timeline.ts');
    const db = await openLocalDatabase(), key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const chat = crypto.randomUUID(), user = crypto.randomUUID(), device = crypto.randomUUID();
    for (let revision = 1; revision <= 100; revision++) {
      const id = crypto.randomUUID();
      await db.put('encrypted_cache', await cache.sealMessageCacheRecord(key, chat, `message:${id}`, { direction: 'INCOMING', message_id: id, client_message_id: id, sender_user_id: user, sender_device_id: device, revision, created_at: new Date().toISOString() }, new TextEncoder().encode(`message ${revision}`)));
    }
    await cache.advanceChatSyncCursor(db, chat, 100);
    const first = await timeline.projectChatHistoryBatch(db, key, chat, 100);
    const controller = new AbortController(); controller.abort();
    let aborted = false;
    try { await timeline.loadMessageTimelineWindow(db, key, chat, { signal: controller.signal }); }
    catch (error) { aborted = error.name === 'AbortError'; }
    const stopped = await db.get('settings', cache.chatTimelineCursorKey(chat));
    const receiveCursor = await cache.readChatSyncCursor(db, chat);
    const resumed = await timeline.loadMessageTimelineWindow(db, key, chat);
    db.close();
    return { aborted, first: first.revision, stopped: stopped.value, receiveCursor, latest: resumed.newestRevision, count: resumed.messages.length };
  });
  assert.equal(result.aborted, true);
  assert.equal(result.stopped, result.first);
  assert.ok(result.first < 100);
  assert.equal(result.receiveCursor, 100);
  assert.equal(result.latest, 100);
  assert.equal(result.count, 80);
});

test('cancelling an attachment reader aborts its active network range request', { timeout: 60_000 }, async () => {
  const result = await inBrowser(async () => {
    const { createDecryptedAttachmentStream } = await import('/src/client/attachments/downloader.ts');
    const { ATTACHMENT_CHUNK_PLAINTEXT_BYTES } = await import('/src/shared/contracts/attachments.ts');
    let networkSignal, requests = 0;
    window.fetch = async (_url, options) => {
      requests++; networkSignal = options.signal;
      return new Promise((_resolve, reject) => networkSignal?.addEventListener('abort', () => reject(networkSignal.reason), { once: true }));
    };
    const descriptor = { version: 1, file_id: crypto.randomUUID(), file_key: 'A'.repeat(43), nonce_prefix: 'A'.repeat(22), plaintext_size: 10 * 1024 * 1024, chunk_plaintext_bytes: ATTACHMENT_CHUNK_PLAINTEXT_BYTES };
    const reader = createDecryptedAttachmentStream(crypto.randomUUID(), descriptor).getReader();
    const reading = reader.read();
    await new Promise(resolve => setTimeout(resolve, 20));
    await reader.cancel(); await reading;
    return { requests, aborted: networkSignal?.aborted ?? false };
  });
  assert.equal(result.requests, 1);
  assert.equal(result.aborted, true);
});

test('corrupt derived history rebuilds from authenticated cache without losing later edits or tombstones', { timeout: 60_000 }, async () => {
  const result = await inBrowser(async () => {
    const { openLocalDatabase } = await import('/src/client/storage/db.ts');
    const cache = await import('/src/client/storage/message-cache.ts');
    const timeline = await import('/src/client/storage/message-timeline.ts');
    const content = await import('/src/client/chat/content.ts');
    const db = await openLocalDatabase(), key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const chat = crypto.randomUUID(), user = crypto.randomUUID(), device = crypto.randomUUID();
    const ids = Array.from({ length: 100 }, () => crypto.randomUUID());
    async function put(revision, text, mutation = null, reply_to_message_id = null) {
      const metadata = { direction: 'INCOMING', message_id: ids[revision - 1], client_message_id: ids[revision - 1], sender_user_id: user, sender_device_id: device, revision, created_at: new Date().toISOString(), mutation, reply_to_message_id };
      const plaintext = content.frameAuthenticatedMessageContent(content.encodeMessageContent(text), { ...metadata, chat_id: chat });
      await db.put('encrypted_cache', await cache.sealMessageCacheRecord(key, chat, `message:${metadata.message_id}`, metadata, plaintext));
      plaintext.fill(0);
    }
    for (let revision = 1; revision <= 97; revision++) await put(revision, `message ${revision}`, null, revision === 97 ? ids[1] : null);
    await put(98, 'edited message 3', { type: 'EDIT', target_message_id: ids[2] });
    await put(99, '', { type: 'TOMBSTONE', target_message_id: ids[1] });
    await put(100, 'must not resurrect', { type: 'EDIT', target_message_id: ids[1] });
    await cache.advanceChatSyncCursor(db, chat, 100);
    await timeline.loadMessageTimelineWindow(db, key, chat);
    // Corrupt a visible original and a hidden tombstone used by a reply.
    for (const id of [ids[96], ids[1]]) {
      const row = await db.get('message_timeline', `${chat}:${id}`);
      row.ciphertext[0] ^= 1; await db.put('message_timeline', row);
    }
    const latest = await timeline.loadMessageTimelineWindow(db, key, chat);
    const older = await timeline.loadMessageTimelineWindow(db, key, chat, { beforeRevision: 10 });
    const again = await timeline.loadMessageTimelineWindow(db, key, chat);
    const read = window => window.messages.map(message => content.decodeMessageContent(cache.cachedMessagePlaintext(message)).text);
    const result = { cursor: await cache.readChatSyncCursor(db, chat), rawCount: await db.count('encrypted_cache'),
      latest: read(latest), older: read(older), again: read(again), replyTarget: latest.messages.find(message => message.message_id === ids[96]).reply_to_message_id };
    db.close(); return result;
  });
  assert.equal(result.cursor, 100);
  assert.equal(result.rawCount, 100);
  assert.equal(result.latest.length, 80);
  assert.ok(result.older.includes('edited message 3'));
  assert.ok(!result.older.includes('message 2'));
  assert.ok(!result.older.includes('must not resurrect'));
  assert.equal(result.replyTarget, null);
  assert.deepEqual(result.again, result.latest);
});

test('stalled realtime reconciliation bounds retained events and still resolves duplicate ACKs exactly once', { timeout: 60_000 }, async () => {
  const result = await inBrowser(async () => {
    const realtime = await import('/src/client/transport/realtime.ts');
    const { CRYPTO_PROTOCOL, CRYPTO_PROTOCOL_VERSION } = await import('/src/shared/constants/protocol.ts');
    const sockets = [];
    window.WebSocket = class extends EventTarget {
      static CONNECTING = 0; static OPEN = 1; static CLOSING = 2; static CLOSED = 3;
      readyState = 1; sent = [];
      constructor() { super(); sockets.push(this); }
      close() { this.readyState = 3; this.dispatchEvent(new Event('close')); }
      send(raw) { this.sent.push(JSON.parse(raw)); }
      receive(value) { this.dispatchEvent(new MessageEvent('message', { data: JSON.stringify(value) })); }
    };
    const chat = crypto.randomUUID(), user = crypto.randomUUID(), device = crypto.randomUUID();
    const syncStarts = [], delivered = [], ownCommitted = [];
    let resume;
    const gate = new Promise(resolve => { resume = resolve; });
    const client = new realtime.ChatRealtimeClient({ chatId: chat, initialRevision: 0, onState() {},
      syncHttp: async after => { syncStarts.push(after); await gate; return 1001; },
      onCommittedMessage: async event => { delivered.push(event.revision); },
      onContiguousOwnCommit: async ack => { ownCommitted.push(ack.revision); },
    });
    client.start(); const socket = sockets.at(-1);
    socket.receive({ type: 'realtime.ready', chat_id: chat, revision: 0 });
    const id = crypto.randomUUID();
    const outgoing = client.sendMessage({ client_message_id: id, sender_sequence: 1, envelopes: [], attachment_ids: [] });
    const duplicatePromise = client.sendMessage({ client_message_id: id, sender_sequence: 1, envelopes: [], attachment_ids: [] });
    const envelope = { recipient_user_id: user, recipient_device_id: device, protocol: CRYPTO_PROTOCOL, protocol_version: CRYPTO_PROTOCOL_VERSION, header: 'fixture', ciphertext: 'A'.repeat(256 * 1024) };
    const measure = () => ({ count: client.committedBuffer.size,
      bytes: [...client.committedBuffer.values()].reduce((total, event) => total + (event.envelope ? 2 * (event.envelope.header.length + event.envelope.ciphertext.length) : 0), 0) });
    let maxCount = 0, maxBytes = 0;
    for (let revision = 2; revision <= 1000; revision++) {
      socket.receive({ type: 'message.committed', chat_id: chat, revision, message_id: crypto.randomUUID(), client_message_id: crypto.randomUUID(), sender_user_id: user, sender_device_id: device, accepted_at: new Date().toISOString(), envelope: revision < 34 ? envelope : { ...envelope, ciphertext: 'small' } });
      const size = measure(); maxCount = Math.max(maxCount, size.count); maxBytes = Math.max(maxBytes, size.bytes);
    }
    const ack = { type: 'message.ack', chat_id: chat, client_message_id: id, message_id: crypto.randomUUID(), revision: 1001, accepted_at: new Date().toISOString(), duplicate: false };
    socket.receive(ack); socket.receive({ ...ack, duplicate: true });
    const accepted = await outgoing;
    const beforeResume = client.revision;
    resume(); await new Promise(resolve => setTimeout(resolve, 20));
    // A second stalled gap with tiny frames exercises the count limit
    // independently of the earlier large-frame byte limit.
    for (let revision = 1003; revision <= 1200; revision++) {
      socket.receive({ type: 'message.committed', chat_id: chat, revision, message_id: crypto.randomUUID(), client_message_id: crypto.randomUUID(), sender_user_id: user, sender_device_id: device, accepted_at: new Date().toISOString(), envelope: { ...envelope, ciphertext: 'small' } });
      const size = measure(); maxCount = Math.max(maxCount, size.count); maxBytes = Math.max(maxBytes, size.bytes);
    }
    const result = { maxCount, maxBytes, beforeResume, afterResume: client.revision, syncStarts, delivered, ownCommitted,
      accepted: accepted.client_message_id === id, samePromise: outgoing === duplicatePromise,
      sends: socket.sent.filter(event => event.type === 'message.send').length, retainedAfter: client.committedBuffer.size };
    client.stop(); return result;
  });
  assert.ok(result.maxCount <= 64, `retained ${result.maxCount} events`);
  assert.ok(result.maxBytes <= 2 * 1024 * 1024, `retained ${result.maxBytes} ciphertext bytes`);
  assert.equal(result.beforeResume, 0);
  assert.equal(result.afterResume, 1001);
  assert.equal(result.syncStarts[0], 0);
  assert.deepEqual(result.delivered, []);
  assert.deepEqual(result.ownCommitted, []);
  assert.equal(result.accepted, true);
  assert.equal(result.samePromise, true);
  assert.equal(result.sends, 1);
  assert.equal(result.retainedAfter, 0);
});

test('preconnected realtime sockets release oversized buffered history before adoption', { timeout: 60_000 }, async () => {
  const result = await inBrowser(async () => {
    const { preconnectRealtimeSocket, ChatRealtimeClient } = await import('/src/client/transport/realtime.ts');
    const { CRYPTO_PROTOCOL, CRYPTO_PROTOCOL_VERSION } = await import('/src/shared/constants/protocol.ts');
    const sockets = [];
    window.WebSocket = class extends EventTarget {
      static CONNECTING = 0; static OPEN = 1; static CLOSING = 2; static CLOSED = 3;
      readyState = 1;
      constructor() { super(); sockets.push(this); }
      close() { this.readyState = 3; this.dispatchEvent(new Event('close')); }
      send() {}
      receive(value) { this.dispatchEvent(new MessageEvent('message', { data: JSON.stringify(value) })); }
    };
    const chat = crypto.randomUUID(), user = crypto.randomUUID(), device = crypto.randomUUID();
    preconnectRealtimeSocket(chat); const original = sockets[0];
    for (let revision = 1; revision <= 16; revision++) original.receive({ type: 'message.committed', chat_id: chat, revision,
      message_id: crypto.randomUUID(), client_message_id: crypto.randomUUID(), sender_user_id: user, sender_device_id: device, accepted_at: new Date().toISOString(),
      envelope: { recipient_user_id: user, recipient_device_id: device, protocol: CRYPTO_PROTOCOL, protocol_version: CRYPTO_PROTOCOL_VERSION, header: 'fixture', ciphertext: 'A'.repeat(256 * 1024) } });
    const closedBeforeAdoption = original.readyState === 3;
    const client = new ChatRealtimeClient({ chatId: chat, initialRevision: 0, syncHttp: async () => 0, onState() {} });
    client.start(); const result = { closedBeforeAdoption, newSocket: sockets.length === 2, revision: client.revision }; client.stop(); return result;
  });
  assert.equal(result.closedBeforeAdoption, true);
  assert.equal(result.newSocket, true);
  assert.equal(result.revision, 0);
});

test('a cancelled derived-history repair deletes bounded batches and resumes after reopening the database', { timeout: 60_000 }, async () => {
  const result = await inBrowser(async () => {
    const { openLocalDatabase } = await import('/src/client/storage/db.ts');
    const cache = await import('/src/client/storage/message-cache.ts');
    const timeline = await import('/src/client/storage/message-timeline.ts');
    let db = await openLocalDatabase();
    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const chat = crypto.randomUUID(), user = crypto.randomUUID(), device = crypto.randomUUID();
    let lastId;
    for (let revision = 1; revision <= 100; revision++) {
      const id = crypto.randomUUID(); lastId = id;
      await db.put('encrypted_cache', await cache.sealMessageCacheRecord(key, chat, `message:${id}`, { direction: 'INCOMING', message_id: id, client_message_id: id, sender_user_id: user, sender_device_id: device, revision, created_at: new Date().toISOString() }, new TextEncoder().encode(`message ${revision}`)));
    }
    await cache.advanceChatSyncCursor(db, chat, 100);
    await timeline.loadMessageTimelineWindow(db, key, chat);
    const row = await db.get('message_timeline', `${chat}:${lastId}`); row.ciphertext[0] ^= 1; await db.put('message_timeline', row);
    const controller = new AbortController(), batches = [];
    const instrumented = new Proxy(db, { get(target, name) {
      if (name === 'transaction') return (...args) => {
        const tx = target.transaction(...args); let deleted = 0;
        const done = tx.done.then(() => { if (deleted) { batches.push(deleted); controller.abort(); } });
        return new Proxy(tx, { get(transaction, property) {
          if (property === 'done') return done;
          if (property === 'objectStore') return storeName => {
            const store = transaction.objectStore(storeName);
            return new Proxy(store, { get(objectStore, member) {
              if (member === 'delete' && storeName === 'message_timeline') return (...keys) => { deleted++; return objectStore.delete(...keys); };
              const value = objectStore[member]; return typeof value === 'function' ? value.bind(objectStore) : value;
            } });
          };
          const value = transaction[property]; return typeof value === 'function' ? value.bind(transaction) : value;
        } });
      };
      const value = target[name]; return typeof value === 'function' ? value.bind(target) : value;
    } });
    let aborted = false;
    try { await timeline.loadMessageTimelineWindow(instrumented, key, chat, { signal: controller.signal }); }
    catch (error) { aborted = error.name === 'AbortError'; }
    const remaining = await db.count('message_timeline'), stoppedCursor = await cache.readChatSyncCursor(db, chat);
    db.close(); db = await openLocalDatabase();
    const resumed = await timeline.loadMessageTimelineWindow(db, key, chat);
    const result = { aborted, batches, remaining, stoppedCursor, resumedCursor: await cache.readChatSyncCursor(db, chat), newest: resumed.newestRevision, count: resumed.messages.length, rawCount: await db.count('encrypted_cache') };
    db.close(); return result;
  });
  assert.equal(result.aborted, true);
  assert.deepEqual(result.batches, [32]);
  assert.equal(result.remaining, 68);
  assert.equal(result.stoppedCursor, 100);
  assert.equal(result.resumedCursor, 100);
  assert.equal(result.newest, 100);
  assert.equal(result.count, 80);
  assert.equal(result.rawCount, 100);
});
