import { test } from 'node:test';
import assert from 'node:assert/strict';
import { inspectImagePreview } from '../../src/client/attachments/preview-policy.ts';

const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=', 'base64');
test('a normal static image can be previewed without invoking a decoder during inspection', async () => {
  const result = await inspectImagePreview(new Blob([png]), 'image/png');
  assert.equal(result.allowed, true);
  assert.equal(result.width, 1); assert.equal(result.height, 1);
});
test('small compressed files with excessive image dimensions cannot enter the browser preview', async () => {
  const huge = Buffer.from(png); huge.writeUInt32BE(50_000, 16); huge.writeUInt32BE(50_000, 20);
  assert.equal((await inspectImagePreview(new Blob([huge]), 'image/png')).allowed, false);
  const pixels = Buffer.from(png); pixels.writeUInt32BE(4000, 16); pixels.writeUInt32BE(4000, 20);
  assert.equal((await inspectImagePreview(new Blob([pixels]), 'image/png')).allowed, false);
});
test('animated image payloads remain downloadable but are not automatically decoded for preview', async () => {
  const control = Buffer.alloc(20); control.writeUInt32BE(8, 0); control.write('acTL', 4); control.writeUInt32BE(10000, 8);
  const animated = Buffer.concat([png.subarray(0, 33), control, png.subarray(33)]);
  assert.equal((await inspectImagePreview(new Blob([animated]), 'image/png')).allowed, false);
});
test('malformed chunk lengths and truncated image headers fail closed', async () => {
  for (const [bytes, type] of [[png.subarray(0, 20), 'image/png'], [Buffer.from('GIF89a'), 'image/gif'], [Buffer.from([0xff, 0xd8, 0xff, 0xc0, 0xff, 0xff]), 'image/jpeg']]) {
    assert.equal((await inspectImagePreview(new Blob([bytes]), type)).allowed, false);
  }
});
