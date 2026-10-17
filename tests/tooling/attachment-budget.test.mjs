import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AttachmentResourceBudget } from '../../src/client/attachments/resource-budget.ts';

test('attachment reservations limit total bytes and concurrent work until released', async () => {
  const budget = new AttachmentResourceBudget(2, 10, 2);
  const first = await budget.reserve(7);
  let secondStarted = false;
  const second = budget.reserve(5).then(release => { secondStarted = true; return release; });
  await Promise.resolve();
  assert.equal(secondStarted, false);
  first(); first();
  const releaseSecond = await second;
  assert.equal(secondStarted, true);
  const releaseThird = await budget.reserve(5);
  let fourthStarted = false;
  const fourth = budget.reserve(1).then(release => { fourthStarted = true; return release; });
  await Promise.resolve(); assert.equal(fourthStarted, false);
  releaseSecond(); (await fourth)(); releaseThird();
});

test('cancelling a queued attachment removes it without leaking a slot or bytes', async () => {
  const budget = new AttachmentResourceBudget(1, 10, 1);
  const active = await budget.reserve(10);
  const controller = new AbortController();
  const waiting = budget.reserve(10, controller.signal);
  const rejected = assert.rejects(waiting, { name: 'AbortError' });
  controller.abort(); await rejected;
  const replacement = budget.reserve(10);
  active(); (await replacement)();
  (await budget.reserve(10))();
});

test('oversized work and a saturated waiting queue fail without growing reservations', async () => {
  const budget = new AttachmentResourceBudget(1, 10, 1);
  await assert.rejects(budget.reserve(11), /size|tamaño/i);
  const first = await budget.reserve(10);
  const queued = budget.reserve(10);
  await assert.rejects(budget.reserve(1), /queue|cola/i);
  first(); (await queued)();
});
