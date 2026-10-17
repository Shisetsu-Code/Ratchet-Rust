# Storage admission and recovery

The storage hardening adds `0003_storage_quotas.sql` after the existing schema and authentication migrations. Durable Object SQLite tables are upgraded on activation. Existing chat history, committed attachments, receipt state and legacy receipt replay responses remain retained. Reaching a quota rejects new growth; it does not evict history or reset message sequences.

## Default limits

| Resource | Owner or room limit | Aggregate limit |
| --- | --- | --- |
| Attachments | 1 GiB per user, 10,000 retained upload records, 16 pending uploads | 100 GiB; 1,000,000 retained upload records |
| Wallpaper ciphertext | 8 uncleaned objects and 25,165,952 bytes per owner administrator | 10 GiB; 100,000 uncleaned objects |
| Wallpaper metadata | 256 retained upload records per owner administrator | 1,000,000 retained upload records |
| Chat messages, events, receipt state and receipt replay responses | 256 MiB and 1,000,000 logical rows per room | 100 GiB and 10,000,000 allocated logical rows |
| Receipt replay responses | 16 MiB and 50,000 requests per user in each room, also charged to the room | Included in chat capacity |
| New receipt requests | 30 per user per 10 seconds; 300 per room per 10 seconds | Bounded within each room |
| Push subscriptions | One replaceable endpoint per device; 16 device slots per user | 50,000 slots and at most one queued hint per slot |

Attachment and wallpaper limits are stored in D1 `storage_limits`; aggregate chat limits are in `chat_capacity_limits`. Per-room chat limits and reservation chunk sizes are constants in `chat/capacity.rs`. Changing constants requires deployment. Lowering a limit preserves existing data and may stop new admission until capacity is available.

The attachment ledger reserves the declared encrypted file size before R2 accepts parts. Each part must have the exact size assigned to its position in that reservation. Replacing a part cannot increase the reserved total. `READY` to `COMMITTED`, including failed-message compensation back to `READY`, leaves the byte charge intact. A committed attachment continues to count and remains downloadable after its former upload expiration timestamp.

Unfinished, aborted, expired and retired objects remain charged until safe cleanup succeeds. Cleaned tombstones retain a metadata-record charge for seven days and are then pruned in bounded batches when unreferenced. Old committed files, active published wallpapers and chat history are outside that cleanup set. An expired **uncommitted** upload remains subject to upload cleanup.

## Deploying over existing data

1. Take coordinated backups of D1, Durable Object storage and the R2 objects required by retained history. A Git backup only covers code.
2. Put the old deployment into maintenance, stop scheduled cleanup, and drain its in-flight upload requests before applying the new migration or starting the new cleaner. Pre-patch wallpaper PUTs have no durable writer marker or multipart handle. The new fencing protocol cannot retroactively stop those writes. Keep old versions from receiving traffic after the drain.
3. Apply all unapplied D1 migrations in order and deploy the matching Worker. The migration charges existing attachments, including committed files. Historical unfinished or aborted multipart uploads reserve 10 MiB plus 32 bytes each because the old uploader could store parts larger than its declared file size. This separate charge preserves the declared protocol size and falls only after verified object completion or safe cleanup; historical `READY`/`COMMITTED` files and new reservations use their exact size. Historical wallpapers reserve the protocol maximum of 3 MiB plus 16 bytes. The migration resets their old cleanup markers for a safe recheck after old writers have drained.
4. Let scheduled capacity reconciliation contact every pre-existing room's authoritative Durable Object. SQLite usage is backfilled from retained messages, events, receipt state and replay responses. The eventually updated `chat_storage_stats` projection is not used as proof of capacity.
5. Check the reconciliation query below before reopening unrestricted growth. New chat capacity grants return retryable `STORAGE_RECONCILIATION_PENDING` while any historical room remains unknown. Read and replay operations continue to use retained data. Reconciliation records actual existing usage even when that usage already exceeds a limit; it does not delete the excess.

Scheduled reconciliation handles up to 100 unknown rooms per invocation. A room becomes reconciled even if the subsequent attempt to reserve additional headroom is denied. Investigate rooms that remain unknown across invocations instead of marking them reconciled from estimated usage.

```sql
SELECT COUNT(*) AS unknown_rooms
FROM chat_storage_capacity WHERE reconciled = 0;

SELECT SUM(allocated_bytes) AS allocated_bytes,
       SUM(allocated_rows) AS allocated_rows
FROM chat_storage_capacity;

SELECT kind, bytes, objects, pending, records
FROM object_storage_usage WHERE owner_id = '*';
```

## Chat capacity and backup restoration

D1 atomically allocates room credits in chunks of 1 MiB and 4,096 rows against the aggregate limits. Each Durable Object enforces its granted allowance inside the same SQLite transaction that commits message or receipt growth. Duplicate message commits are checked first. Capacity checks after asynchronous reservation re-read local usage before admitting a synchronous commit batch.

Unused credits count against aggregate capacity. Allocations do not expire on hibernation, crash or inactivity and are not automatically returned when a receipt replay response expires. This conservative policy prevents a room from spending credits that were reassigned elsewhere. There is no automatic history deletion or online credit-shrinking operation in this patch. Monitor reserved headroom as well as used bytes when sizing limits.

When restoring D1 or Durable Object backups, quiesce writes and stop old Worker instances first. Reset `chat_storage_capacity.reconciled` to zero for every existing room and rerun authoritative reconciliation before reopening growth. Do not restore an older D1 capacity ledger while leaving active rooms able to spend cached allowances, and do not manually reduce allocations while those allowances remain usable. Coordinated restoration must retain the messages' corresponding R2 objects.

## Multipart writer recovery

Attachments and new wallpaper uploads register their multipart handle before uploading object bytes. A durable exclusive writer token protects each R2 operation. Cleanup first fences the row to a terminal state, then closes the multipart handle. It releases a writer token only after the operation completes or the provider positively confirms the handle is closed. Elapsed time or an absent object alone does not establish that a late write is impossible.

Successful abort, R2 `NoSuchUpload` (`10024`), or a completed object observed after a failed abort establishes closure. Cleanup deletes the completed object before marking the row cleaned and releasing the object charge. A provider error leaves the charge in place for retry. Failed cleanup rows are rescheduled with bounded backoff, and cleaned rows are excluded from later scans. Each invocation handles at most 32 stalled writer recoveries and 100 cleanup candidates per object kind.

A crash before a newly created handle is registered can leave an empty multipart upload, but the fenced request cannot upload bytes through it. R2's incomplete multipart lifecycle removes such handles; confirm that the bucket retains an appropriate incomplete-upload lifecycle rule. See Cloudflare's [Workers R2 API reference](https://developers.cloudflare.com/r2/api/workers/workers-api-reference/) and [R2 error codes](https://developers.cloudflare.com/r2/api/error-codes/).

## Receipt replay and push delivery

Receipt bodies are bounded to 32 KiB and use a strict typed schema with at most 100 distinct message IDs. Unknown fields, duplicate message IDs and states other than `READ` or `DELIVERED` are rejected. New requests store a canonical SHA-256 fingerprint and the compact original response. Their non-sliding replay window is 30 days. Before admitting message or receipt growth, the Worker removes at most 512 expired replay responses so exhausted capacity cannot block cleanup itself. Receipt processing also removes its own expired request ID if that row falls beyond the batch. Existing full-payload replay records have no expiration and remain charged, preserving pre-upgrade offline request deduplication.

During the replay window an unchanged request returns the original result and a changed payload with the same ID conflicts. After expiration the original cached response and request-ID conflict detection are no longer promised, but receipt state stays monotonic: `READ` never regresses and no-op receipts do not create events. Exact known replays bypass growth reservation and the new-request rate counter.

Push registration replaces the device's existing endpoint while keeping endpoint ownership checks. The durable queue coalesces unleased hints without resetting their queue age, selects recipients across users, and limits concurrent provider requests to four per dispatcher and eight global leases. Each 30-second lease starts when its individual delivery attempts the claim, including later dispatch waves. Cryptographic preparation and transport share an absolute ten-second deadline from that claim; late continuations cannot start or resume delivery after the deadline. Completion, timeout and cancellation abort the transport before releasing the lease. A WebCrypto primitive already submitted may finish internally, but its result cannot continue a timed-out delivery. HTTP 404/410 permanently revoke an unchanged endpoint; 429, 5xx and transient errors back off, without revoking it. After eight failed attempts a hint is discarded; a later message can enqueue another. Scheduled maintenance also drains the queue.

## What the byte counters mean

Object counters represent reserved or retained ciphertext payload plus separately bounded metadata records. Chat counters sum UTF-8/blob payload sizes and conservative fixed row overhead across all retained message, event and receipt tables. They are application admission budgets, not exact physical SQLite page, index, provider multipart or billing measurements. Monitor D1, Durable Object and R2 provider usage with operational headroom; those systems have separate physical limits. Do not infer available storage from only live upload states, message count, or the eventually updated statistics projection.
