# Authentication admission and local key passwords

Migration `0002_auth_admission.sql` adds admission tables and challenge indexes
without replacing credentials, users or sessions. Apply it before deploying the
Worker that uses it. Existing challenge identities and consumption markers are
preserved. An old `next_allowed_at` value no longer blocks an entire account.
Legacy challenge writers can omit the added origin column during the short
migration/deployment interval; global retained-row ceilings still apply. New
Worker paths always supply an origin and reserve admission atomically. Reverting
the Worker does not undo an applied database migration: preserve a database
backup and plan database rollback or forward recovery separately.

## Password work

Every password verification reserves a D1 permit before PBKDF2. An atomic INSERT
checks all rate and concurrency limits, then consumes a supplied proof exactly
once. Unknown login names use the same admission path and total PBKDF2 iteration
budget as existing names. Legacy iteration counts remain supported by padding
their work to 600,000 iterations. Rejected admission performs no dummy PBKDF2.
This removes the previous fast account-lockout timing distinction; it does not
claim identical end-to-end network latency.

Default policy uses rolling 60-second windows:

| Scope | Total requests | Per origin | Per origin and principal | Active total / origin |
| --- | ---: | ---: | ---: | ---: |
| Password login and access activation | 120 | 30 | 15 | 4 / 2 |
| Validated-session password reauthentication | 60 | 30 | 10 | 4 / 2 |
| Authorized password creation/replacement | 30 | 30 | 10 | 4 / 2 |
| Password proof creation | 120 | 12 | 6 | No KDF |
| Public challenge preparation | 240 | 40 | 20 | No KDF |
| Validated-session challenge preparation | 120 | 40 | 20 | No KDF |

Password writes share one origin bucket, so their effective concurrent write
limit is two. The target or authorizing principal also has a per-window limit.
These initial capacity settings are configurable through `auth_admission_policy`;
measure real traffic, NAT usage and CPU before increasing them. A successful
login releases concurrent capacity but never erases its rate charge. Failures
are recorded only after actual verification, conditioned on the credential
version that was checked. Failure observations expire after 15 minutes and do
not gate a whole account.

Rate records expire after ten minutes and have an absolute 10,000-row ceiling.
Leases recover after 120 seconds if a request crashes. Both Worker configurations
limit CPU time to 30,000 ms; a verification refuses to start when fewer than 30
seconds remain on its lease. Preserve this relationship when changing runtime
limits. No lease mechanism can guarantee availability while its backing service
is unavailable: admission fails closed.

Reauthentication uses its dedicated pool only after validating the current
session, user and device. Merely supplying a cookie or device identifier cannot
select it. Its edge prefilter is separate from anonymous login traffic.

## One-use work challenge

After ten admitted attempts for a login name in a minute, anonymous login or
activation returns HTTP 429 with `type: AUTHENTICATION_PROOF_REQUIRED`. The name
is counted regardless of whether it exists. Another origin therefore has a
password route available without inheriting an account-wide lockout, subject to
the service's hard capacity limits.

Clients request `POST /api/v1/auth/password/challenge` with `{"login_name":"…"}`.
The response contains protocol `ratchet-auth-work-v1`, UUID `challenge_id`, a
43-character base64url `challenge`, `difficulty` (currently 18), and `expires_at`
as Unix seconds. Find a nonnegative 32-bit integer `solution` whose SHA-256 hash
of the UTF-8 string below starts with `difficulty` zero bits:

```text
ratchet-auth-work-v1\n<challenge>\n<decimal solution>
```

Retry the same login or activation request once with
`"proof":{"challenge_id":"…","solution":123}`. Proofs are bound to origin and
normalized login name, expire after two minutes, and are consumed in the same
transaction that admits the password work. A proof never bypasses the global,
origin, pair or concurrent-work limits. Replay, a different principal and a
different origin are rejected before PBKDF2.

The browser handles this response, validates the work ceiling, yields between
bounded batches and stops after 20 seconds or cancellation. Ordinary native/API
callers keep their existing request format; callers that hit the risk threshold
must implement this protocol or respect the retry interval. The challenge raises
the cost of automated attempts; it is not bot detection or proof of a human.

Proof storage has a 512-row ceiling, at most four pending rows per origin, and
reuses an unconsumed challenge for the same origin/name where possible.

## Authentication challenges

Portable key and passkey login share a retained-row limit of 2,000; their
reauthentication pool holds at most 512. Each pool permits 40 pending challenges
per origin. Bootstrap has a separate 128-row ceiling and 16 pending per origin;
administrator provisioning and owner-console challenges each have a 512-row
ceiling and 40 pending per origin. Public issuance also shares the rate budget
above. Existing rows count toward retained capacity, including expired rows
until cleanup actually deletes them.

The bounded cleanup transaction deletes an expired set's consumption rows and
then precisely those parent challenges. It never deletes consumption markers
for live challenges. Scheduled cleanup and opportunistic preparation cleanup
cover portable keys, passkeys, administrator provisioning and owner console.

## Owner and administrator key files

Provisioning and ADMIN recovery now require an independent local passphrase for
the encrypted `.ratchet-key` file. That passphrase is never sent with account
passwords or signed operations. Existing key files remain readable. The owner
tool can produce and verify a new encrypted copy while preserving the original
and its signing identity. Rewrapping does not revoke leaked older copies; rotate
and revoke the signing key if an old file and password were exposed. See
`tools/owner_setup/README.md` for the local migration operation.
