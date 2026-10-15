# Customer quota A/B comparison

All 24 primary case results passed; three matched pairs per case; full recovery, no lost or duplicate messages, matching ACK counts and workload dimensions.

Improvement is (sequential mean - rust mean) / sequential mean; positive favors current Rust. ACK figures summarize each run equally. Three local pairs do not establish statistical significance.

Both variants are Rust. `rust` labels the parallel candidate at measurement time; it does not imply that candidate was adopted. All rounds, including the slower third candidate run, remain included. No cause is assigned to that variation.

| Case | Metric | Sequential mean | Parallel candidate mean | Improvement % | Faster pairs |
|---|---|---:|---:|---:|---:|
| 1000-one-chat-256B | elapsed_ms | 5685.95 | 5792.69 | -1.88 | 2/3 |
| 1000-one-chat-256B | ack_p95_ms | 207.73 | 202.54 | 2.50 | 2/3 |
| 1000-one-chat-256B | ack_mean_ms | 179.84 | 183.62 | -2.10 | 2/3 |
| 1000-one-chat-256B | server_cpu_ms | 5473.96 | 5286.46 | 3.43 | 2/3 |
| 1000-twenty-chats-256B | elapsed_ms | 5865.76 | 8267.45 | -40.94 | 2/3 |
| 1000-twenty-chats-256B | ack_p95_ms | 258.07 | 383.39 | -48.56 | 1/3 |
| 1000-twenty-chats-256B | ack_mean_ms | 185.36 | 260.36 | -40.46 | 2/3 |
| 1000-twenty-chats-256B | server_cpu_ms | 4583.34 | 4479.17 | 2.27 | 2/3 |
| 2000-one-chat-256B | elapsed_ms | 15504.11 | 19440.31 | -25.39 | 1/3 |
| 2000-one-chat-256B | ack_p95_ms | 300.50 | 376.64 | -25.34 | 1/3 |
| 2000-one-chat-256B | ack_mean_ms | 246.70 | 309.08 | -25.29 | 1/3 |
| 2000-one-chat-256B | server_cpu_ms | 16562.50 | 16906.25 | -2.08 | 0/3 |
| 1000-one-chat-4KiB | elapsed_ms | 6287.79 | 8374.93 | -33.19 | 1/3 |
| 1000-one-chat-4KiB | ack_p95_ms | 240.36 | 332.24 | -38.23 | 0/3 |
| 1000-one-chat-4KiB | ack_mean_ms | 198.98 | 265.34 | -33.35 | 1/3 |
| 1000-one-chat-4KiB | server_cpu_ms | 6026.05 | 6171.88 | -2.42 | 1/3 |

| Case | Sequential recovered | Current Rust recovered |
|---|---:|---:|
| 1000-one-chat-256B | 3000 | 3000 |
| 1000-twenty-chats-256B | 3000 | 3000 |
| 2000-one-chat-256B | 6000 | 6000 |
| 1000-one-chat-4KiB | 3000 | 3000 |

Profiled 1000-message diagnostic (one run per variant; excluded from primary means):

| Variant | Samples | Phase | Mean ms | P95 ms |
|---|---:|---|---:|---:|
| sequential | 100 | attachment_claim | 0.00 | 0.00 |
| sequential | 100 | authorize | 0.02 | 0.00 |
| sequential | 100 | batch_staging_wait | 1.52 | 3.00 |
| sequential | 100 | frame_decode | 0.02 | 0.00 |
| sequential | 100 | lookup | 0.05 | 0.00 |
| sequential | 100 | postcommit_wait | 16.67 | 27.00 |
| sequential | 100 | preparation_window_wait | 0.01 | 0.00 |
| sequential | 100 | prepare_validate_crypto | 0.09 | 1.00 |
| sequential | 100 | publish_enumerate_sockets | 0.00 | 0.00 |
| sequential | 100 | publish_event_build | 0.09 | 1.00 |
| sequential | 100 | publish_event_serialize | 0.17 | 1.00 |
| sequential | 100 | publish_peer_authorize | 0.06 | 1.00 |
| sequential | 100 | publish_peer_decode | 0.05 | 0.00 |
| sequential | 100 | publish_push_schedule | 0.01 | 0.00 |
| sequential | 100 | publish_total | 0.44 | 1.00 |
| sequential | 100 | publish_wasm_js_send | 0.03 | 0.00 |
| sequential | 100 | quota_customer_burst_io | 29.29 | 34.00 |
| sequential | 100 | quota_customer_sustained_io | 30.63 | 35.00 |
| sequential | 100 | quota_device_io | 36.60 | 44.00 |
| sequential | 100 | quota_io | 96.52 | 107.00 |
| sequential | 100 | ready_queue_wait | 8.76 | 16.00 |
| sequential | 100 | sqlite_commit | 0.18 | 1.00 |
| rust | 100 | attachment_claim | 0.00 | 0.00 |
| rust | 100 | authorize | 0.01 | 0.00 |
| rust | 100 | batch_staging_wait | 1.63 | 4.00 |
| rust | 100 | frame_decode | 0.02 | 0.00 |
| rust | 100 | lookup | 0.04 | 0.00 |
| rust | 100 | postcommit_wait | 15.73 | 27.00 |
| rust | 100 | preparation_window_wait | 0.00 | 0.00 |
| rust | 100 | prepare_validate_crypto | 0.06 | 1.00 |
| rust | 100 | publish_enumerate_sockets | 0.02 | 0.00 |
| rust | 100 | publish_event_build | 0.08 | 1.00 |
| rust | 100 | publish_event_serialize | 0.06 | 1.00 |
| rust | 100 | publish_peer_authorize | 0.06 | 1.00 |
| rust | 100 | publish_peer_decode | 0.09 | 1.00 |
| rust | 100 | publish_push_schedule | 0.02 | 0.00 |
| rust | 100 | publish_total | 0.52 | 1.00 |
| rust | 100 | publish_wasm_js_send | 0.10 | 1.00 |
| rust | 100 | quota_customer_burst_io | 57.51 | 67.00 |
| rust | 100 | quota_customer_sustained_io | 57.50 | 67.00 |
| rust | 100 | quota_device_io | 32.92 | 37.00 |
| rust | 100 | quota_io | 90.44 | 101.00 |
| rust | 100 | ready_queue_wait | 9.09 | 20.00 |
| rust | 100 | sqlite_commit | 0.22 | 1.00 |
