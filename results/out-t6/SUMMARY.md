# Starknet DA cross-check

## L1 block 26214566, transaction 69

**FAIL** — Starknet through block 16525351.

- Alias-contract storage exact equality: True.
- Cairo-1 declarations exact equality: True.
- Contracts, ours/public: 761/761; storage entries: 22679/22924.
- Sampled field matches: 400/403; total failed assertions: 3.
- Alias-resolution field errors: 0; skipped items: 23001 (reasons in JSON).
- Counts differ. Public no-op writes, writes reverted within the range, empty records, or a decoding/data discrepancy could account for this. No cause is established by this sampled check; prior-state analysis would be needed.

## L1 block 26214569, transaction 68

**FAIL** — Starknet through block 16526851.

- Alias-contract storage exact equality: True.
- Cairo-1 declarations exact equality: True.
- Contracts, ours/public: 814/814; storage entries: 23797/23954.
- Sampled field matches: 401/403; total failed assertions: 2.
- Alias-resolution field errors: 0; skipped items: 24079 (reasons in JSON).
- Counts differ. Public no-op writes, writes reverted within the range, empty records, or a decoding/data discrepancy could account for this. No cause is established by this sampled check; prior-state analysis would be needed.

## L1 block 26214977, transaction 40

**FAIL** — Starknet through block 16528351.

- Alias-contract storage exact equality: True.
- Cairo-1 declarations exact equality: True.
- Contracts, ours/public: 810/811; storage entries: 14314/14436.
- Sampled field matches: 410/411; total failed assertions: 1.
- Alias-resolution field errors: 0; skipped items: 14579 (reasons in JSON).
- Counts differ. Public no-op writes, writes reverted within the range, empty records, or a decoding/data discrepancy could account for this. No cause is established by this sampled check; prior-state analysis would be needed.

## Run totals

- Selected updates: 3.
- Completed cross-checks: 3.
- Failed updates: 3.
- Other core blob selectors skipped: 0.
- PASS means the stated exact and sampled assertions passed; it is not exhaustive equivalence of every state-diff field.
