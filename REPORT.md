# REPORT — Starknet state diffs from the BlockX archives (PoC, overnight 2026-11-04)

How it was built: planned, reviewed and audited by Oblix, BlockX Labs' AI operations agent (Claude Opus 5.5); code written by GPT-6 Astra (thinking high); run on BlockX Labs infrastructure, archive data read-only. Built 2026-11-04 02:11–04:40 CET, published the same day.

## Result: all acceptance criteria in PLAN.md are met
| # | Criterion | Result |
|---|---|---|
| 1 | ≥ 5 Starknet updates in Ere with versioned hashes = KZG commitments of our archived blobs | **8/8** (Ere mainnet-03200, L1 blocks 26214566–26215794, 3–6 blobs each) |
| 2 | Blobs decoded; ≥ 3 cross-checked against public Starknet data, 100 % match or every mismatch explained | **3/3** cross-checked. Exact parts 100 %. **All 6 mismatches in the sample plus 1 contract difference explained.** Storage-count differences are consistent with the same cause but not verified entry by entry (see below) |
| 3 | Unit tests pass; Opus audit PASS | **89 tests + 6 subtests pass**; audits/T2, T4, T6, T7 PASS (T6 after 2 small Opus fixes) |
| 4 | REPORT.md with method, results, limitations, effort | This document |

## Method (pipeline)
1. **Ere** (`src/ere_reader.py`): e2store + snappy + RLP, type-3 txs to the Starknet core contract **0xc662c410c0ecf747543f5ba90660f6abebd9c8c4** (confirmed on docs.starknet.io/learn/cheatsheets/chain-info), selector **0x507ee528** (`updateStateKzgDA`).
2. **Blobs** (`src/blob_store.py`): slot = (timestamp − 1606824023)/12 → `<blob-archive-root>/era_<slot//8192>/blobs_<slot>.ssz` (N × 131 072 B). KZG commitment recomputed with ckzg plus the Ethereum trusted setup → versioned hash compared with the tx.
3. **Decode** (`src/blob_decode.py`): bit-reversal + IFFT over BLS12-381 (port of starkware-libs/sequencer kzg/utils.rs).
4. **Decompress and parse** (`src/stateless.py`, `src/os_state_diff.py`): stateless compression v0, then contract headers, storage and class updates (port of the Rust reference, sequencer @312f7f6ca120).
5. **Aliases** (`src/aliases.py`): 0x2 original → alias. Aliases from this update come from our own data. Older ones come via public `starknet_getStorageAt(0x2, …)`.
6. **Cross-check** (`src/l1_update.py`, `src/starknet_public.py`, `src/crosscheck.py`, `src/cli.py`): the OS header from the calldata gives the Starknet block range. It is verified against the public block hash. Public `starknet_getStateUpdate` is aggregated over the range and compared.

## Results
### KZG (src/probe_kzg.py on Ere epoch 03200)
8/8 Starknet updates (blocks 26214566–26215794, slots 15453641–15454871) have all versioned hashes matched against blobs from our own archive.

### Decoded diffs and cross-check (results/out-t6/, public RPC starknet-rpc.publicnode.com, sample 200, seed 0)
| L1 block | Starknet range | Header | 0x2 storage | Class updates | Contracts ours/public | Storage ours/public | Sample (storage/nonce/class) |
|---|---|---|---|---|---|---|---|
| 26214566 | 16523851→16525351 | offset 0, verified | exact ✅ | exact ✅ | 761/761 | 22 679/22 924 | 197/200, 173/173, 30/30 |
| 26214569 | 16525351→16526851 | offset 0, verified | exact ✅ (6 519) | exact ✅ | 814/814 | 23 797/23 954 | 198/200, 173/173, 30/30 |
| 26214977 | 16526851→16528351 | offset 0, verified | exact ✅ | exact ✅ | 810/811 | 14 314/14 436 | 199/200, 182/182, 29/29 |

Each L1 update covers 1 500 Starknet blocks.

**Internal consistency:** the alias counter in 0x2 rises between consecutive updates by exactly the number of new alias assignments (6 518 and 4 057).

### Explanation of all differences
- **6 sample mismatches** (results/out-t6/mismatch-explanations.json): our diff is missing the key, while the public data has a value. Checked with `starknet_getStorageAt` before and after the range:
  - In 5 cases the value before = public value = value after. These are net no-op writes, which the OS correctly omits.
  - The 6th case (contract 0x95ad…7f) did not exist before the range: it was deployed within the range and wrote 0x0, which is the default value. Also a no-op.
- **Contract difference 810/811** (results/out-t6/contract-diff-26214977.json): the public-only contract 0x2ab5…94e2 (alias 0xb552) has no nonce or class change, and both of its storage writes are net no-ops. The OS therefore omits the whole contract.
- **Storage-count differences** (−245, −157, −122 ≈ 0.85–1.07 % of public entries) have the same signature: our diff is never larger, and every mismatch examined is a no-op. They have **not been verified entry by entry**, which would take about 15–23k RPC calls per update.

## Limitations
See docs/LIMITATIONS.md. In short:
- **Not verified:** KZG proofs and beacon inclusion. L1 acceptance is taken from the receipt status in the Ere file (not yet checked against the receipts root).
- **Alias bootstrap trusts public RPC** for aliases older than the window.
- **The cross-check is exact only for 0x2 and classes.** The rest is a sample plus counts.
- **Only updateStateKzgDA, full_output=0, compression v0** are supported. The archive starts around May 2025. PeerDAS columns are not decoded.
- **Pure Python and slow:** an Ere file takes about 5 min, and IFFT is single-threaded.

## Effort and model use (measured)
| Step | Model / who | Time |
|---|---|---|
| T1 ere_reader | gpt-6-astra high | 222 s |
| T2 blob_store + blob_decode | gpt-6-astra high | 105 s |
| T4 stateless + os_state_diff + aliases | gpt-6-astra high | 146 s |
| T6 l1_update, starknet_public, crosscheck, cli | gpt-6-astra high | 293 s |
| T7 README + LIMITATIONS | gpt-6-astra high | 57 s |
| Plan, refs, specs T4/T6/T7, review, 2 bug fixes, probes, audits, REPORT | claude-opus-5-5 (Oblix) | about 2.5 h of coordinator turns |
| Public RPC | publicnode.com, ≤ 2 req/s | 5 801 unique calls (on-disk cache 49 MB) + 12 manual getStorageAt checks |

GPT workers: 823 s in total, 5 calls, 0 rerounds. Token cost is not reported by `openclaw infer`. Human time used so far: 0.

## Next steps (not started, owner decision)
1. Exhaustive storage verification, or no-op filtering via a state-prior lookup for an entire update. This is a cost/time question for the public RPC, or for our own Starknet node.
2. Performance: native snappy/RLP or multiprocessing over Ere. Run more updates and the whole archive window.
3. ~~Verify KZG proofs off-chain~~ Superseded: updates are now selected only if their L1 receipt status is 1 (see docs/LIMITATIONS.md). A successful `updateStateKzgDA` has already passed `verifyKzgProofs` and the SHARP fact check; off-chain proof checks cannot rule out a reverted copy. Re-run on Ere 03200: 40/40 core blob transactions have status 1, so the results above are unchanged.
4. Feed into the Starknet Seed reassessment (N12) and an ESP/sponsor package (N6).
5. Alias bootstrap without trusting RPC: prove the pre-window 0x2 entries with `starknet_getStorageProof` at the end block of a recent update, checked against the `final_root` read from L1 (aliases are never reassigned, so one proof covers every earlier update). Suggested by Carlos (Zealynx).
