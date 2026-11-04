# Limitations

## Cryptographic verification boundary

KZG commitments are recomputed from archived blobs using the Ethereum trusted setup. Their derived versioned hashes are matched to those carried by the execution transactions.

**KZG proofs and beacon-block inclusion are NOT verified.** A commitment match establishes correspondence between the blob bytes and a transaction’s versioned hash; it must not be presented as verification of the complete beacon inclusion or data-availability proof chain.

## Alias bootstrap depends on public RPC

The blob archive starts approximately May 2025, after v0.13.4 introduced stateful alias compression. It therefore does not supply the complete earlier alias history.

Aliases allocated before the archive window are resolved through public `starknet_getStorageAt` calls on contract `0x2`. Reconstruction trusts that endpoint for those mappings. Aliases allocated within the same update come from our own decoded data.

Consequently, archive-only recovery of execution and blob payloads does not imply archive-only, trust-independent resolution of every address and storage key.

## Cross-check coverage is deliberately limited

The cross-check provides:

- Exact comparison of contract `0x2` storage updates.
- Exact comparison of class updates, including compiled-class-hash updates.
- Count-level comparison for contracts and storage.
- **Seeded, sampled** comparison of alias-resolved storage, nonce, and class-hash fields.

This is not exhaustive equivalence. Matching counts do not establish matching contents, and passing samples do not establish correctness of unsampled fields. Public RPC data is a comparison source, not an independently verified Starknet state proof.

## Net no-op writes affect comparisons

Public per-block state updates include writes that can be no-ops across the complete L1 range: the value after the range equals its value before the range. The OS omits these net no-ops, so aggregating public per-block updates can produce different counts and apparent field mismatches.

Such differences must be reported and explained, not silently discarded or counted as unexplained successes.

For the first recorded cross-check:

- Two sampled storage discrepancies were explained by public values of `0x0` both before and after the range.
- The decoded storage count was 157 below the public count. The workboard attributed this to no-op writes but explicitly said they had **not yet been individually verified**.

Final run (REPORT.md): all 6 sampled mismatches and the single contract-count difference across the three updates were verified as net no-ops (or a zero write by a contract deployed within the range). Storage-count deficits (−245/−157/−122) share that signature but were not verified entry by entry.

## Supported format scope

Supported scope is limited to:

- `updateStateKzgDA`, selector `0x507ee528`.
- `full_output=0`.
- Compression version `0`.
- v0.13.3+ stateless-compressed state diffs, including v0.13.4+ alias handling.

Older formats, including pre-v0.13.3 calldata/blob layouts, are not supported. The supported version labels do not imply compatibility with every later format change.

## Archive gaps and PeerDAS columns

The blob archive begins approximately May 2025. Missing archive data constrains which updates can be recovered.

Slots available only as `columns_<slot>.ssz` PeerDAS columns are reported but not decoded. These files are not interchangeable with the supported concatenated-blob files. A reported gap is not a successful recovery.

## Performance

Ere decoding is pure Python and takes minutes per file in the recorded probe. IFFT decoding is also a performance limitation. There is no parallelism.

The supplied observations are not a general throughput benchmark. For final measurements and run-specific performance, see REPORT.md.

## Public RPC availability

Public RPC access is rate-limited and cached on disk. Endpoint availability and method support vary; several public endpoints tested during the build had been discontinued, while others failed to answer or rejected access.

A previously usable endpoint is not a guarantee of future availability. Public RPC failures can prevent alias bootstrap or cross-check completion even when the archive data is present.

## Interim validation, not completed acceptance

The full three-update run completed; acceptance criteria are assessed in REPORT.md, with the count-level qualification above.

For final completion status, results, and any remaining discrepancies, see REPORT.md.

## Not production software

This is an engineering proof of concept, not production software. There has been no security review beyond the coordinator audits. Worker-generated code was reviewed by Claude Opus 5.5; audit records are in `audits/`.

Those reviews do not constitute a comprehensive independent security assessment or a guarantee of correctness.
