# Sample dataset

`samples/sample-03200/` is a proof-of-concept sample of Starknet state diffs
reconstructed from Ere epoch `03200` and archived Ethereum blobs. It covers
Starknet blocks **16523852–16528351**, inclusive: 4,500 blocks represented by
three L1 updates.

These are final state changes per L1-update range, not individual Starknet
block diffs or transaction execution traces. The sample contains 60,790
storage assignments, 1,526 contract-update rows, and one class declaration.

## Files

With `--json-gzip`, the range files are:

- `json/starknet-16523852-16525351.json.gz`
- `json/starknet-16525352-16526851.json.gz`
- `json/starknet-16526852-16528351.json.gz`

Each decompresses to one UTF-8 JSON object followed by a newline. Without
`--json-gzip`, the exporter writes the same JSON bytes to names ending in
`.json` instead. Gzip headers have `mtime=0` and no original filename.

The remaining files are:

| File | Contents |
| --- | --- |
| `parquet/updates.parquet` | Three update records: boundaries, provenance, OS headers, counts |
| `parquet/storage_diffs.parquet` | Storage assignments and address/key resolution |
| `parquet/contract_updates.parquet` | Nonce and/or class-hash changes |
| `parquet/declared_classes.parquet` | Class-hash to compiled-class-hash declarations |
| `manifest.json` | Provenance, code identity, selection, counts, coverage, diagnostics, file checksums |
| `README.md` | Generated file list, loading examples, and limitations |

Parquet files use Zstandard compression. `--no-parquet` omits all four
Parquet files; logical table counts remain in the manifest. The manifest
lists the actual generated filenames and is authoritative for a particular
export.

## Encoding and JSON layout

The data schema identifier is `starknet-l1-state-diff/v0`.

Felts are lowercase `0x`-prefixed hexadecimal strings without leading
padding: zero is `"0x0"`. Unresolved addresses and keys are JSON `null`.
Absent nonce or class-hash changes are also `null`, distinct from a change
to zero. L1 transaction and versioned hashes are byte-derived hex strings
and retain their fixed-width encoding.

Each range object has these fields:

| Field | Layout |
| --- | --- |
| `schema` | Data schema identifier |
| `starknet_range` | Integer `first`, `last`, and `blocks`; inclusive boundaries |
| `l1` | Integer `block`, `timestamp`, `tx_index`, `blob_count`; string `tx_hash`; string array `versioned_hashes` |
| `os_header` | All `HEADER_FIELDS` from `src/l1_update.py`, plus integer `offset` and boolean `verified_public` |
| `contracts` | Array of contract records described below |
| `declared_classes` | Array of `{class_hash, compiled_class_hash}` felt-string objects |
| `counts` | Integer `contracts`, `storage_diffs`, `contract_updates`, `declared_classes` |

An OS header's `prev_block_number`, `new_block_number`, `use_kzg_da`, and
`full_output` are JSON integers. Its other protocol fields are felt
strings. `offset` is the header's position in the program output.
`verified_public` indicates optional public-header verification, not
verification of the exported state diffs.

Each contract record contains:

- `address_alias`: the encoded address as a felt string.
- `address`: the resolved address or `null`.
- `address_resolution`: `identity`, `l1_range`, or `unresolved`.
- `nonce`, `class_hash`: felt strings or `null`.
- `storage`: an array of objects containing `key_alias`, `key`,
  `key_resolution`, and `value`. Aliases and values are felt strings;
  `key` may be `null`.

Contracts and storage keys are sorted numerically by their encoded values.
Declarations are sorted by class hash and compiled class hash. JSON object
keys are sorted, with compact separators.

## Parquet schemas

All fields are nullable in the explicit Arrow schemas, including in empty
tables. `string` below means an Arrow UTF-8 string, `int64` means a signed
64-bit integer, and `bool` means a boolean. Felt columns remain strings;
they are not truncated to machine integers.

Every table begins with:

| Columns | Type |
| --- | --- |
| `starknet_first`, `starknet_last` | `int64` |

### `updates`

One row per L1 update. In addition to the two boundary columns:

| Columns | Type |
| --- | --- |
| `starknet_blocks` | `int64` |
| `l1_block`, `l1_timestamp`, `l1_tx_index`, `l1_blob_count` | `int64` |
| `l1_tx_hash` | `string` |
| `l1_versioned_hashes` | `list<string>` |
| `initial_root`, `final_root` | `string` |
| `prev_block_number`, `new_block_number` | `int64` |
| `prev_block_hash`, `new_block_hash` | `string` |
| `os_program_hash`, `starknet_os_config_hash` | `string` |
| `use_kzg_da`, `full_output` | `int64` |
| `header_offset` | `int64` |
| `header_verified_public` | `bool` |
| `count_contracts`, `count_storage_diffs`, `count_contract_updates`, `count_declared_classes` | `int64` |

### `storage_diffs`

One row per storage assignment. In addition to the two boundary columns:

| Columns | Type |
| --- | --- |
| `address_alias`, `address`, `address_resolution` | `string` |
| `key_alias`, `key`, `key_resolution`, `value` | `string` |

### `contract_updates`

One row for each contract with a nonce and/or class-hash change. In addition
to the two boundary columns:

| Columns | Type |
| --- | --- |
| `address_alias`, `address`, `address_resolution` | `string` |
| `nonce`, `class_hash` | `string` |

### `declared_classes`

One row per declaration. In addition to the two boundary columns:

| Columns | Type |
| --- | --- |
| `class_hash`, `compiled_class_hash` | `string` |

## Manifest

The manifest schema is `starknet-l1-state-diff-manifest/v0`.

- `schema`, `data_schema`: manifest and range-data schema identifiers.
- `source_ere`: input basename and SHA-256, never its absolute path.
- `code_identity`: relative `src/` filenames mapped to SHA-256 hashes of
  loaded source modules, including loaded transitive dependencies.
- `counts`: logical row counts for the four Parquet tables.
- `alias_resolution_coverage`: address and key counts split into
  `identity`, `l1_range`, and `unresolved`.
- `selection`: `core_blob_transactions_seen`, `other_selectors_skipped`,
  and `reverted_skipped` counters.
- `failed_updates`: update provenance, stage, exception type, and header
  diagnostics when available. Exception messages are not emitted.
- `reverted_skipped`: provenance records for dropped matching-selector
  transactions; this is a list, unlike the counter inside `selection`.
- `range_break`: discontinuity diagnostics, or `null`.
- `run_error`: outer failure stage and exception type, or `null`.
- `parquet_enabled`: boolean.
- `limitations`: explicit scope qualifications.
- `files`: relative filenames mapped to `sha256` and byte length.

Selection counters describe the transaction prefix examined before the
update limit or an early stop, not necessarily every core transaction in
the file. Other selectors are excluded before checking receipt status.
Only status `1` updates count toward `--max-updates`. Ere receipts follow
all bodies, so reading the whole file is still necessary before the first
update becomes available.

Every generated file except the manifest itself is checksummed.
Self-hashing would be circular. Individual files are written atomically;
the manifest is written last. The output directory as a whole is not a
transactional snapshot. `--force` clears its existing contents.

The source used for the recorded sample was
`mainnet-03200-0bbc3b5f.ere`, SHA-256
`262c6a4bf2817e89aa412092d20efb00b398df50db704e0a71bc8b4e54f8b5f1`.
Code hashes and compressed-file checksums must be taken from the manifest
for the corresponding export, not copied from an earlier run.

## Alias resolution and coverage

Resolution kinds are:

- **`identity`**: no alias lookup is required. Addresses below `0x80`
  are identity values. Keys below `0x80`, and all keys of resolved system
  addresses at or below `0xf`, are identity values.
- **`l1_range`**: the mapping was learned from contract `0x2` assignments
  in the same update or an earlier successfully exported update.
- **`unresolved`**: the original is unknown and is exported as `null`.
  The alias is retained; the exporter does not guess.

Assignments are learned before resolving an update. An unresolved aliased
address does not prevent resolution of a known key alias: its original
address is above `0xf`, so keys at or above `0x80` are compressed and the
learned key map still applies.

The recorded sample's coverage is:

| Category | Identity | Learned in range | Unresolved | Resolved total |
| --- | ---: | ---: | ---: | ---: |
| Addresses | 6 | 262 | 2,117 | 268 / 2,385 |
| Storage keys | 22,562 | 17,822 | 20,406 | 40,384 / 60,790 |

Only **11% of addresses are resolved; 89% are unresolved**. Approximately
66% of keys are resolved and 34% unresolved. These are contract-record and
storage-entry counts across updates, not globally unique address or key
counts.

The unresolved mappings were allocated before the available range. The
blob archive begins after stateful alias compression was introduced, so
replaying that archive alone cannot recover the earlier assignments.
A one-time bootstrap of the alias table, contract `0x2` storage, from a
Starknet full node at the archive boundary would supply the missing
mappings for subsequent forward replay. Public RPC storage lookups do not
enumerate that table. This exporter performs neither bootstrap nor RPC
de-aliasing.

## Independent public-data check

A separate offline audit compared the sample with previously cached public
Starknet data. It reported **0 discrepancies in the checks performed**:

| Check | Result |
| --- | --- |
| Resolved addresses present in public data | 268 / 268 |
| Class hashes equal | 236 / 236 |
| Nonces equal | 50 / 50 |
| Resolved `(address, key)` values equal | 22,656 / 22,656; none different or missing |
| For unresolved addresses with resolved keys, `(key, value)` pair present in public data | 17,728 / 17,728 |
| Parquet versus JSON | Set equality for all three detail tables |

Pair presence for an unresolved address does not establish which address
owns that pair. These checks do not resolve the missing aliases, prove
state-root equivalence, or establish exhaustive equality with public
state diffs. Public data is a comparison source, not an independently
verified state proof.

The exporter itself does not perform this state-diff comparison.
Its optional `--rpc` argument verifies OS headers only.

## Loading

Run these examples from the repository root.

### DuckDB

