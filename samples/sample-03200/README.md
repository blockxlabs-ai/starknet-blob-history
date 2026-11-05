# Starknet L1 state-diff sample

Internal sample; nothing is published.

- `json/starknet-16523852-16525351.json.gz`: one reconstructed diff per L1 update.
- `json/starknet-16525352-16526851.json.gz`: one reconstructed diff per L1 update.
- `json/starknet-16526852-16528351.json.gz`: one reconstructed diff per L1 update.
- `parquet/updates.parquet`: L1 provenance, OS headers and counts.
- `parquet/storage_diffs.parquet`: storage assignments with alias resolution.
- `parquet/contract_updates.parquet`: nonce and/or class-hash changes.
- `parquet/declared_classes.parquet`: compiled-class-hash declarations.
- `manifest.json`: source/code hashes, coverage, failures and file checksums.

Run these examples from this directory:

DuckDB: `SELECT * FROM read_parquet('parquet/storage_diffs.parquet');`

pandas: `import pandas as pd; df = pd.read_parquet('parquet/storage_diffs.parquet')`

Felts are lowercase hexadecimal strings; unresolved originals are null.
Coverage counts each contract address and each storage key once per update.
The manifest inventories every generated file except itself (self-hashing
would be circular). Boolean verification status uses a Parquet boolean;
numeric fields use int64. Versioned hashes are a list of strings.

## Limitations

- Aliases assigned before the range are unresolved without a bootstrap; this exporter does not bootstrap or use RPC for de-aliasing.
- Storage values are final values per L1-update range, not per Starknet block.
- No state-diff public cross-check is performed in this export; optional RPC access verifies only OS headers.
- Deprecated Cairo-0 declarations are not in the KZG DA diff.
- Selection drops reverted L1 transactions (receipt status != 1).
