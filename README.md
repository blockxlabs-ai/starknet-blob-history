# starknet-blob-history

Recover and verify **Starknet state diffs from Ethereum history alone** — after the blobs have expired from the Ethereum p2p network (≈ 18 days).

Inputs are two kinds of Ethereum archives:
- **Ere** files (Ethereum execution history, [e2store Ere format](https://github.com/eth-clients/e2store-format-specs/blob/main/formats/ere.md)) — used to find Starknet's L1 state-update transactions and their blob versioned hashes;
- a **blob archive** (one `blobs_<slot>.ssz` file per beacon slot) — used to fetch the blobs.

Pipeline: find type-3 txs to the Starknet core contract (`0xc662…c8c4`) → load the blobs for the slot and **verify each one with KZG** against the tx's versioned hash → bit-reversal + inverse FFT over BLS12-381 → stateless decompression → parse the OS state diff → resolve stateful-compression aliases (contract `0x2`) → optionally **cross-check** against public Starknet JSON-RPC.

Status: **proof of concept**. On mainnet data (Ere epoch 03200) it matched 8/8 Starknet updates by KZG and cross-checked 3/3 decoded updates against public Starknet data; all differences are explained (net no-op writes are omitted by the Starknet OS). See [REPORT.md](REPORT.md) and [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

Public mirrors of the inputs run by BlockX Labs: https://ere.blockxlabs.ai (Ere), https://era1.blockxlabs.ai (era1).

## Use
```
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
# KZG trusted setup: https://github.com/ethereum/c-kzg-4844/blob/main/src/trusted_setup.txt
export BLOB_ARCHIVE_ROOTS=/path/to/blob-archive            # contains era_NNNNN/blobs_<slot>.ssz
python -m src.cli --ere /path/to/mainnet-03200-0bbc3b5f.ere --setup trusted_setup.txt \
    --rpc https://<a-public-starknet-rpc> --max-updates 3 --out out
python -m pytest -q tests
```

## Credits and licence
The blob decoding, stateless decompression and state-diff parsing are Python ports of StarkWare's reference implementation in [starkware-libs/sequencer](https://github.com/starkware-libs/sequencer) (Apache-2.0, commit 312f7f6ca120); see [NOTICE](NOTICE).
Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.

Built by [BlockX Labs](https://blockxlabs.ai). AI-assisted: see REPORT.md for how it was built.
