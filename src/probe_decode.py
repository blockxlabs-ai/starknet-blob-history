"""Coordinator probe (Oblix/Opus, not a worker deliverable): decode real Starknet DA blobs.

For the first N Starknet state-update txs in an Ere file: match archived blobs by KZG, IFFT-decode
(blob_decode), stateless-decompress + parse (os_state_diff.decode_da). Addresses/keys stay ALIASED.
Read-only on archive data. Prints one JSON summary per tx; with --dump writes the aliased diff of
the first tx to runs/diff-<block>.json.

Usage: python -m src.probe_decode <ere-file> <core-address> <trusted-setup> [n_txs] [--dump]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from src import blob_decode, blob_store, ere_reader, os_state_diff, stateless


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    dump = "--dump" in sys.argv
    ere_file, address, setup = Path(args[0]), args[1], args[2]
    n_txs = int(args[3]) if len(args) > 3 else 3
    to = bytes.fromhex(address.removeprefix("0x"))
    ts = blob_store.load_trusted_setup(setup)
    done = 0
    for block in ere_reader.iter_blocks(ere_file):
        for tx in ere_reader.blob_txs(block, to):
            slot = ere_reader.slot_for_timestamp(tx.timestamp)
            blobs = blob_store.match_blobs(blob_store.load_blobs(slot), tx.versioned_hashes, ts)
            felts = blob_decode.decode_blobs(blobs)
            it = iter(felts)
            header = stateless.unpack_felts_to([next(it)], 9, stateless.HEADER_ELM_BOUND)
            diff = os_state_diff.decode_da(felts)
            n_storage = sum(len(c.storage) for c in diff.contracts)
            alias_rec = next((c for c in diff.contracts if c.address == 2), None)
            rec = {"block": tx.block_number, "tx": "0x" + tx.tx_hash.hex(), "blobs": len(blobs),
                   "felts": len(felts), "nonzero_felts": sum(1 for f in felts if f),
                   "stateless_header": {"version": header[0], "data_len": header[1],
                                        "bucket_lens": header[2:8], "n_repeats": header[8]},
                   "contracts": len(diff.contracts), "storage_updates": n_storage,
                   "nonce_updates": sum(1 for c in diff.contracts if c.nonce is not None),
                   "class_replacements": sum(1 for c in diff.contracts if c.class_hash is not None),
                   "declared_classes": len(diff.classes),
                   "alias_contract_entries": len(alias_rec.storage) if alias_rec else 0,
                   "alias_counter": hex(alias_rec.storage.get(0)) if alias_rec and 0 in alias_rec.storage else None}
            print(json.dumps(rec), flush=True)
            if dump and done == 0:
                out = Path("runs") / f"diff-{tx.block_number}-aliased.json"
                out.parent.mkdir(exist_ok=True)
                out.write_text(json.dumps({
                    "block": tx.block_number, "tx": "0x" + tx.tx_hash.hex(), "aliased": True,
                    "contracts": [{"address": hex(c.address), "nonce": c.nonce, "class_hash": hex(c.class_hash) if c.class_hash is not None else None,
                                   "storage": {hex(k): hex(v) for k, v in c.storage.items()}} for c in diff.contracts],
                    "classes": [{"class_hash": hex(c.class_hash), "compiled_class_hash": hex(c.compiled_class_hash)} for c in diff.classes]}, indent=1))
            done += 1
            if done >= n_txs:
                return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
