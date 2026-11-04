"""Coordinator probe (Oblix/Opus, not a worker deliverable): real-data KZG match.

Scan one Ere file for type-3 txs to the Starknet core contract, then for each tx load the
archived blobs for its beacon slot, recompute KZG commitments and match the tx's versioned
hashes. Read-only on archive data. Prints one JSON line per tx and a summary line.

Usage: python -m src.probe_kzg <ere-file> <core-address> <trusted-setup> [max_txs]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from src import blob_store, ere_reader


def main() -> int:
    ere_file, address, setup = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
    max_txs = int(sys.argv[4]) if len(sys.argv) > 4 else 10
    to = bytes.fromhex(address.removeprefix("0x"))
    ts = blob_store.load_trusted_setup(setup)
    seen = matched = 0
    selectors: dict[str, int] = {}
    for block in ere_reader.iter_blocks(ere_file):
        for tx in ere_reader.blob_txs(block, to):
            seen += 1
            sel = tx.data[:4].hex()
            selectors[sel] = selectors.get(sel, 0) + 1
            slot = ere_reader.slot_for_timestamp(tx.timestamp)
            found = blob_store.find_slot_file(slot)
            rec = {"block": tx.block_number, "tx": "0x" + tx.tx_hash.hex(), "selector": "0x" + sel,
                   "n_blobs": len(tx.versioned_hashes), "slot": slot, "slot_file": found.status}
            if found.status == "blobs":
                blobs = blob_store.load_blobs(slot)
                rec["archived_blobs"] = len(blobs)
                try:
                    blob_store.match_blobs(blobs, tx.versioned_hashes, ts)
                    rec["kzg_match"] = True
                    matched += 1
                except blob_store.MissingBlobsError as exc:
                    rec["kzg_match"] = False
                    rec["missing"] = len(exc.missing_hashes)
            print(json.dumps(rec), flush=True)
            if seen >= max_txs:
                print(json.dumps({"summary": True, "txs": seen, "kzg_matched": matched, "selectors": selectors}))
                return 0
    print(json.dumps({"summary": True, "txs": seen, "kzg_matched": matched, "selectors": selectors}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
