"""Coordinator probe (Oblix/Opus): find public contracts with no counterpart in our decoded diff.

For one L1 update: decode our ALIASED diff (from archive), aggregate the public diff over the Starknet
range (cached), map every public contract address to its alias (this update's 0x2 entries, else public
starknet_getStorageAt(0x2, address) at new_block; < 0x80 identity), and list public contracts whose alias
is absent from ours. For each such contract, check every public storage entry for net no-op (value before
the range == public value) and report nonce/class changes. Read-only; public RPC rate-limited + cached.

Usage: python -m src.explain_contracts <ere-file> <l1-block> <trusted-setup> <rpc-url> <cache-dir> <out-json>
"""
from __future__ import annotations

import json
import sys

from src import blob_decode, blob_store, ere_reader, l1_update, os_state_diff, starknet_public

CORE = bytes.fromhex("c662c410c0ecf747543f5ba90660f6abebd9c8c4")


def main() -> int:
    ere_file, l1_block, setup, rpc, cache, out = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6]
    ts = blob_store.load_trusted_setup(setup)
    tx = None
    for block in ere_reader.iter_blocks(ere_file):
        if block.number == l1_block:
            tx = next(t for t in ere_reader.blob_txs(block, CORE) if t.data[:4] == bytes.fromhex("507ee528"))
            break
    program, _ = l1_update.decode_calldata(tx.data)
    header = l1_update.parse_os_output_header(program)
    prev, new = header["prev_block_number"], header["new_block_number"]
    blobs = blob_store.match_blobs(blob_store.load_blobs(ere_reader.slot_for_timestamp(tx.timestamp)), tx.versioned_hashes, ts)
    ours = os_state_diff.decode_da(blob_decode.decode_blobs(blobs))
    ours_addrs = {c.address for c in ours.contracts}
    alias_entries = next((c.storage for c in ours.contracts if c.address == 2), {})
    client = starknet_public.PublicClient(rpc, cache, rate=2.0)
    updates = [client.call("starknet_getStateUpdate", {"block_id": {"block_number": n}}) for n in range(prev + 1, new + 1)]
    public = starknet_public.aggregate_state_updates(updates)

    def alias_of(addr: int) -> int:
        if addr < 0x80:
            return addr
        if addr in alias_entries:
            return alias_entries[addr]
        return int(client.call("starknet_getStorageAt", {"contract_address": "0x2", "key": hex(addr), "block_id": {"block_number": new}}), 16)

    missing = []
    for c in public.contracts:
        a = alias_of(c.address)
        if a not in ours_addrs:
            entries = []
            for k, v in c.storage.items():
                before = client.call("starknet_getStorageAt", {"contract_address": hex(c.address), "key": hex(k), "block_id": {"block_number": prev}})
                entries.append({"key": hex(k), "public": hex(v), "before": before, "net_noop": int(before, 16) == v})
            missing.append({"address": hex(c.address), "alias": hex(a), "nonce": c.nonce, "class_hash": hex(c.class_hash) if c.class_hash is not None else None,
                            "storage_entries": len(entries), "all_storage_net_noop": all(e["net_noop"] for e in entries), "entries": entries})
    res = {"l1_block": l1_block, "sn_prev": prev, "sn_new": new, "ours_contracts": len(ours_addrs), "public_contracts": len(public.contracts),
           "public_without_counterpart": missing}
    with open(out, "w") as f:
        json.dump(res, f, indent=1)
    print(json.dumps({k: (v if k != "public_without_counterpart" else [{x: m[x] for x in m if x != "entries"} for m in v]) for k, v in res.items()}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
