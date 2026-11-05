"""End-to-end Ere/blob/public-data cross-check.

Header discovery has a circular dependency: the public block hash requires
a block number, while the prefix location is initially unknown. We examine
only offsets 0..64 using the specified structural conditions, query each
candidate's block number, and accept a candidate only after public hash
verification. No prefix format is assumed. RPC block-not-found rejects a
candidate; other RPC failures abort that update rather than being hidden.

Only blob transactions to the core with the specified selector and a
successful receipt (status 1, read from the same Ere file) count towards
--max-updates. Other selectors and reverted transactions are counted
separately. Receipts follow all bodies in Ere, so the first update is
available only after the whole file has been read.
Transactions missing blob files, unsupported full_output payloads, decoding
failures, and public-data failures produce explicit failed update records.

Multiple updates in one L1 block are stored in the same <l1_block>.json
under "updates", avoiding overwrites. No checked updates is a failure.
Sampling-limit/deprecated-declaration skips are expected; resolution errors
are failures. Totals alone are informational, as documented in crosscheck.

This CLI is intentionally limited to the supplied partial/stateless DA
decoder. A full_output header is rejected rather than decoded as partial.
Exception text and endpoint URLs are never included in output.
"""

import argparse
from collections import Counter
from itertools import islice
from pathlib import Path

from .crosscheck import crosscheck, markdown_summary
from .l1_update import (
    SELECTOR,
    HeaderError,
    decode_calldata,
    find_os_header,
    parse_os_output_header,
)
from .os_state_diff import decode_da
from .starknet_public import (
    PublicClient,
    RPCError,
    aggregate_state_updates,
    atomic_json,
    felt,
)


DEFAULT_CORE = "0xc662c410c0ecf747543f5ba90660f6abebd9c8c4"


def verified_header(program_output, client) -> tuple[int, dict, dict]:
    diagnostics = Counter()
    hashes = {}
    for offset in range(min(65, max(0, len(program_output) - 9))):
        diagnostics["offsets_examined"] += 1
        try:
            candidate = parse_os_output_header(program_output[offset:offset + 10])
        except HeaderError:
            diagnostics["structurally_rejected"] += 1
            continue
        if (
            candidate["use_kzg_da"] != 1
            or candidate["new_block_number"] <= candidate["prev_block_number"]
        ):
            diagnostics["structurally_rejected"] += 1
            continue
        number = candidate["new_block_number"]
        if number not in hashes:
            try:
                hashes[number] = client.get_block_hash(number)
            except RPCError as exc:
                if exc.code != 24:  # Starknet RPC: block not found.
                    raise
                hashes[number] = None
        expected = hashes[number]
        if expected is None:
            diagnostics["block_not_found"] += 1
            continue
        if candidate["new_block_hash"] != expected:
            diagnostics["hash_rejected"] += 1
            continue

        # Verify at the candidate itself, then call the required locator on
        # the complete program output. The number is checked again so a
        # repeated hash in a different window cannot redirect the range.
        located, header = find_os_header(program_output, expected)
        if header["new_block_number"] != number:
            raise HeaderError("Conflicting candidate block numbers")
        return located, header, dict(diagnostics)
    raise HeaderError("No candidate header verified against public data")


def _core(value: str) -> bytes:
    try:
        if not value.startswith("0x") or len(value) != 42:
            raise ValueError
        result = bytes.fromhex(value[2:])
        if len(result) != 20:
            raise ValueError
        return result
    except ValueError:
        raise argparse.ArgumentTypeError("core must be a 20-byte hex address") from None


def _positive(value: str) -> int:
    result = int(value)
    if result <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return result


def _sample_size(value: str) -> int:
    result = int(value)
    if not 0 <= result <= 200:
        raise argparse.ArgumentTypeError("sample must be in 0..200")
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ere", required=True)
    parser.add_argument("--core", type=_core, default=DEFAULT_CORE)
    parser.add_argument("--setup", required=True)
    parser.add_argument("--rpc", required=True)
    parser.add_argument("--max-updates", type=_positive, default=3)
    parser.add_argument("--sample", type=_sample_size, default=200)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--rate", type=float, default=2.0)
    parser.add_argument("--cache", default=".cache/starknet-public")
    parser.add_argument("--out", default="out")
    args = parser.parse_args(argv)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    groups = {}
    summaries = ["# Starknet DA cross-check\n"]
    counters = Counter()
    failures = 0
    checked = 0
    run_error = None

    try:
        # Keep CLI helper imports usable in offline tests without loading
        # the existing blob/KZG implementations.
        from .blob_decode import decode_blobs
        from .blob_store import (
            find_slot_file,
            load_blobs,
            load_trusted_setup,
            match_blobs,
        )
        from .ere_reader import blob_txs_with_status, slot_for_timestamp

        client = PublicClient(args.rpc, args.cache, rate=args.rate)
        trusted_setup = load_trusted_setup(args.setup)  # Opus fix: keep the setup (T6-1 discarded it)

        def updates():
            for transaction in blob_txs_with_status(args.ere, args.core):
                counters["core_blob_transactions_seen"] += 1
                if transaction.data[:4] != SELECTOR:
                    counters["other_selectors_skipped"] += 1
                    continue
                # A reverted tx still carries blobs that match its versioned
                # hashes; only a successful one passed the core's proof checks.
                if transaction.status != 1:
                    counters["reverted_skipped"] += 1
                    continue
                yield transaction

        for transaction in islice(updates(), args.max_updates):
            counters["updates_selected"] += 1
            block_number = transaction.block_number
            record = {
                "l1_block": block_number,
                "timestamp": transaction.timestamp,
                "tx_index": transaction.tx_index,
                "tx_hash": "0x" + transaction.tx_hash.hex(),
                "versioned_hashes": [
                    "0x" + value.hex() for value in transaction.versioned_hashes
                ],
                "ok": False,
            }
            stage = "calldata"
            try:
                program, proofs = decode_calldata(transaction.data)
                record["program_output_words"] = len(program)
                record["kzg_proof_count"] = len(proofs)

                stage = "header_verification"
                offset, header, discovery = verified_header(program, client)
                record["os_header_offset"] = offset
                record["os_header"] = header
                record["header_discovery"] = discovery
                if header["full_output"] != 0:
                    stage = "unsupported_full_output"
                    raise ValueError("Partial DA decoder cannot decode full output")

                stage = "blob_loading"
                slot = slot_for_timestamp(transaction.timestamp)
                record["slot"] = slot
                record["slot_file_status"] = find_slot_file(slot).status
                slot_blobs = load_blobs(slot)
                if slot_blobs is None:
                    raise FileNotFoundError("No available blobs for slot")
                if not transaction.versioned_hashes:
                    raise ValueError("Update has no versioned blob hashes")

                stage = "blob_matching"
                blobs = match_blobs(
                    slot_blobs,
                    transaction.versioned_hashes,
                    trusted_setup,  # Opus fix: was transaction.timestamp
                )
                if len(blobs) != len(transaction.versioned_hashes):
                    raise ValueError("Blob matcher returned the wrong count")

                stage = "blob_decoding"
                ours = decode_da(decode_blobs(blobs))

                stage = "public_state_updates"
                previous = header["prev_block_number"]
                new = header["new_block_number"]
                public_updates = [
                    client.get_state_update(number)
                    for number in range(previous + 1, new + 1)
                ]
                record["starknet_range"] = {
                    "first": previous + 1,
                    "last": new,
                    "blocks": len(public_updates),
                }

                # Verify boundaries and continuity, in addition to the
                # independent public hash used for header discovery.
                stage = "public_chain_validation"
                chain_errors = []
                if felt(public_updates[0]["old_root"]) != header["initial_root"]:
                    chain_errors.append("initial_root")
                if felt(public_updates[-1]["new_root"]) != header["final_root"]:
                    chain_errors.append("final_root")
                if felt(public_updates[-1]["block_hash"]) != header["new_block_hash"]:
                    chain_errors.append("new_block_hash")
                for index in range(1, len(public_updates)):
                    if (
                        felt(public_updates[index - 1]["new_root"])
                        != felt(public_updates[index]["old_root"])
                    ):
                        chain_errors.append(f"root_link_at_{previous + 1 + index}")
                record["public_chain_errors"] = chain_errors

                stage = "crosscheck"
                public = aggregate_state_updates(public_updates)
                report = crosscheck(
                    ours, public, client, new,
                    sample=args.sample, seed=args.seed,
                )
                record["crosscheck"] = report
                record["mismatch_count"] = (
                    report["mismatch_count"] + len(chain_errors)
                )
                record["ok"] = report["ok"] and not chain_errors
                checked += 1
                summaries.append(
                    f"## L1 block {block_number}, transaction "
                    f"{transaction.tx_index}\n\n"
                    + markdown_summary(report)
                    + (
                        f"\n**FAIL:** {len(chain_errors)} public-chain "
                        "boundary/continuity assertions failed.\n"
                        if chain_errors else ""
                    )
                )
            except Exception as exc:
                # Do not leak URLs, response bodies, filesystem paths, or
                # arbitrary dependency exception messages into artifacts.
                record["error"] = {
                    "stage": stage,
                    "type": type(exc).__name__,
                }
                summaries.append(
                    f"## L1 block {block_number}, transaction "
                    f"{transaction.tx_index}\n\n"
                    f"**FAIL** — stage `{stage}`, "
                    f"error type `{type(exc).__name__}`.\n"
                )

            if not record["ok"]:
                failures += 1
            groups.setdefault(block_number, []).append(record)
            atomic_json(
                out / f"{block_number}.json",
                {"l1_block": block_number, "updates": groups[block_number]},
            )
    except Exception as exc:
        run_error = type(exc).__name__
        summaries.append(f"**Run failure:** `{run_error}`.\n")

    summaries.append(
        "## Run totals\n\n"
        f"- Selected updates: {counters['updates_selected']}.\n"
        f"- Completed cross-checks: {checked}.\n"
        f"- Failed updates: {failures}.\n"
        f"- Other core blob selectors skipped: "
        f"{counters['other_selectors_skipped']}.\n"
        f"- Reverted core blob transactions skipped: "
        f"{counters['reverted_skipped']}.\n"
        "- PASS means the stated exact and sampled assertions passed; "
        "it is not exhaustive equivalence of every state-diff field.\n"
    )
    if checked == 0:
        summaries.append("**FAIL:** no updates were cross-checked.\n")
    (out / "SUMMARY.md").write_text("\n".join(summaries), encoding="utf-8")
    return 0 if checked > 0 and failures == 0 and run_error is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
