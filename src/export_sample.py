"""Export a contiguous sample of L1-reconstructed state diffs."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from copy import deepcopy
from itertools import islice

from .aliases import AliasMap
from .l1_update import HEADER_FIELDS, SELECTOR, decode_calldata, find_os_header
from .os_state_diff import StateDiff, decode_da


SCHEMA = "starknet-l1-state-diff/v0"
INTEGER_HEADER_FIELDS = {
    "prev_block_number", "new_block_number", "use_kzg_da", "full_output",
}
COUNT_FIELDS = (
    "contracts", "storage_diffs", "contract_updates", "declared_classes",
)
SELECTION_FIELDS = (
    "core_blob_transactions_seen", "other_selectors_skipped", "reverted_skipped",
)
RESOLUTIONS = ("identity", "l1_range", "unresolved")
LIMITATIONS = [
    "Aliases assigned before the range are unresolved without a bootstrap; "
    "this exporter does not bootstrap or use RPC for de-aliasing.",
    "Storage values are final values per L1-update range, not per Starknet block.",
    "No state-diff public cross-check is performed in this export; optional "
    "RPC access verifies only OS headers.",
    "Deprecated Cairo-0 declarations are not in the KZG DA diff.",
    "Selection drops reverted L1 transactions (receipt status != 1).",
]


def felt_hex(value: int | None) -> str | None:
    return None if value is None else hex(value)


def resolve_diff(diff: StateDiff, alias_map: AliasMap) -> list[dict]:
    """Learn this update's assignments, then resolve without guessing.

    The supplied map must contain only assignments learned during this run.
    It is updated; the input diff is not modified.
    """
    alias_map.update_from_diff(diff)
    contracts = []
    for contract in sorted(diff.contracts, key=lambda item: item.address):
        try:
            address = alias_map.resolve_address(contract.address)
        except KeyError:
            address = None
        address_resolution = (
            "unresolved" if address is None
            else "identity" if contract.address < 0x80
            else "l1_range"
        )

        storage = []
        for key_alias, value in sorted(contract.storage.items()):
            if key_alias < 0x80 or (address is not None and address <= 0xF):
                key, resolution = key_alias, "identity"
            else:
                # Opus fix: an unresolved address is an alias >= 0x80,
                # so its original is > 0xF and keys >= 0x80 ARE compressed
                # (should_compress_storage_key); resolve them from the map.
                try:
                    key = alias_map.resolve_key(key_alias)
                    resolution = "l1_range"
                except KeyError:
                    key, resolution = None, "unresolved"
            storage.append({
                "key_alias": felt_hex(key_alias),
                "key": felt_hex(key),
                "key_resolution": resolution,
                "value": felt_hex(value),
            })

        contracts.append({
            "address_alias": felt_hex(contract.address),
            "address": felt_hex(address),
            "address_resolution": address_resolution,
            "nonce": felt_hex(contract.nonce),
            "class_hash": felt_hex(contract.class_hash),
            "storage": storage,
        })
    return contracts


def range_break(previous_last: int | None, header: dict) -> dict | None:
    """Return a diagnostic when the next update does not extend the range."""
    previous = header["prev_block_number"]
    if previous_last is None or previous == previous_last:
        return None
    return {
        "expected_prev_block_number": previous_last,
        "actual_prev_block_number": previous,
        "new_block_number": header["new_block_number"],
    }


def update_record(
    diff: StateDiff,
    alias_map: AliasMap,
    *,
    header: dict,
    header_offset: int,
    header_verified_public: bool,
    l1: dict,
) -> dict:
    """Build a JSON-ready record; only the supplied alias map is mutated."""
    previous = header["prev_block_number"]
    new = header["new_block_number"]
    if new <= previous or header["full_output"] != 0 or header["use_kzg_da"] != 1:
        raise ValueError("Unsupported OS header")

    contracts = resolve_diff(diff, alias_map)
    classes = [
        {
            "class_hash": felt_hex(item.class_hash),
            "compiled_class_hash": felt_hex(item.compiled_class_hash),
        }
        for item in sorted(
            diff.classes,
            key=lambda item: (item.class_hash, item.compiled_class_hash),
        )
    ]
    counts = {
        "contracts": len(contracts),
        "storage_diffs": sum(len(item["storage"]) for item in contracts),
        "contract_updates": sum(
            item["nonce"] is not None or item["class_hash"] is not None
            for item in contracts
        ),
        "declared_classes": len(classes),
    }
    os_header = {
        name: header[name] if name in INTEGER_HEADER_FIELDS else felt_hex(header[name])
        for name in HEADER_FIELDS
    }
    os_header.update(
        offset=header_offset,
        verified_public=header_verified_public,
    )
    return {
        "schema": SCHEMA,
        "starknet_range": {
            "first": previous + 1,
            "last": new,
            "blocks": new - previous,
        },
        "l1": {
            "block": l1["block"],
            "timestamp": l1["timestamp"],
            "tx_index": l1["tx_index"],
            "tx_hash": l1["tx_hash"],
            "versioned_hashes": list(l1["versioned_hashes"]),
            "blob_count": l1["blob_count"],
        },
        "os_header": os_header,
        "contracts": contracts,
        "declared_classes": classes,
        "counts": counts,
    }


def parquet_schemas(pa) -> dict:
    """Schemas are explicit even for empty tables and all-null columns."""
    string, integer = pa.string(), pa.int64()
    bounds = [
        ("starknet_first", integer),
        ("starknet_last", integer),
    ]
    address = [
        ("address_alias", string),
        ("address", string),
        ("address_resolution", string),
    ]
    return {
        "updates": pa.schema(bounds + [
            ("starknet_blocks", integer),
            ("l1_block", integer),
            ("l1_timestamp", integer),
            ("l1_tx_index", integer),
            ("l1_tx_hash", string),
            ("l1_versioned_hashes", pa.list_(string)),
            ("l1_blob_count", integer),
        ] + [
            (name, integer if name in INTEGER_HEADER_FIELDS else string)
            for name in HEADER_FIELDS
        ] + [
            ("header_offset", integer),
            ("header_verified_public", pa.bool_()),
        ] + [
            (f"count_{name}", integer) for name in COUNT_FIELDS
        ]),
        "storage_diffs": pa.schema(bounds + address + [
            ("key_alias", string),
            ("key", string),
            ("key_resolution", string),
            ("value", string),
        ]),
        "contract_updates": pa.schema(bounds + address + [
            ("nonce", string),
            ("class_hash", string),
        ]),
        "declared_classes": pa.schema(bounds + [
            ("class_hash", string),
            ("compiled_class_hash", string),
        ]),
    }


def table_rows(records: list[dict]) -> dict[str, list[dict]]:
    tables = {
        name: [] for name in (
            "updates", "storage_diffs", "contract_updates", "declared_classes",
        )
    }
    for record in records:
        bounds = {
            "starknet_first": record["starknet_range"]["first"],
            "starknet_last": record["starknet_range"]["last"],
        }
        header, l1 = record["os_header"], record["l1"]
        tables["updates"].append({
            **bounds,
            "starknet_blocks": record["starknet_range"]["blocks"],
            **{f"l1_{name}": value for name, value in l1.items()},
            **{name: header[name] for name in HEADER_FIELDS},
            "header_offset": header["offset"],
            "header_verified_public": header["verified_public"],
            **{f"count_{name}": record["counts"][name] for name in COUNT_FIELDS},
        })
        for contract in record["contracts"]:
            address = {
                name: contract[name]
                for name in ("address_alias", "address", "address_resolution")
            }
            if contract["nonce"] is not None or contract["class_hash"] is not None:
                tables["contract_updates"].append({
                    **bounds,
                    **address,
                    "nonce": contract["nonce"],
                    "class_hash": contract["class_hash"],
                })
            for storage in contract["storage"]:
                tables["storage_diffs"].append({
                    **bounds, **address, **storage,
                })
        for declaration in record["declared_classes"]:
            tables["declared_classes"].append({**bounds, **declaration})
    return tables


def _json_bytes(value) -> bytes:
    return (
        json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _atomic_write(path: Path, writer) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            writer(stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _write_bytes(path: Path, data: bytes) -> None:
    _atomic_write(path, lambda stream: stream.write(data))


def _write_gzip(path: Path, data: bytes) -> None:
    def writer(stream):
        # Do not include the temporary filename or wall-clock time.
        with gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=0) as zipped:
            zipped.write(data)

    _atomic_write(path, writer)


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _code_identity() -> dict[str, str]:
    """Hash loaded source modules, including transitive src dependencies."""
    source = Path(__file__).resolve().parent
    loaded = {
        Path(filename).resolve()
        for module in list(sys.modules.values())
        if isinstance(filename := getattr(module, "__file__", None), str)
    }
    loaded.add(Path(__file__).resolve())  # Also covers execution via -m.
    return {
        f"src/{path.name}": _sha256(path)
        for path in sorted(source.glob("*.py"))
        if path.resolve() in loaded
    }


def _parquet_modules():
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError:
        raise RuntimeError(
            "Parquet export requires pyarrow; install it or use --no-parquet."
        ) from None
    return pa, pq


def _check_out(out: Path, force: bool) -> None:
    if out.is_symlink():
        raise FileExistsError("Output directory must not be a symlink")
    if out.exists():
        if not out.is_dir() or (not force and any(out.iterdir())):
            raise FileExistsError("Output directory is not empty; use --force")


def _prepare_out(out: Path, force: bool) -> None:
    _check_out(out, force)
    out.mkdir(parents=True, exist_ok=True)
    if force:
        for child in out.iterdir():
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()


def _readme(parquet: bool, json_files: list[str]) -> bytes:
    text = """# Starknet L1 state-diff sample

Internal sample; nothing is published.

"""
    text += "".join(
        f"- `{name}`: one reconstructed diff per L1 update.\n"
        for name in json_files
    )
    text += """- `parquet/updates.parquet`: L1 provenance, OS headers and counts.
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

"""
    if not parquet:
        text += "Parquet was disabled for this run; the loading examples require it.\n\n"
    text += "## Limitations\n\n"
    text += "".join(f"- {item}\n" for item in LIMITATIONS)
    return text.encode("utf-8")


def write_outputs(
    records,
    out,
    *,
    ere,
    no_parquet: bool = False,
    json_gzip: bool = False,
    force: bool = False,
    failed_updates=(),
    reverted_skipped=(),
    selection: dict | None = None,
    range_break_record: dict | None = None,
    run_error: dict | None = None,
) -> dict:
    """Write deterministic artifacts, atomically replacing each file.

    --force replaces the directory's contents. The manifest is written last.
    Table counts describe logical rows, including when Parquet is disabled.
    """
    modules = None if no_parquet else _parquet_modules()
    records = list(records)
    previous_last = None
    for record in records:
        header = record["os_header"]
        if range_break(previous_last, header) is not None:
            raise ValueError("Records are not contiguous")
        previous_last = header["new_block_number"]

    source = Path(ere)
    source_info = {"basename": source.name, "sha256": _sha256(source)}
    code_identity = _code_identity()
    tables = table_rows(records)
    coverage = {
        category: dict.fromkeys(RESOLUTIONS, 0)
        for category in ("addresses", "keys")
    }
    for record in records:
        for contract in record["contracts"]:
            coverage["addresses"][contract["address_resolution"]] += 1
            for storage in contract["storage"]:
                coverage["keys"][storage["key_resolution"]] += 1

    out = Path(out)
    _prepare_out(out, force)
    written = []
    json_files = []
    for record in records:
        bounds = record["starknet_range"]
        relative = f"json/starknet-{bounds['first']}-{bounds['last']}.json"
        if json_gzip:
            relative += ".gz"
            _write_gzip(out / relative, _json_bytes(record))
        else:
            _write_bytes(out / relative, _json_bytes(record))
        written.append(relative)
        json_files.append(relative)

    if modules is not None:
        pa, pq = modules
        for name, schema in parquet_schemas(pa).items():
            table = pa.Table.from_pylist(tables[name], schema=schema)
            relative = f"parquet/{name}.parquet"
            _atomic_write(
                out / relative,
                lambda stream, table=table: pq.write_table(
                    table, stream, compression="zstd",
                ),
            )
            written.append(relative)

    _write_bytes(out / "README.md", _readme(not no_parquet, json_files))
    written.append("README.md")
    manifest = {
        "schema": "starknet-l1-state-diff-manifest/v0",
        "data_schema": SCHEMA,
        "source_ere": source_info,
        "code_identity": code_identity,
        "counts": {name: len(rows) for name, rows in tables.items()},
        "alias_resolution_coverage": coverage,
        "selection": {
            name: (selection or {}).get(name, 0) for name in SELECTION_FIELDS
        },
        "failed_updates": list(failed_updates),
        "reverted_skipped": list(reverted_skipped),
        "range_break": range_break_record,
        "run_error": run_error,
        "parquet_enabled": not no_parquet,
        "limitations": list(LIMITATIONS),
        "files": {
            relative: {
                "sha256": _sha256(out / relative),
                "bytes": (out / relative).stat().st_size,
            }
            for relative in sorted(written)
        },
    }
    _write_bytes(out / "manifest.json", _json_bytes(manifest))
    return manifest


def _selected_updates(transactions, selection: dict, reverted: list):
    """Filter core blob transactions in release CLI selection order."""
    for transaction in transactions:
        selection["core_blob_transactions_seen"] += 1
        if transaction.data[:4] != SELECTOR:
            selection["other_selectors_skipped"] += 1
            continue
        # A reverted tx can carry copied calldata and its own blobs;
        # only a successful one passed the core's proof checks.
        if transaction.status != 1:
            selection["reverted_skipped"] += 1
            reverted.append({
                "l1_block": transaction.block_number,
                "l1_tx_index": transaction.tx_index,
                "l1_tx_hash": "0x" + transaction.tx_hash.hex(),
            })
            continue
        yield transaction


def _positive(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ere", required=True)
    parser.add_argument("--setup", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--max-updates", type=_positive, default=3)
    parser.add_argument("--rpc")
    parser.add_argument("--cache", default=".cache/starknet-public")
    parser.add_argument("--no-parquet", action="store_true")
    parser.add_argument("--json-gzip", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)

    if not args.no_parquet:
        try:
            _parquet_modules()
        except RuntimeError:
            parser.exit(
                2,
                "Parquet export requires pyarrow; install it or use --no-parquet.\n",
            )
    out = Path(args.out)
    try:
        _check_out(out, args.force)
        out.mkdir(parents=True, exist_ok=True)
    except FileExistsError:
        parser.exit(2, "Output must be a directory, empty unless --force is used.\n")
    except OSError:
        parser.exit(2, "Cannot create the output directory.\n")

    records, failures, reverted = [], [], []
    selection = dict.fromkeys(SELECTION_FIELDS, 0)
    aliases = AliasMap()
    previous_last = None
    broken = None
    run_error = None
    stage = "imports"
    try:
        # These imports stay out of the pure transformation/test path.
        from .blob_decode import decode_blobs
        from .blob_store import load_blobs, load_trusted_setup, match_blobs
        from .cli import DEFAULT_CORE
        from .ere_reader import blob_txs_with_status, slot_for_timestamp

        client = None
        if args.rpc:
            from .cli import verified_header
            from .starknet_public import PublicClient

            stage = "public_client"
            client = PublicClient(args.rpc, args.cache, rate=2.0)

        stage = "trusted_setup"
        trusted_setup = load_trusted_setup(args.setup)
        core = bytes.fromhex(DEFAULT_CORE[2:])

        # Receipts follow all bodies, so the first update appears only after
        # the whole Ere file has been read.
        transactions = _selected_updates(
            blob_txs_with_status(args.ere, core), selection, reverted,
        )
        stage = "ere_reading"
        for transaction in islice(transactions, args.max_updates):
            provenance = {
                "l1_block": transaction.block_number,
                "l1_tx_index": transaction.tx_index,
                "l1_tx_hash": "0x" + transaction.tx_hash.hex(),
            }
            diagnostics = {}
            stage = "calldata"
            try:
                program, _proofs = decode_calldata(transaction.data)
                stage = "header_verification" if client else "header_structural"
                if client is None:
                    offset, header = find_os_header(program, None)
                else:
                    offset, header, _discovery = verified_header(program, client)
                diagnostics = {
                    "header_offset": offset,
                    "header_verified_public": client is not None,
                }

                broken = range_break(previous_last, header)
                if broken is not None:
                    broken.update(provenance)
                    break

                if header["full_output"] != 0:
                    stage = "unsupported_full_output"
                    raise ValueError
                if header["use_kzg_da"] != 1:
                    stage = "unsupported_use_kzg_da"
                    raise ValueError

                stage = "slot"
                slot = slot_for_timestamp(transaction.timestamp)
                stage = "blob_loading"
                slot_blobs = load_blobs(slot)
                if slot_blobs is None:
                    raise FileNotFoundError
                if not transaction.versioned_hashes:
                    raise ValueError

                stage = "blob_matching"
                blobs = match_blobs(
                    slot_blobs, transaction.versioned_hashes, trusted_setup,
                )
                if len(blobs) != len(transaction.versioned_hashes):
                    raise ValueError

                stage = "blob_decoding"
                felts = decode_blobs(blobs)
                stage = "da_decoding"
                diff = decode_da(felts)
                stage = "alias_resolution"
                candidate_aliases = deepcopy(aliases)
                record = update_record(
                    diff,
                    candidate_aliases,
                    header=header,
                    header_offset=offset,
                    header_verified_public=client is not None,
                    l1={
                        "block": transaction.block_number,
                        "timestamp": transaction.timestamp,
                        "tx_index": transaction.tx_index,
                        "tx_hash": provenance["l1_tx_hash"],
                        "versioned_hashes": [
                            "0x" + value.hex()
                            for value in transaction.versioned_hashes
                        ],
                        "blob_count": len(blobs),
                    },
                )
                records.append(record)
                aliases = candidate_aliases
                previous_last = header["new_block_number"]
            except Exception as exc:
                failures.append({
                    **provenance,
                    **diagnostics,
                    "stage": stage,
                    "type": type(exc).__name__,
                })
                # Do not advance the exported boundary after a failed update.
                # A later update cannot silently bridge the missing range.
            stage = "ere_reading"
    except Exception as exc:
        run_error = {"stage": stage, "type": type(exc).__name__}

    try:
        write_outputs(
            records,
            out,
            ere=args.ere,
            no_parquet=args.no_parquet,
            json_gzip=args.json_gzip,
            force=args.force,
            failed_updates=failures,
            reverted_skipped=reverted,
            selection=selection,
            range_break_record=broken,
            run_error=run_error,
        )
    except Exception as exc:
        print(f"Export write failed ({type(exc).__name__}).", file=sys.stderr)
        return 1
    return 0 if records and not failures and broken is None and run_error is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
