import gzip
import hashlib
import json
import sys
from copy import deepcopy
from itertools import islice
from pathlib import PurePosixPath
from types import SimpleNamespace

import pytest

from src import export_sample as exporter
from src.aliases import AliasMap
from src.export_sample import (
    SELECTION_FIELDS,
    _selected_updates,
    felt_hex,
    parquet_schemas,
    range_break,
    resolve_diff,
    update_record,
    write_outputs,
)
from src.l1_update import HEADER_FIELDS, SELECTOR
from src.os_state_diff import ClassDeclaration, ContractDiff, StateDiff


def contract(address, storage=None, nonce=None, class_hash=None):
    return ContractDiff(address, nonce, class_hash, storage or {})


def header(previous=10, new=12):
    result = dict.fromkeys(HEADER_FIELDS, 0)
    result.update(
        prev_block_number=previous,
        new_block_number=new,
        use_kzg_da=1,
    )
    return result


def record(diff, aliases=None, previous=10, new=12):
    return update_record(
        diff,
        AliasMap() if aliases is None else aliases,
        header=header(previous, new),
        header_offset=0,
        header_verified_public=False,
        l1={
            "block": 100,
            "timestamp": 200,
            "tx_index": 0,
            "tx_hash": "0x" + "01" * 32,
            "versioned_hashes": ["0x" + "02" * 32],
            "blob_count": 1,
        },
    )


@pytest.mark.parametrize("address", [0, 1, 2, 0xF])
def test_system_contract_keys_are_identity(address):
    # Contract 0x2 must contain valid assignment pairs.
    diff = StateDiff([contract(address, {0x1234: 0x80})], [])
    row = resolve_diff(diff, AliasMap())[0]
    assert row["address"] == hex(address)
    assert row["address_resolution"] == "identity"
    assert row["storage"] == [{
        "key_alias": "0x1234",
        "key": "0x1234",
        "key_resolution": "identity",
        "value": "0x80",
    }]


@pytest.mark.parametrize("address", [0x10, 0x7F])
def test_small_addresses_and_small_keys_are_identity(address):
    row = resolve_diff(
        StateDiff([contract(address, {0x7F: 0, 0x80: 1})], []),
        AliasMap(),
    )[0]
    assert row["address"] == hex(address)
    assert row["address_resolution"] == "identity"
    assert row["storage"][0]["key"] == "0x7f"
    assert row["storage"][0]["key_resolution"] == "identity"
    assert row["storage"][1]["key"] is None
    assert row["storage"][1]["key_resolution"] == "unresolved"


def test_learning_from_same_update_with_alias_contract_last():
    diff = StateDiff([
        contract(0x80, {0x81: 7}, nonce=3, class_hash=0x82),
        contract(2, {0x1234: 0x80, 0x5678: 0x81, 0: 0x82}),
    ], [ClassDeclaration(0x80, 0x81)])
    original = deepcopy(diff)
    rows = resolve_diff(diff, AliasMap())
    assert diff == original
    assert [row["address_alias"] for row in rows] == ["0x2", "0x80"]
    resolved = rows[1]
    assert resolved["address"] == "0x1234"
    assert resolved["address_resolution"] == "l1_range"
    assert resolved["storage"] == [{
        "key_alias": "0x81",
        "key": "0x5678",
        "key_resolution": "l1_range",
        "value": "0x7",
    }]
    assert resolved["nonce"] == "0x3"
    assert resolved["class_hash"] == "0x82"


def test_learning_from_earlier_update():
    aliases = AliasMap()
    resolve_diff(
        StateDiff([contract(2, {0x1000: 0x80, 0x2000: 0x81})], []),
        aliases,
    )
    row = resolve_diff(
        StateDiff([contract(0x80, {0x81: 5})], []),
        aliases,
    )[0]
    assert row["address"] == "0x1000"
    assert row["address_resolution"] == "l1_range"
    assert row["storage"][0]["key"] == "0x2000"
    assert row["storage"][0]["key_resolution"] == "l1_range"


def test_unresolved_address_still_resolves_known_large_keys():
    # An aliased (>= 0x80) address has an original > 0xF, so its keys
    # >= 0x80 are compressed and a learned key alias applies.
    aliases = AliasMap()
    resolve_diff(StateDiff([contract(2, {0x2000: 0x81})], []), aliases)
    row = resolve_diff(
        StateDiff([contract(0x80, {0x81: 7, 0x82: 1, 0: 0})], []),
        aliases,
    )[0]
    assert row["address_alias"] == "0x80"
    assert row["address"] is None
    assert row["address_resolution"] == "unresolved"
    assert row["storage"][0]["key"] == "0x0"
    assert row["storage"][0]["key_resolution"] == "identity"
    assert row["storage"][1]["key"] == "0x2000"
    assert row["storage"][1]["key_resolution"] == "l1_range"
    assert row["storage"][2]["key"] is None
    assert row["storage"][2]["key_resolution"] == "unresolved"


def test_aliased_address_is_not_a_system_contract():
    aliases = AliasMap()
    rows = resolve_diff(StateDiff([
        contract(0x80, {0xABCD: 0}),
        contract(2, {0x1234: 0x80}),
    ], []), aliases)
    row = rows[1]
    assert row["address"] == "0x1234"
    assert row["storage"][0]["key"] is None
    assert row["storage"][0]["key_resolution"] == "unresolved"


def test_hex_formatting_nulls_and_numeric_sorting():
    result = record(StateDiff([
        contract(0x10, {0x10: 0, 2: 0}, nonce=0, class_hash=0),
        contract(3),
    ], [ClassDeclaration(0, 0)]))
    assert felt_hex(0) == "0x0"
    assert felt_hex(0x00ABC) == "0xabc"
    assert felt_hex(None) is None
    assert [row["address_alias"] for row in result["contracts"]] == ["0x3", "0x10"]
    assert result["contracts"][0]["nonce"] is None
    assert result["contracts"][0]["class_hash"] is None
    row = result["contracts"][1]
    assert row["nonce"] == row["class_hash"] == "0x0"
    assert [item["key_alias"] for item in row["storage"]] == ["0x2", "0x10"]
    assert all(item["value"] == "0x0" for item in row["storage"])
    assert result["declared_classes"] == [{
        "class_hash": "0x0", "compiled_class_hash": "0x0",
    }]
    assert result["os_header"]["initial_root"] == "0x0"
    assert result["os_header"]["prev_block_number"] == 10
    assert result["os_header"]["verified_public"] is False
    assert set(result["os_header"]) == set(HEADER_FIELDS) | {
        "offset", "verified_public",
    }


def test_contiguity_break_detection(tmp_path):
    assert range_break(None, header()) is None
    assert range_break(10, header()) is None
    expected = {
        "expected_prev_block_number": 9,
        "actual_prev_block_number": 10,
        "new_block_number": 12,
    }
    assert range_break(9, header()) == expected

    source = tmp_path / "input.ere"
    source.write_bytes(b"synthetic")
    first = record(StateDiff([], []))
    following = record(StateDiff([], []), previous=13, new=15)
    with pytest.raises(ValueError, match="contiguous"):
        write_outputs(
            [first, following], tmp_path / "bad",
            ere=source, no_parquet=True,
        )
    assert not (tmp_path / "bad").exists()

    manifest = write_outputs(
        [first], tmp_path / "partial", ere=source, no_parquet=True,
        range_break_record=range_break(12, header(13, 15)),
        failed_updates=[{"stage": "blob_loading", "type": "FileNotFoundError"}],
    )
    assert manifest["counts"]["updates"] == 1
    assert manifest["range_break"]["actual_prev_block_number"] == 13
    assert manifest["failed_updates"] == [
        {"stage": "blob_loading", "type": "FileNotFoundError"},
    ]


@pytest.fixture
def sample(tmp_path):
    source = tmp_path / "private" / "input.ere"
    source.parent.mkdir()
    source.write_bytes(b"synthetic Ere input")
    aliases = AliasMap()
    first = record(StateDiff([
        contract(1, {0: 0}, nonce=0, class_hash=0),
        contract(0x80, {0x81: 4}),
    ], [ClassDeclaration(0, 2)]), aliases)
    second = record(StateDiff([
        contract(0x80, {0x81: 0}, nonce=2),
        contract(2, {0x1000: 0x80, 0x2000: 0x81}),
    ], []), aliases, previous=12, new=15)
    return source, [first, second]


def test_deterministic_json_manifest_and_checksums(tmp_path, sample):
    source, records = sample
    outputs = [tmp_path / "one", tmp_path / "two"]
    manifests = [
        write_outputs(records, out, ere=source, no_parquet=True)
        for out in outputs
    ]
    assert manifests[0] == manifests[1]
    for path in outputs[0].rglob("*"):
        if path.is_file():
            relative = path.relative_to(outputs[0])
            assert path.read_bytes() == (outputs[1] / relative).read_bytes()

    manifest = manifests[0]
    assert manifest["source_ere"] == {
        "basename": source.name,
        "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
    }
    assert manifest["alias_resolution_coverage"] == {
        "addresses": {"identity": 2, "l1_range": 1, "unresolved": 1},
        "keys": {"identity": 3, "l1_range": 1, "unresolved": 1},
    }
    assert manifest["selection"] == dict.fromkeys(SELECTION_FIELDS, 0)
    assert "Selection drops reverted L1 transactions (receipt status != 1)." in (
        manifest["limitations"]
    )
    assert "src/export_sample.py" in manifest["code_identity"]
    assert list(manifest["code_identity"]) == sorted(manifest["code_identity"])
    for relative, metadata in manifest["files"].items():
        assert not PurePosixPath(relative).is_absolute()
        data = (outputs[0] / relative).read_bytes()
        assert metadata == {
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
        }

    for filename in ("manifest.json", "README.md"):
        text = (outputs[0] / filename).read_text(encoding="utf-8")
        assert str(tmp_path) not in text
        assert str(source.resolve()) not in text
    for name in manifest["code_identity"]:
        assert not PurePosixPath(name).is_absolute()

    data = (outputs[0] / "json/starknet-11-12.json").read_bytes()
    assert data.endswith(b"\n")
    assert data == (
        json.dumps(
            records[0], sort_keys=True, ensure_ascii=False, separators=(",", ":"),
        ) + "\n"
    ).encode("utf-8")


def test_json_gzip_is_deterministic_and_matches_plain_json(tmp_path, sample):
    source, records = sample
    plain = tmp_path / "plain"
    write_outputs(records, plain, ere=source, no_parquet=True)
    outputs = [tmp_path / "gzip-one", tmp_path / "gzip-two"]
    manifests = [
        write_outputs(
            records, out, ere=source, no_parquet=True, json_gzip=True,
        )
        for out in outputs
    ]
    assert manifests[0] == manifests[1]
    for path in outputs[0].rglob("*"):
        if path.is_file():
            relative = path.relative_to(outputs[0])
            assert path.read_bytes() == (outputs[1] / relative).read_bytes()

    readme = (outputs[0] / "README.md").read_text(encoding="utf-8")
    for path in (plain / "json").glob("*.json"):
        relative = f"json/{path.name}.gz"
        compressed = (outputs[0] / relative).read_bytes()
        assert gzip.decompress(compressed) == path.read_bytes()
        assert compressed[4:8] == b"\x00" * 4  # mtime
        assert not compressed[3] & 0x08  # No original filename.
        assert f"`{relative}`" in readme
        assert not (outputs[0] / "json" / path.name).exists()
        assert manifests[0]["files"][relative] == {
            "sha256": hashlib.sha256(compressed).hexdigest(),
            "bytes": len(compressed),
        }


def test_nonempty_output_requires_force_and_removes_stale_files(tmp_path, sample):
    source, records = sample
    out = tmp_path / "out"
    out.mkdir()
    stale = out / "stale.txt"
    stale.write_text("old", encoding="utf-8")
    with pytest.raises(FileExistsError):
        write_outputs(records, out, ere=source, no_parquet=True)
    assert stale.exists()

    write_outputs(records, out, ere=source, no_parquet=True, force=True)
    assert not stale.exists()
    assert (out / "manifest.json").is_file()


def test_parquet_explicit_schemas_and_round_trip(tmp_path, sample):
    pa = pytest.importorskip("pyarrow")
    import pyarrow.parquet as pq

    source, records = sample
    out = tmp_path / "parquet-export"
    manifest = write_outputs(records, out, ere=source)
    expected_counts = {
        "updates": 2,
        "storage_diffs": 5,
        "contract_updates": 2,
        "declared_classes": 1,
    }
    assert manifest["counts"] == expected_counts
    for name, schema in parquet_schemas(pa).items():
        path = out / "parquet" / f"{name}.parquet"
        table = pq.read_table(path)
        assert table.schema.equals(schema)
        assert table.num_rows == expected_counts[name]
        assert table.schema.field("starknet_first").type == pa.int64()
        metadata = pq.ParquetFile(path).metadata
        assert metadata.row_group(0).column(0).compression == "ZSTD"

    storage = pq.read_table(out / "parquet/storage_diffs.parquet").to_pylist()
    assert storage[1]["address"] is None
    assert storage[1]["key"] is None
    assert storage[-1]["address"] == "0x1000"
    assert storage[-1]["key"] == "0x2000"
    assert storage[-1]["value"] == "0x0"

    updates = pq.read_table(out / "parquet/updates.parquet").to_pylist()
    assert updates[0]["header_offset"] == 0
    assert updates[0]["header_verified_public"] is False
    assert updates[0]["initial_root"] == "0x0"
    assert updates[1]["starknet_first"] == 13
    contracts = pq.read_table(out / "parquet/contract_updates.parquet").to_pylist()
    assert contracts[0]["nonce"] == contracts[0]["class_hash"] == "0x0"


def test_empty_parquet_tables_retain_schemas(tmp_path):
    pa = pytest.importorskip("pyarrow")
    import pyarrow.parquet as pq

    source = tmp_path / "input.ere"
    source.write_bytes(b"")
    out = tmp_path / "empty"
    write_outputs([], out, ere=source)
    for name, schema in parquet_schemas(pa).items():
        table = pq.read_table(out / "parquet" / f"{name}.parquet")
        assert table.num_rows == 0
        assert table.schema.equals(schema)


def transaction(index, status=1, data=SELECTOR):
    return SimpleNamespace(
        block_number=100,
        timestamp=1606824035,
        tx_index=index,
        tx_hash=bytes([index]) * 32,
        data=data,
        status=status,
        versioned_hashes=[b"\x01" * 32],
    )


@pytest.mark.parametrize("status", [0, None])
def test_selection_skips_non_success_and_counts_before_limit(status):
    other = transaction(0, status=0, data=b"\x00" * 4)
    reverted = transaction(1, status=status)
    accepted = transaction(2)
    unseen = transaction(3, status=0)
    selection = dict.fromkeys(SELECTION_FIELDS, 0)
    skipped = []
    selected = list(islice(
        _selected_updates(
            iter([other, reverted, accepted, unseen]), selection, skipped,
        ),
        1,
    ))
    assert selected == [accepted]
    assert selection == {
        "core_blob_transactions_seen": 3,
        "other_selectors_skipped": 1,
        "reverted_skipped": 1,
    }
    assert skipped == [{
        "l1_block": 100,
        "l1_tx_index": 1,
        "l1_tx_hash": "0x" + "01" * 32,
    }]


@pytest.fixture
def fake_run(tmp_path, monkeypatch):
    from src import blob_store

    source = tmp_path / "input.ere"
    source.write_bytes(b"synthetic Ere input")
    out = tmp_path / "export"
    transactions = [
        transaction(0, data=b"\x00" * 4),
        transaction(1, status=0),
        transaction(2),
        transaction(3, status=0),
    ]
    calls = []

    def blob_txs_with_status(path, core):
        calls.append((path, core))
        return iter(transactions)

    monkeypatch.setitem(sys.modules, "src.ere_reader", SimpleNamespace(
        blob_txs_with_status=blob_txs_with_status,
        slot_for_timestamp=lambda timestamp: 1,
    ))
    monkeypatch.setitem(sys.modules, "src.blob_decode", SimpleNamespace(
        decode_blobs=lambda blobs: [],
    ))
    monkeypatch.setitem(sys.modules, "src.cli", SimpleNamespace(
        DEFAULT_CORE="0xc662c410c0ecf747543f5ba90660f6abebd9c8c4",
    ))
    monkeypatch.setattr(blob_store, "load_trusted_setup", lambda path: object())
    monkeypatch.setattr(
        blob_store, "match_blobs", lambda blobs, hashes, setup: blobs,
    )
    monkeypatch.setattr(exporter, "decode_calldata", lambda data: ([], []))
    monkeypatch.setattr(exporter, "find_os_header", lambda program, public: (0, header()))
    monkeypatch.setattr(exporter, "decode_da", lambda felts: StateDiff([], []))
    # Importing pyarrow must not be necessary for --no-parquet.
    monkeypatch.setitem(sys.modules, "pyarrow", None)
    monkeypatch.setitem(sys.modules, "pyarrow.parquet", None)
    args = [
        "--ere", str(source),
        "--setup", str(tmp_path / "setup.txt"),
        "--out", str(out),
        "--max-updates", "1",
        "--no-parquet",
        "--json-gzip",
    ]
    return blob_store, args, out, source, calls


def test_cli_selection_and_json_gzip(fake_run, monkeypatch):
    blob_store, args, out, source, calls = fake_run
    monkeypatch.setattr(blob_store, "load_blobs", lambda slot: [b"blob"])
    assert exporter.main(args) == 0
    assert calls == [(
        str(source),
        bytes.fromhex("c662c410c0ecf747543f5ba90660f6abebd9c8c4"),
    )]
    manifest = json.loads((out / "manifest.json").read_bytes())
    assert manifest["selection"] == {
        "core_blob_transactions_seen": 3,
        "other_selectors_skipped": 1,
        "reverted_skipped": 1,
    }
    assert manifest["counts"]["updates"] == 1
    assert manifest["failed_updates"] == []
    assert manifest["reverted_skipped"] == [{
        "l1_block": 100,
        "l1_tx_index": 1,
        "l1_tx_hash": "0x" + "01" * 32,
    }]
    name = "json/starknet-11-12.json.gz"
    assert name in manifest["files"]
    data = json.loads(gzip.decompress((out / name).read_bytes()))
    assert data["l1"]["tx_index"] == 2
    assert not (out / "parquet").exists()


def test_cli_no_blob_roots_records_blob_store_error(fake_run, monkeypatch):
    blob_store, args, out, source, calls = fake_run
    monkeypatch.setattr(blob_store, "DEFAULT_ROOTS", ())
    assert exporter.main(args) == 1
    manifest = json.loads((out / "manifest.json").read_bytes())
    assert manifest["counts"]["updates"] == 0
    assert manifest["run_error"] is None
    assert manifest["failed_updates"] == [{
        "l1_block": 100,
        "l1_tx_index": 2,
        "l1_tx_hash": "0x" + "02" * 32,
        "header_offset": 0,
        "header_verified_public": False,
        "stage": "blob_loading",
        "type": "BlobStoreError",
    }]
    assert manifest["selection"]["reverted_skipped"] == 1
    assert str(source.parent) not in (out / "manifest.json").read_text()


def test_atomic_write_preserves_existing_file_on_failure(tmp_path):
    path = tmp_path / "artifact"
    path.write_bytes(b"original")

    def fail(stream):
        stream.write(b"partial")
        raise OSError("synthetic write failure")

    with pytest.raises(OSError):
        exporter._atomic_write(path, fail)
    assert path.read_bytes() == b"original"
    assert list(tmp_path.iterdir()) == [path]
