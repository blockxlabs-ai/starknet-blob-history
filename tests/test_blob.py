"""Run with: python -m pytest tests/test_blob.py"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import random
import sys
from types import SimpleNamespace

import pytest

from src import blob_decode as decode
from src import blob_store as store


@pytest.mark.parametrize("count", [0, 1, 137, 4096])
def test_round_trip(count: int) -> None:
    rng = random.Random(20250308 + count)
    coefficients = [rng.randrange(1 << 251) for _ in range(count)]
    original = coefficients.copy()
    blob = decode.coefficients_to_blob(coefficients)

    assert len(blob) == store.BYTES_PER_BLOB
    assert coefficients == original
    assert decode.decode_blobs([blob]) == (
        coefficients + [0] * (4096 - count)
    )


def test_multiple_blobs_and_empty_input() -> None:
    blobs = [
        decode.coefficients_to_blob([17]),
        decode.coefficients_to_blob([23, 42]),
    ]
    assert decode.decode_blobs(blobs) == (
        [17] + [0] * 4095 + [23, 42] + [0] * 4094
    )
    assert decode.decode_blobs([]) == []


def test_root_of_unity() -> None:
    r = decode.BLS_MODULUS
    w = decode.ROOT_OF_UNITY
    assert pow(w, 4096, r) == 1
    assert pow(w, 2048, r) != 1
    assert pow(decode.TWO_ADIC_ROOT_OF_UNITY, 1 << 32, r) == 1
    assert pow(decode.TWO_ADIC_ROOT_OF_UNITY, 1 << 31, r) != 1
    assert w == pow(7, (r - 1) // 4096, r)


def test_linear_polynomial_against_independent_evaluations() -> None:
    # An independent wire-format fixture catches matching forward/inverse
    # mistakes that an ordinary round trip would not detect.
    expected = bytearray()
    for wire_index in range(4096):
        evaluation_index = int(f"{wire_index:012b}"[::-1], 2)
        x = pow(
            decode.ROOT_OF_UNITY, evaluation_index, decode.BLS_MODULUS
        )
        expected.extend(
            ((11 + 19 * x) % decode.BLS_MODULUS).to_bytes(32, "big")
        )

    blob = bytes(expected)
    assert decode.coefficients_to_blob([11, 19]) == blob
    assert decode.decode_blobs([blob]) == [11, 19] + [0] * 4094


def test_rust_field_conversion_semantics() -> None:
    # Rust deserialization reduces BigUint into Fr.
    noncanonical = (decode.BLS_MODULUS + 5).to_bytes(32, "big") * 4096
    assert decode.decode_blobs([noncanonical]) == [5] + [0] * 4095

    # Rust's final Fr -> Felt conversion reduces into the Starknet field.
    blob = decode.coefficients_to_blob([decode.STARKNET_MODULUS + 9])
    assert decode.decode_blobs([blob]) == [9] + [0] * 4095


def test_decode_validation() -> None:
    with pytest.raises(decode.BlobDecodeError):
        decode.decode_blobs([b"\0" * (store.BYTES_PER_BLOB - 1)])
    with pytest.raises(decode.BlobDecodeError):
        decode.coefficients_to_blob([0] * 4097)
    with pytest.raises(TypeError):
        decode.coefficients_to_blob([1.5])
    with pytest.raises(decode.BlobDecodeError):
        decode.bit_reversal([0])


def test_versioned_hash_of_infinity() -> None:
    infinity = b"\xc0" + b"\0" * 47
    expected = b"\x01" + hashlib.sha256(infinity).digest()[1:]
    assert store.versioned_hash(infinity) == expected
    with pytest.raises(ValueError):
        store.versioned_hash(b"\0" * 47)


def test_real_zero_blob_commitment() -> None:
    setup = os.environ.get("TRUSTED_SETUP")
    if not setup or not Path(setup).is_file():
        pytest.skip("TRUSTED_SETUP does not point to a file")

    # If a setup was explicitly supplied, a missing/broken ckzg installation
    # is a test failure rather than silently skipping the integration test.
    import ckzg

    ts = store.load_trusted_setup(setup)
    commitment = ckzg.blob_to_kzg_commitment(
        b"\0" * store.BYTES_PER_BLOB, ts
    )
    assert commitment == b"\xc0" + b"\0" * 47


def test_load_two_blobs_and_bad_size(tmp_path: Path) -> None:
    slot = 8192 + 37
    directory = tmp_path / "era_00001"
    directory.mkdir()
    path = directory / f"blobs_{slot}.ssz"
    first = b"\0" * store.BYTES_PER_BLOB
    second = b"\x01" * store.BYTES_PER_BLOB
    path.write_bytes(first + second)

    found = store.find_slot_file(slot, [tmp_path])
    assert found.status == "blobs"
    assert found.path == path
    assert store.load_blobs(slot, [tmp_path]) == [first, second]

    path.write_bytes(first + b"\0")
    with pytest.raises(store.InvalidBlobFileSize) as error:
        store.load_blobs(slot, [tmp_path])
    assert error.value.path == path
    assert error.value.size == store.BYTES_PER_BLOB + 1

    path.write_bytes(b"")
    assert store.load_blobs(slot, [tmp_path]) == []


def test_columns_only_and_cross_root_precedence(tmp_path: Path) -> None:
    roots = [tmp_path / "primary", tmp_path / "history"]
    slot = 42
    for root in roots:
        (root / "era_00000").mkdir(parents=True)

    columns = roots[0] / "era_00000" / "columns_42.ssz"
    columns.write_bytes(b"not a blob")
    found = store.find_slot_file(slot, roots)
    assert found.status == "columns_only"
    assert found.path == columns
    assert store.load_blobs(slot, roots) is None

    blob = b"\0" * store.BYTES_PER_BLOB
    path = roots[1] / "era_00000" / "blobs_42.ssz"
    path.write_bytes(blob)
    assert store.find_slot_file(slot, roots).path == path
    assert store.load_blobs(slot, roots) == [blob]

    assert store.find_slot_file(43, roots).status == "missing"
    assert store.find_slot_file(43, roots).path is None
    assert store.load_blobs(43, roots) is None


def test_default_roots_and_slot_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store, "DEFAULT_ROOTS", (tmp_path,))
    directory = tmp_path / "era_00000"
    directory.mkdir()
    (directory / "blobs_0.ssz").write_bytes(b"")
    assert store.load_blobs(0) == []
    assert store.load_blobs(0, []) is None

    with pytest.raises(ValueError):
        store.find_slot_file(-1, [tmp_path])
    with pytest.raises(TypeError):
        store.find_slot_file(True, [tmp_path])


def test_match_order_duplicates_and_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = b"\0" * store.BYTES_PER_BLOB
    second = (1).to_bytes(32, "big") * 4096
    commitments = {
        first: b"\xc0" + b"\0" * 47,
        second: b"\x80" + b"\x01" * 47,
    }
    ts = object()
    calls = []

    def fake_commitment(blob: bytes, settings: object) -> bytes:
        assert settings is ts
        calls.append(blob)
        return commitments[blob]

    monkeypatch.setitem(
        sys.modules,
        "ckzg",
        SimpleNamespace(blob_to_kzg_commitment=fake_commitment),
    )
    first_hash = store.versioned_hash(commitments[first])
    second_hash = store.versioned_hash(commitments[second])

    assert store.match_blobs(
        [first, second], [second_hash, first_hash, second_hash], ts
    ) == [second, first, second]
    assert calls == [first, second]

    missing = b"\x01" + b"\xff" * 31
    with pytest.raises(store.MissingBlobsError) as error:
        store.match_blobs([first], [missing, first_hash, missing], ts)
    assert error.value.missing_hashes == [missing, missing]
    assert "0x" + missing.hex() in str(error.value)

    assert store.match_blobs([], [], ts) == []
    with pytest.raises(ValueError):
        store.match_blobs([], [b"short"], ts)
    with pytest.raises(ValueError):
        store.match_blobs([b"short"], [first_hash], ts)
