"""Synthetic, offline tests; no external archives or network access required."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from src import ere_reader as reader

type RLPInput = bytes | int | list[RLPInput]

ADDRESS = bytes.fromhex("1234567890abcdef1234567890abcdef12345678")
OTHER_ADDRESS = b"\xff" * 20
VERSIONED_HASHES = [b"\x01" + b"\x11" * 31, b"\x01" + b"\x22" * 31]
TIMESTAMP = 1606824023 + 123 * 12


def _encode(value: RLPInput) -> bytes:
    """Independent RLP encoder for test fixtures."""
    if isinstance(value, int):
        if value < 0:
            raise ValueError("RLP integers must be nonnegative")
        value = value.to_bytes((value.bit_length() + 7) // 8, "big")

    if isinstance(value, bytes):
        if len(value) == 1 and value[0] < 0x80:
            return value
        payload, short_base, long_base = value, 0x80, 0xB7
    else:
        payload = b"".join(_encode(item) for item in value)
        short_base, long_base = 0xC0, 0xF7

    if len(payload) < 56:
        return bytes([short_base + len(payload)]) + payload
    length = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
    return bytes([long_base + len(length)]) + length + payload


def _crc32c(data: bytes) -> int:
    """Independent bitwise CRC32C implementation for fixture construction."""
    value = 0xFFFFFFFF
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x82F63B78 if value & 1 else 0)
    return value ^ 0xFFFFFFFF


def _masked_crc(data: bytes) -> bytes:
    crc = _crc32c(data)
    masked = (((crc >> 15) | (crc << 17)) + 0xA282EAD8) & 0xFFFFFFFF
    return masked.to_bytes(4, "little")


def _chunk(kind: int, data: bytes) -> bytes:
    return bytes([kind]) + len(data).to_bytes(3, "little") + data


def _frame(data: bytes) -> bytes:
    output = _chunk(0xFF, b"sNaPpY")
    for start in range(0, len(data), 65_536):
        piece = data[start : start + 65_536]
        output += _chunk(0x01, _masked_crc(piece) + piece)
    return output


def _entry(kind: int, payload: bytes) -> bytes:
    return (
        kind.to_bytes(2, "big")
        + len(payload).to_bytes(4, "little")
        + b"\x00\x00"
        + payload
    )


def _header(number: int, timestamp: int) -> bytes:
    fields: list[RLPInput] = [b""] * 15
    fields[8] = number
    fields[11] = timestamp
    return _frame(_encode(fields))


def _blob_envelope() -> bytes:
    fields: list[RLPInput] = [
        1,                          # chain_id
        2,                          # nonce
        3,                          # max_priority_fee_per_gas
        4,                          # max_fee_per_gas
        21_000,                     # gas_limit
        ADDRESS,
        0,                          # value
        b"hello blobs",
        [],                         # access_list
        5,                          # max_fee_per_blob_gas
        list(VERSIONED_HASHES),
        0,                          # y_parity
        1,                          # r
        2,                          # s
    ]
    return b"\x03" + _encode(fields)


def _legacy_fields() -> list[RLPInput]:
    return [0, 1, 21_000, ADDRESS, 0, b"legacy", 27, 1, 1]


@pytest.fixture
def archive(tmp_path: Path) -> Path:
    path = tmp_path / "mainnet-00001-00000000.ere"
    path.write_bytes(
        _entry(0x6532, b"")
        + _entry(0x0300, _header(8192, TIMESTAMP))
        + _entry(0x0300, _header(8193, TIMESTAMP + 12))
        # Post-Shanghai body: transactions, uncles, withdrawals.
        + _entry(0x0400, _frame(_encode([[_blob_envelope()], [], []])))
        # Two-field body, with a legacy transaction represented as an RLP list.
        + _entry(0x0400, _frame(_encode([[_legacy_fields()], []])))
        + _entry(0x0A00, b"ignored receipts")
        + _entry(0x0B00, b"ignored proof")
        + _entry(0x0600, b"ignored difficulty")
        + _entry(0x0700, b"ignored root")
        + _entry(0x6732, b"ignored index")
    )
    return path


@pytest.fixture
def keccak256() -> Callable[[bytes], bytes]:
    """Skip hash-dependent tests only when no usable Keccak provider exists."""
    try:
        from Crypto.Hash import keccak
    except ImportError:
        try:
            from eth_hash.auto import keccak as eth_keccak

            eth_keccak(b"")  # Force backend discovery.
        except ImportError:
            pytest.skip("Install pycryptodome or eth-hash with a Keccak backend")
        return eth_keccak
    return lambda data: keccak.new(digest_bits=256, data=data).digest()


def test_entries_and_blocks(archive: Path) -> None:
    entries = list(reader.iter_entries(archive))
    assert entries[0] == (0x6532, b"")
    assert [kind for kind, _ in entries[:5]] == [
        0x6532, 0x0300, 0x0300, 0x0400, 0x0400
    ]

    blocks = list(reader.iter_blocks(archive))
    assert len(blocks) == 2
    assert [(block.number, block.timestamp) for block in blocks] == [
        (8192, TIMESTAMP),
        (8193, TIMESTAMP + 12),
    ]
    assert blocks[0].txs == [_blob_envelope()]
    assert blocks[1].txs == [_encode(_legacy_fields())]
    assert reader.blob_txs(blocks[0], OTHER_ADDRESS) == []
    assert reader.blob_txs(blocks[1], ADDRESS) == []


def test_blob_transaction(
    archive: Path, keccak256: Callable[[bytes], bytes]
) -> None:
    block = next(reader.iter_blocks(archive))
    matches = reader.blob_txs(block, ADDRESS)
    assert len(matches) == 1

    transaction = matches[0]
    assert transaction.block_number == 8192
    assert transaction.timestamp == TIMESTAMP
    assert transaction.tx_index == 0
    assert transaction.to == ADDRESS
    assert transaction.data == b"hello blobs"
    assert transaction.versioned_hashes == VERSIONED_HASHES
    assert transaction.tx_hash == keccak256(_blob_envelope())
    assert transaction.tx_hash != keccak256(_blob_envelope()[1:])


def test_cli(
    archive: Path,
    keccak256: Callable[[bytes], bytes],
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert reader.main([str(archive), "0x" + ADDRESS.hex()]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["block_number"] == 8192
    assert record["tx_index"] == 0
    assert record["tx_hash"] == "0x" + keccak256(_blob_envelope()).hex()
    assert record["to"] == "0x" + ADDRESS.hex()
    assert record["data"] == "0x" + b"hello blobs".hex()
    assert record["versioned_hashes"] == [
        "0x" + value.hex() for value in VERSIONED_HASHES
    ]


@pytest.mark.parametrize(
    ("encoded", "expected"),
    [
        (b"\x80", b""),
        (b"\x00", b"\x00"),
        (b"\x7f", b"\x7f"),
        (b"\xc0", []),
        (b"\xb8\x38" + b"x" * 56, b"x" * 56),
        (_encode([b"cat", [b"", b"dog"], []]), [b"cat", [b"", b"dog"], []]),
        (_encode([b"x" * 60]), [b"x" * 60]),
    ],
)
def test_rlp_valid(encoded: bytes, expected: reader.RLP) -> None:
    assert reader.rlp_decode(encoded) == expected


@pytest.mark.parametrize(
    "encoded",
    [
        b"",                    # Missing value.
        b"\x81",                # Truncated string.
        b"\x81\x01",            # Noncanonical single-byte string.
        b"\xb8\x01x",            # Long form used for a short string.
        b"\xb9\x00\x38" + b"x" * 56,  # Leading zero in length.
        b"\xc1\x81",            # Child string crosses its list boundary.
        b"\xf8\x01\x80",        # Noncanonical long-form list.
        b"\x80\x80",            # Trailing value.
    ],
)
def test_rlp_invalid(encoded: bytes) -> None:
    with pytest.raises(reader.EreError):
        reader.rlp_decode(encoded)


def test_crc32c_known_vector_and_multichunk_frame() -> None:
    assert _crc32c(b"123456789") == 0xE3069283
    payload = bytes(range(256)) * 300
    assert reader.snappy_frame_decode(_frame(payload)) == payload
    assert reader.snappy_frame_decode(_frame(b"")) == b""


def test_crc_mismatch() -> None:
    frame = bytearray(_frame(b"payload"))
    # Identifier is 10 bytes, followed by the 4-byte data-chunk header.
    frame[14] ^= 1
    with pytest.raises(reader.EreError, match="CRC32C"):
        reader.snappy_frame_decode(bytes(frame))


@pytest.mark.parametrize("force_python", [False, True])
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # Literal "abcd", then COPY_1, COPY_2, and COPY_4, all offset 4.
        (
            b"\x10\x0cabcd\x01\x04\x0e\x04\x00\x0f\x04\x00\x00\x00",
            b"abcd" * 4,
        ),
        # One literal followed by an overlapping COPY_1.
        (b"\x0a\x00a\x15\x01", b"a" * 10),
        # A literal with a one-byte extended length.
        (b"\x46\xf0\x45" + b"x" * 70, b"x" * 70),
    ],
)
def test_compressed_chunks(
    raw: bytes,
    expected: bytes,
    force_python: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if force_python:
        monkeypatch.setattr(reader, "_cramjam_snappy", None)
    frame = (
        _chunk(0xFF, b"sNaPpY")
        + _chunk(0x80, b"skippable extension")
        + _chunk(0x00, _masked_crc(expected) + raw)
    )
    assert reader.snappy_frame_decode(frame) == expected


def test_invalid_raw_copy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(reader, "_cramjam_snappy", None)
    # Declares four output bytes, but attempts a copy from an empty output.
    raw = b"\x04\x01\x01"
    frame = _chunk(0xFF, b"sNaPpY") + _chunk(0x00, b"\x00" * 4 + raw)
    with pytest.raises(reader.EreError, match="copy offset"):
        reader.snappy_frame_decode(frame)


@pytest.mark.parametrize(
    "frame",
    [
        b"",
        b"\xff",
        _chunk(0xFF, b"wrong!"),
        _chunk(0x01, _masked_crc(b"x") + b"x"),
        _chunk(0xFF, b"sNaPpY") + _chunk(0x02, b""),
        _chunk(0xFF, b"sNaPpY") + _chunk(0x01, b"\x00"),
        _frame(b"abc")[:-1],
    ],
)
def test_invalid_frames(frame: bytes) -> None:
    with pytest.raises(reader.EreError):
        reader.snappy_frame_decode(frame)


@pytest.mark.parametrize(
    "contents",
    [
        b"\x03",
        _entry(0x0300, b"abc")[:-1],
        b"\x03\x00\x00\x00\x00\x00\x01\x00",
    ],
)
def test_invalid_entries(tmp_path: Path, contents: bytes) -> None:
    path = tmp_path / "invalid.ere"
    path.write_bytes(contents)
    with pytest.raises(reader.EreError):
        list(reader.iter_entries(path))


@pytest.mark.parametrize(("header_count", "body_count"), [(2, 1), (1, 2)])
def test_count_mismatch(
    tmp_path: Path, header_count: int, body_count: int
) -> None:
    path = tmp_path / "counts.ere"
    path.write_bytes(
        b"".join(
            _entry(0x0300, _header(index, TIMESTAMP))
            for index in range(header_count)
        )
        + _entry(0x0400, _frame(_encode([[], []]))) * body_count
    )
    with pytest.raises(reader.EreError, match="count mismatch"):
        list(reader.iter_blocks(path))


def test_header_after_body(tmp_path: Path) -> None:
    path = tmp_path / "ordering.ere"
    path.write_bytes(
        _entry(0x0300, _header(0, TIMESTAMP))
        + _entry(0x0400, _frame(_encode([[], []])))
        + _entry(0x0300, _header(1, TIMESTAMP + 12))
    )
    with pytest.raises(reader.EreError, match="after bodies"):
        list(reader.iter_blocks(path))


def test_address_validation_and_slots() -> None:
    with pytest.raises(ValueError, match="20 bytes"):
        reader.blob_txs(reader.Block(0, TIMESTAMP, []), b"short")
    assert reader.slot_for_timestamp(1606824023) == 0
    assert reader.slot_for_timestamp(TIMESTAMP) == 123
    assert reader.slot_for_timestamp(TIMESTAMP + 11) == 123
    assert reader.slot_for_timestamp(1606824022) == -1
