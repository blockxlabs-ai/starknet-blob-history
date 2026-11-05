"""Streaming Ere reader with strict RLP and checked Snappy decoding.

Optional acceleration: cramjam.
Transaction hashing requires pycryptodome or eth-hash with a working backend.

Entry types use their wire-byte spelling as integer labels, not little-endian
integer interpretation: b"\\x03\\x00" is CompressedHeader, labeled 0x0300.
"""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

try:
    from cramjam import snappy as _cramjam_snappy
except ImportError:
    _cramjam_snappy = None

type RLP = bytes | list[RLP]
type Pathish = str | os.PathLike[str]

COMPRESSED_HEADER = 0x0300
COMPRESSED_BODY = 0x0400
COMPRESSED_SLIM_RECEIPTS = 0x0A00

_MAX_SNAPPY_CHUNK = 65_536
_MAX_RLP_DEPTH = 256
_SNAPPY_IDENTIFIER = b"sNaPpY"


class EreError(ValueError):
    """Malformed e2store, Snappy, RLP, or supported Ethereum data."""


@dataclass(slots=True)
class Block:
    """A block's metadata and canonical transaction wire encodings."""

    number: int
    timestamp: int
    txs: list[bytes]


@dataclass(slots=True)
class BlobTx:
    """Selected fields of a matching EIP-4844 transaction."""

    block_number: int
    timestamp: int
    tx_index: int
    tx_hash: bytes
    to: bytes
    data: bytes
    versioned_hashes: list[bytes]
    # Receipt status (1 success, 0 reverted); None when receipts were not read.
    status: int | None = None


def iter_entries(path: Pathish) -> Iterator[tuple[int, bytes]]:
    """Read one entry at a time, validating reserved bytes and truncation."""
    with open(path, "rb") as stream:
        offset = 0
        while True:
            header = stream.read(8)
            if not header:
                return
            if len(header) != 8:
                raise EreError(f"Truncated entry header at offset {offset}")
            if header[6:8] != b"\x00\x00":
                raise EreError(f"Nonzero reserved bytes at offset {offset}")

            entry_type = int.from_bytes(header[:2], "big")
            length = int.from_bytes(header[2:6], "little")
            payload = stream.read(length)
            if len(payload) != length:
                raise EreError(
                    f"Truncated entry payload at offset {offset}: "
                    f"expected {length} bytes, got {len(payload)}"
                )
            yield entry_type, payload
            offset += 8 + length


def _make_crc32c_table() -> tuple[int, ...]:
    table: list[int] = []
    for value in range(256):
        for _ in range(8):
            value = (value >> 1) ^ (0x82F63B78 if value & 1 else 0)
        table.append(value)
    return tuple(table)


_CRC32C_TABLE = _make_crc32c_table()


def _crc32c_py(data: bytes) -> int:
    """Compute CRC-32C/Castagnoli, not the IEEE CRC used by zlib (pure-Python reference)."""
    crc = 0xFFFFFFFF
    for value in data:
        crc = _CRC32C_TABLE[(crc ^ value) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


# The pure-Python CRC is ~91 % of Ere decode time. Use the optional C implementation
# google-crc32c (Apache-2.0) when installed; the result is identical (see tests).
try:  # pragma: no cover - depends on the environment
    import google_crc32c as _gcrc32c

    def _crc32c(data: bytes) -> int:
        return _gcrc32c.value(bytes(data))

    CRC32C_IMPL = "google-crc32c/" + getattr(_gcrc32c, "implementation", "?")
except ImportError:  # pragma: no cover
    _crc32c = _crc32c_py
    CRC32C_IMPL = "pure-python"


def _masked_crc32c(data: bytes) -> int:
    crc = _crc32c(data)
    rotated = (crc >> 15) | ((crc << 17) & 0xFFFFFFFF)
    return (rotated + 0xA282EAD8) & 0xFFFFFFFF


def _snappy_raw_length(data: bytes) -> tuple[int, int]:
    """Read Snappy's uint32 varint uncompressed-length prefix."""
    value = 0
    for index in range(5):
        if index >= len(data):
            raise EreError("Truncated Snappy raw length")
        byte = data[index]
        if index == 4 and byte > 0x0F:
            raise EreError("Snappy raw length exceeds uint32")
        value |= (byte & 0x7F) << (7 * index)
        if not byte & 0x80:
            return value, index + 1
    raise EreError("Invalid Snappy raw length")


def _snappy_raw_python(data: bytes, expected: int, pos: int) -> bytes:
    """Decode literals and all three raw Snappy copy instruction forms."""
    output = bytearray()
    while pos < len(data):
        tag = data[pos]
        pos += 1
        kind = tag & 0x03

        if kind == 0:
            length_code = tag >> 2
            if length_code < 60:
                length = length_code + 1
            else:
                width = length_code - 59
                if pos + width > len(data):
                    raise EreError("Truncated Snappy literal length")
                length = int.from_bytes(data[pos : pos + width], "little") + 1
                pos += width

            if pos + length > len(data):
                raise EreError("Truncated Snappy literal")
            if len(output) + length > expected:
                raise EreError("Snappy literal exceeds declared output length")
            output.extend(data[pos : pos + length])
            pos += length
            continue

        width = {1: 1, 2: 2, 3: 4}[kind]
        if pos + width > len(data):
            raise EreError("Truncated Snappy copy offset")

        if kind == 1:
            length = 4 + ((tag >> 2) & 0x07)
            offset = ((tag & 0xE0) << 3) | data[pos]
        else:
            length = 1 + (tag >> 2)
            offset = int.from_bytes(data[pos : pos + width], "little")
        pos += width

        if offset == 0 or offset > len(output):
            raise EreError("Invalid Snappy copy offset")
        if len(output) + length > expected:
            raise EreError("Snappy copy exceeds declared output length")

        # Copies may overlap: each newly appended byte can become a source.
        for _ in range(length):
            output.append(output[-offset])

    if len(output) != expected:
        raise EreError(
            f"Snappy output length mismatch: expected {expected}, got {len(output)}"
        )
    return bytes(output)


def _snappy_raw_decode(data: bytes) -> bytes:
    expected, pos = _snappy_raw_length(data)
    if expected > _MAX_SNAPPY_CHUNK:
        raise EreError("Snappy chunk exceeds the 65536-byte uncompressed limit")

    if _cramjam_snappy is None:
        return _snappy_raw_python(data, expected, pos)

    try:
        output = bytes(_cramjam_snappy.decompress_raw(data))
    except Exception as exc:
        # cramjam's extension-defined exception types vary across releases.
        raise EreError(f"Invalid raw Snappy block: {exc}") from exc
    if len(output) != expected:
        raise EreError("Snappy output length does not match its declared length")
    return output


def snappy_frame_decode(data: bytes) -> bytes:
    """Decode a Snappy framed stream and verify every data chunk's CRC32C.

    Supports compressed and uncompressed chunks, repeated stream identifiers,
    and skippable extension chunks. Rejects unknown unskippable chunks.
    """
    output = bytearray()
    pos = 0
    identified = False

    while pos < len(data):
        if len(data) - pos < 4:
            raise EreError("Truncated Snappy frame chunk header")

        kind = data[pos]
        length = int.from_bytes(data[pos + 1 : pos + 4], "little")
        pos += 4
        end = pos + length
        if end > len(data):
            raise EreError("Truncated Snappy frame chunk")
        chunk = data[pos:end]
        pos = end

        if kind == 0xFF:
            if chunk != _SNAPPY_IDENTIFIER:
                raise EreError("Invalid Snappy stream identifier")
            identified = True
            continue

        if not identified:
            raise EreError("Snappy stream must begin with its stream identifier")

        if 0x80 <= kind <= 0xFE:
            continue
        if kind not in (0x00, 0x01):
            raise EreError(f"Unknown unskippable Snappy chunk type 0x{kind:02x}")
        if len(chunk) < 4:
            raise EreError("Snappy data chunk is missing its CRC32C")

        expected_crc = int.from_bytes(chunk[:4], "little")
        decoded = _snappy_raw_decode(chunk[4:]) if kind == 0x00 else chunk[4:]
        if len(decoded) > _MAX_SNAPPY_CHUNK:
            raise EreError("Snappy chunk exceeds the 65536-byte uncompressed limit")
        if _masked_crc32c(decoded) != expected_crc:
            raise EreError("Snappy CRC32C mismatch")
        output.extend(decoded)

    if not identified:
        raise EreError("Missing Snappy stream identifier")
    return bytes(output)


def _rlp_item(
    data: bytes, pos: int, limit: int, depth: int
) -> tuple[RLP, int]:
    if depth > _MAX_RLP_DEPTH:
        raise EreError(f"RLP nesting exceeds {_MAX_RLP_DEPTH}")
    if pos >= limit:
        raise EreError("Truncated RLP item")

    prefix = data[pos]
    if prefix < 0x80:
        return data[pos : pos + 1], pos + 1

    is_list = prefix >= 0xC0
    short_base = 0xC0 if is_list else 0x80
    long_base = 0xF7 if is_list else 0xB7
    start = pos + 1

    if prefix <= long_base:
        length = prefix - short_base
    else:
        width = prefix - long_base
        if start + width > limit:
            raise EreError("Truncated RLP length")
        if data[start] == 0:
            raise EreError("Noncanonical RLP length with leading zero")
        length = int.from_bytes(data[start : start + width], "big")
        start += width
        if length < 56:
            raise EreError("Noncanonical long-form RLP length")

    end = start + length
    if end > limit:
        raise EreError("Truncated RLP payload")

    if not is_list:
        if length == 1 and data[start] < 0x80:
            raise EreError("Noncanonical RLP single-byte string")
        return data[start:end], end

    values: list[RLP] = []
    cursor = start
    while cursor < end:
        value, cursor = _rlp_item(data, cursor, end, depth + 1)
        values.append(value)
    return values, end


def rlp_decode(b: bytes) -> RLP:
    """Decode exactly one canonical RLP value; reject trailing bytes."""
    value, end = _rlp_item(b, 0, len(b), 0)
    if end != len(b):
        raise EreError("Trailing bytes after RLP value")
    return value


def _rlp_prefix(length: int, short_base: int, long_base: int) -> bytes:
    if length < 56:
        return bytes([short_base + length])
    encoded_length = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([long_base + len(encoded_length)]) + encoded_length


def _rlp_encode(value: RLP) -> bytes:
    """Re-encode a decoded legacy transaction into its canonical wire form."""
    if isinstance(value, bytes):
        if len(value) == 1 and value[0] < 0x80:
            return value
        return _rlp_prefix(len(value), 0x80, 0xB7) + value
    payload = b"".join(_rlp_encode(item) for item in value)
    return _rlp_prefix(len(payload), 0xC0, 0xF7) + payload


def _rlp_uint(value: RLP, field: str) -> int:
    if not isinstance(value, bytes):
        raise EreError(f"{field} must be an RLP byte string")
    if value and value[0] == 0:
        raise EreError(f"{field} has a noncanonical integer encoding")
    return int.from_bytes(value, "big")


def _header_metadata(payload: bytes) -> tuple[int, int]:
    header = rlp_decode(snappy_frame_decode(payload))
    if not isinstance(header, list) or len(header) < 12:
        raise EreError("Header must be an RLP list with at least 12 fields")
    return (
        _rlp_uint(header[8], "Header number"),
        _rlp_uint(header[11], "Header timestamp"),
    )


def _body_transactions(payload: bytes) -> list[bytes]:
    body = rlp_decode(snappy_frame_decode(payload))
    if not isinstance(body, list) or len(body) not in (2, 3):
        raise EreError("Body must contain transactions, uncles, and optional withdrawals")
    if not all(isinstance(field, list) for field in body):
        raise EreError("Body transactions, uncles, and withdrawals must be lists")

    transactions = body[0]
    assert isinstance(transactions, list)
    result: list[bytes] = []
    for transaction in transactions:
        if isinstance(transaction, list):
            result.append(_rlp_encode(transaction))
        else:
            if not transaction or transaction[0] not in (1, 2, 3, 4):
                raise EreError("Expected a legacy list or a type-1/2/3/4 envelope")
            # A typed transaction is already its complete wire encoding.
            result.append(transaction)
    return result


def _iter_blocks_and_receipts(path: Pathish) -> Iterator[Block | bytes]:
    """Yield each Block in body order and each raw slim-receipts payload.

    Receipt payloads are positional like bodies (the n-th belongs to the n-th
    header) and are returned undecoded, so callers decode only what they need.
    """
    headers: list[tuple[int, int]] = []
    body_count = 0
    bodies_started = False

    for entry_type, payload in iter_entries(path):
        if entry_type == COMPRESSED_HEADER:
            if bodies_started:
                raise EreError("CompressedHeader appears after bodies have started")
            headers.append(_header_metadata(payload))
        elif entry_type == COMPRESSED_BODY:
            bodies_started = True
            if body_count >= len(headers):
                raise EreError("Header/body count mismatch: more bodies than headers")
            number, timestamp = headers[body_count]
            txs = _body_transactions(payload)
            body_count += 1
            yield Block(number=number, timestamp=timestamp, txs=txs)
        elif entry_type == COMPRESSED_SLIM_RECEIPTS:
            yield payload
        # Version, index, proofs, difficulty, roots, and unknown entry types
        # do not affect positional header/body pairing.

    if body_count != len(headers):
        raise EreError(
            f"Header/body count mismatch: {len(headers)} headers, {body_count} bodies"
        )


def iter_blocks(path: Pathish) -> Iterator[Block]:
    """Pair headers and bodies by position, buffering only header metadata.

    Header numbers are authoritative; filenames need not follow a convention.
    All headers must precede bodies. Count validation finishes at exhaustion,
    so callers must consume the entire iterator to validate the entire file.
    """
    for item in _iter_blocks_and_receipts(path):
        if isinstance(item, Block):
            yield item


def _keccak256(data: bytes) -> bytes:
    """Use Ethereum Keccak-256, deliberately never hashlib.sha3_256."""
    try:
        from Crypto.Hash import keccak
    except ImportError:
        try:
            from eth_hash.auto import keccak as eth_keccak

            return eth_keccak(data)
        except ImportError as exc:
            raise RuntimeError(
                "Ethereum Keccak-256 is unavailable. Install pycryptodome or "
                "'eth-hash[pycryptodome]'; hashlib.sha3_256 is not compatible."
            ) from exc
    return keccak.new(digest_bits=256, data=data).digest()


def blob_txs(block: Block, to_address: bytes) -> list[BlobTx]:
    """Extract type-3 transactions addressed to an exact 20-byte recipient."""
    if not isinstance(to_address, bytes) or len(to_address) != 20:
        raise ValueError("to_address must be exactly 20 bytes")

    matches: list[BlobTx] = []
    for index, transaction in enumerate(block.txs):
        if not transaction or transaction[0] != 0x03:
            continue

        fields = rlp_decode(transaction[1:])
        if not isinstance(fields, list) or len(fields) != 14:
            raise EreError("EIP-4844 transaction payload must contain 14 fields")

        recipient, calldata, hashes = fields[5], fields[7], fields[10]
        if not isinstance(recipient, bytes) or len(recipient) != 20:
            raise EreError("EIP-4844 transaction recipient must be 20 bytes")
        if not isinstance(calldata, bytes):
            raise EreError("EIP-4844 transaction data must be a byte string")
        if not isinstance(hashes, list):
            raise EreError("EIP-4844 versioned hashes must be a list")

        versioned_hashes: list[bytes] = []
        for value in hashes:
            if not isinstance(value, bytes) or len(value) != 32:
                raise EreError("Each blob versioned hash must be 32 bytes")
            versioned_hashes.append(value)

        if recipient == to_address:
            matches.append(
                BlobTx(
                    block_number=block.number,
                    timestamp=block.timestamp,
                    tx_index=index,
                    tx_hash=_keccak256(transaction),
                    to=recipient,
                    data=calldata,
                    versioned_hashes=versioned_hashes,
                )
            )
    return matches


def _receipt_status(receipts: RLP, tx_index: int, tx_count: int) -> int:
    """Return 1/0 from a slim receipt [type, status, cumulative_gas, logs]."""
    if not isinstance(receipts, list) or len(receipts) != tx_count:
        raise EreError("Receipt count does not match the block's transaction count")
    receipt = receipts[tx_index]
    if not isinstance(receipt, list) or len(receipt) != 4:
        raise EreError("Slim receipt must be [type, status, cumulative_gas, logs]")
    if receipt[0] != b"\x03":
        raise EreError("Receipt type does not match the EIP-4844 transaction")
    if receipt[1] not in (b"", b"\x01"):
        raise EreError("Receipt status must be 0 or 1")
    return 1 if receipt[1] else 0


def blob_txs_with_status(path: Pathish, to_address: bytes) -> Iterator[BlobTx]:
    """Matching blob transactions with status read from the same file's receipts.

    A reverted blob transaction is still included with its blobs, so a
    versioned-hash match alone does not show that L1 accepted it; callers
    should drop status != 1. Receipts follow all bodies in Ere, so matches are
    buffered and yielded only after the receipts have been read. Missing or
    inconsistent receipts raise EreError rather than defaulting to success.
    """
    tx_counts: list[int] = []
    pending: dict[int, list[BlobTx]] = {}
    receipt_count = 0

    for item in _iter_blocks_and_receipts(path):
        if isinstance(item, Block):
            matches = blob_txs(item, to_address)
            if matches:
                pending[len(tx_counts)] = matches
            tx_counts.append(len(item.txs))
            continue

        position = receipt_count
        receipt_count += 1
        if position >= len(tx_counts):
            raise EreError("Receipts entry appears before its body")
        if position in pending:
            receipts = rlp_decode(snappy_frame_decode(item))
            for transaction in pending[position]:
                transaction.status = _receipt_status(
                    receipts, transaction.tx_index, tx_counts[position]
                )

    if receipt_count != len(tx_counts):
        raise EreError(
            f"Receipt/body count mismatch: {len(tx_counts)} bodies, "
            f"{receipt_count} receipt entries"
        )
    for matches in pending.values():
        yield from matches


def slot_for_timestamp(ts: int) -> int:
    """Return the mainnet beacon slot using floor division."""
    return (ts - 1606824023) // 12


def _parse_address(value: str) -> bytes:
    if not value.startswith("0x") or len(value) != 42:
        raise argparse.ArgumentTypeError("Address must be 0x followed by 40 hex digits")
    try:
        address = bytes.fromhex(value[2:])
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Address contains invalid hex digits") from exc
    if len(address) != 20:
        raise argparse.ArgumentTypeError("Address must decode to exactly 20 bytes")
    return address


def _json_record(transaction: BlobTx) -> dict[str, object]:
    return {
        "block_number": transaction.block_number,
        "timestamp": transaction.timestamp,
        "tx_index": transaction.tx_index,
        "tx_hash": "0x" + transaction.tx_hash.hex(),
        "to": "0x" + transaction.to.hex(),
        "data": "0x" + transaction.data.hex(),
        "versioned_hashes": [
            "0x" + value.hex() for value in transaction.versioned_hashes
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    """Print one JSON object per matching blob transaction."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path, help="Ere archive")
    parser.add_argument("address", type=_parse_address, help="0x-prefixed recipient")
    args = parser.parse_args(argv)

    try:
        for block in iter_blocks(args.file):
            for transaction in blob_txs(block, args.address):
                print(json.dumps(_json_record(transaction), separators=(",", ":")))
    except BrokenPipeError:
        return 0
    except (OSError, EreError, RuntimeError) as exc:
        parser.exit(1, f"ere_reader: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
