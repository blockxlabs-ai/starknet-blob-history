"""Archive discovery and blob matching by recomputed KZG commitments.

Matching verifies that blob contents produce the requested versioned hashes.
It does not verify separate KZG proofs or establish beacon-chain inclusion.
ckzg is imported lazily; archive access does not require it.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from hashlib import sha256
from os import PathLike, fspath
from pathlib import Path
from typing import Literal

BYTES_PER_BLOB = 131072
SLOTS_PER_ERA = 8192
# Blob archive roots: set BLOB_ARCHIVE_ROOTS (os.pathsep-separated) or pass roots explicitly.
# Layout under each root: era_<slot // 8192, 5 digits>/blobs_<slot>.ssz (N x 131072-byte blobs).
DEFAULT_ROOTS = tuple(Path(p) for p in __import__("os").environ.get("BLOB_ARCHIVE_ROOTS", "").split(__import__("os").pathsep) if p)

type Root = str | PathLike[str]
type Roots = Iterable[Root] | Root | None


class BlobStoreError(Exception):
    """Base class for archive and matching errors."""


class InvalidBlobFileSize(BlobStoreError, ValueError):
    def __init__(self, path: Path, size: int) -> None:
        self.path = path
        self.size = size
        super().__init__(
            f"{path}: size {size} is not a multiple of {BYTES_PER_BLOB}"
        )


class MissingBlobsError(BlobStoreError):
    def __init__(self, missing_hashes: Iterable[bytes]) -> None:
        # Preserve request order, including duplicate missing requests.
        self.missing_hashes = list(missing_hashes)
        super().__init__(
            "Missing blobs for versioned hashes: "
            + ", ".join("0x" + value.hex() for value in self.missing_hashes)
        )


@dataclass(frozen=True, slots=True)
class SlotFile:
    status: Literal["blobs", "columns_only", "missing"]
    path: Path | None


def _root_paths(roots: Roots) -> tuple[Path, ...]:
    if roots is None:
        if not DEFAULT_ROOTS:
            raise BlobStoreError("no blob archive roots: set BLOB_ARCHIVE_ROOTS or pass roots")
        return DEFAULT_ROOTS
    if isinstance(roots, (str, PathLike)):
        return (Path(roots),)
    return tuple(Path(root) for root in roots)


def find_slot_file(slot: int, roots: Roots = None) -> SlotFile:
    """Search all roots for blobs before reporting columns_only.

    Within each category, the first matching root wins. Explicit roots replace
    the defaults. Missing slots return SlotFile("missing", None).
    """
    if isinstance(slot, bool) or not isinstance(slot, int):
        raise TypeError("slot must be an integer")
    if slot < 0:
        raise ValueError("slot must be nonnegative")

    directories = tuple(
        root / f"era_{slot // SLOTS_PER_ERA:05d}"
        for root in _root_paths(roots)
    )
    for directory in directories:
        path = directory / f"blobs_{slot}.ssz"
        if path.is_file():
            return SlotFile("blobs", path)

    for directory in directories:
        path = directory / f"columns_{slot}.ssz"
        if path.is_file():
            return SlotFile("columns_only", path)

    return SlotFile("missing", None)


def load_blobs(slot: int, roots: Roots = None) -> list[bytes] | None:
    """Return complete blobs, or None for missing/columns-only slots.

    Use find_slot_file to distinguish missing from columns_only. An empty
    blob file is valid and returns []; malformed sizes raise.
    """
    found = find_slot_file(slot, roots)
    if found.status != "blobs":
        return None

    assert found.path is not None
    data = found.path.read_bytes()
    if len(data) % BYTES_PER_BLOB:
        raise InvalidBlobFileSize(found.path, len(data))
    return [
        data[offset : offset + BYTES_PER_BLOB]
        for offset in range(0, len(data), BYTES_PER_BLOB)
    ]


def load_trusted_setup(path: Root) -> object:
    """Load a caller-supplied ckzg trusted setup, e.g. refs/trusted_setup.txt."""
    import ckzg

    return ckzg.load_trusted_setup(fspath(path), 0)


def versioned_hash(commitment: bytes) -> bytes:
    if len(commitment) != 48:
        raise ValueError("a KZG commitment must contain exactly 48 bytes")
    return b"\x01" + sha256(commitment).digest()[1:]


def match_blobs(
    slot_blobs: Iterable[bytes],
    wanted_versioned_hashes: Iterable[bytes],
    ts: object,
) -> list[bytes]:
    """Recompute commitments and return blobs in requested hash order.

    Duplicate requests return the matching blob repeatedly; matching does not
    consume a blob. ckzg errors, including noncanonical scalar errors, propagate.
    """
    wanted = list(wanted_versioned_hashes)
    for value in wanted:
        if not isinstance(value, bytes):
            raise TypeError("versioned hashes must be bytes")
        if len(value) != 32:
            raise ValueError("a versioned hash must contain exactly 32 bytes")
    if not wanted:
        return []

    import ckzg

    wanted_set = set(wanted)
    matches: dict[bytes, bytes] = {}
    for blob in slot_blobs:
        if len(blob) != BYTES_PER_BLOB:
            raise ValueError(
                f"blob must contain {BYTES_PER_BLOB} bytes, got {len(blob)}"
            )
        commitment = ckzg.blob_to_kzg_commitment(blob, ts)
        digest = versioned_hash(commitment)
        if digest in wanted_set:
            matches.setdefault(digest, blob)

    missing = [value for value in wanted if value not in matches]
    if missing:
        raise MissingBlobsError(missing)
    return [matches[value] for value in wanted]
