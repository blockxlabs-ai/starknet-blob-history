"""Parse the reference partial/non-full-output state-diff representation.

parse_decompressed() implements Vec<PartialContractChanges> followed by
Vec<PartialCompiledClassHashUpdate> from os_output_types.rs. There are no
previous values. A packed nonce of zero means None, not an explicit update
to zero. The class-hash field is present only when the class flag is set.

decode_da() mirrors PartialOsStateDiff::try_from_output_iter:
    decompress(iter).into_iter().chain(iter)
Consequently a raw suffix can supply fields after the compressed prefix.
It does not repeatedly decompress frames or strip zeros from the input.

Scope: plaintext DA payloads, already IFFT-decoded and concatenated.
For use_kzg_da=true, full_output=false, os_output.rs itself parses only
PartialCommitmentOsStateDiff, i.e. commitment metadata. This module parses
the explicit partial payload behind that commitment, not the outer OS
output, KZG metadata, or encrypted payloads.

Reference/API differences:
* Rust stores storage updates in a Vec; the requested Python API uses a
  dict. Duplicate keys therefore retain the last value.
* Python exceptions replace Rust parsing errors.
* No platform-dependent usize limit is imposed on count fields.
* Parsing leaves trailing data unread by default, as the relevant Rust
  parsers do. strict=True is an additional exhaustion check, inappropriate
  for an input containing blob padding.
"""

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from itertools import chain

from .stateless import FELT_PRIME, decompress


N_UPDATES_BOUND = 1 << 64
N_UPDATES_SMALL_PACKING_BOUND = 1 << 8
FLAG_BOUND = 2
PATRICIA_KEY_BOUND = 1 << 251


@dataclass
class ContractDiff:
    address: int
    nonce: int | None
    class_hash: int | None
    storage: dict[int, int]


@dataclass
class ClassDeclaration:
    class_hash: int
    compiled_class_hash: int


@dataclass
class StateDiff:
    contracts: list[ContractDiff]
    classes: list[ClassDeclaration]


class StateDiffDecodeError(ValueError):
    pass


def _read(stream: Iterator[int], field: str) -> int:
    try:
        value = next(stream)
    except StopIteration:
        raise StateDiffDecodeError(f"Missing expected field: {field}") from None
    if type(value) is not int or not 0 <= value < FELT_PRIME:
        raise StateDiffDecodeError(f"Invalid felt in {field}: {value!r}")
    return value


def _read_patricia_key(stream: Iterator[int], field: str) -> int:
    value = _read(stream, field)
    if value >= PATRICIA_KEY_BOUND:
        raise StateDiffDecodeError(f"Invalid Patricia key in {field}: {value}")
    return value


def parse_decompressed(
    felts: Iterable[int], *, strict: bool = False
) -> StateDiff:
    """Read one explicit partial state diff from decompressed felts."""
    stream = iter(felts)
    contracts = []

    n_contracts = _read(stream, "n_items of PartialContractChanges")
    for _ in range(n_contracts):
        address = _read_patricia_key(stream, "addr")
        header = _read(stream, "nonce_n_changes_two_flags")

        nonce_n_changes_one_flag, class_updated = divmod(header, FLAG_BOUND)
        nonce_n_changes, is_small = divmod(
            nonce_n_changes_one_flag, FLAG_BOUND
        )
        bound = N_UPDATES_SMALL_PACKING_BOUND if is_small else N_UPDATES_BOUND
        nonce, n_changes = divmod(nonce_n_changes, bound)

        class_hash = _read(stream, "new_class_hash") if class_updated else None
        storage = {}
        for _ in range(n_changes):
            key = _read_patricia_key(stream, "storage key")
            value = _read(stream, "storage value")
            storage[key] = value

        contracts.append(
            ContractDiff(address, nonce if nonce else None, class_hash, storage)
        )

    n_classes = _read(stream, "n_items of PartialCompiledClassHashUpdate")
    classes = []
    for _ in range(n_classes):
        class_hash = _read(stream, "class_hash")
        compiled_class_hash = _read(stream, "new_compiled_class_hash")
        classes.append(ClassDeclaration(class_hash, compiled_class_hash))

    if strict:
        sentinel = object()
        if next(stream, sentinel) is not sentinel:
            raise StateDiffDecodeError("Output iterator not exhausted")

    return StateDiff(contracts, classes)


def decode_da(felts: Iterable[int], *, strict: bool = False) -> StateDiff:
    """Stateless-decompress and parse; addresses/keys remain aliased.

    For v0.13.4+ call aliases.apply(result, persistent_alias_map) afterwards.
    Do not use this entry point for pre-stateless-compression payloads.
    """
    stream = iter(felts)
    decompressed = decompress(stream)
    return parse_decompressed(chain(decompressed, stream), strict=strict)
