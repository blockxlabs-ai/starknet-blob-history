"""Pure-Python port of StarkWare's blob FFT encoding and decoding.

Wire scalars are big-endian. As in Rust's Fr::from(BigUint), deserialization
reduces modulo the BLS scalar modulus rather than rejecting noncanonical input.
KZG commitment computation separately enforces ckzg's canonical-input rules.

The Rust decoder finishes with Felt::from_bytes_be_slice: decoded Fr
coefficients are therefore reduced modulo the Starknet field modulus. For
Starknet-felt input coefficients this conversion leaves the values unchanged.
"""

from __future__ import annotations

from collections.abc import Iterable

FIELD_ELEMENTS_PER_BLOB = 4096
LOG2_FIELD_ELEMENTS_PER_BLOB = 12
BYTES_PER_FIELD_ELEMENT = 32
BYTES_PER_BLOB = FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD_ELEMENT

BLS_MODULUS = (
    52435875175126190479447740508185965837690552500527637822603658699938581184513
)
STARKNET_MODULUS = 2**251 + 17 * 2**192 + 1
TWO_ADICITY = 32
MULTIPLICATIVE_GENERATOR = 7
TWO_ADIC_ROOT_OF_UNITY = pow(
    MULTIPLICATIVE_GENERATOR,
    (BLS_MODULUS - 1) // (1 << TWO_ADICITY),
    BLS_MODULUS,
)
ROOT_OF_UNITY = pow(
    TWO_ADIC_ROOT_OF_UNITY,
    1 << (TWO_ADICITY - LOG2_FIELD_ELEMENTS_PER_BLOB),
    BLS_MODULUS,
)
INVERSE_ROOT_OF_UNITY = pow(ROOT_OF_UNITY, -1, BLS_MODULUS)
INVERSE_DOMAIN_SIZE = pow(FIELD_ELEMENTS_PER_BLOB, -1, BLS_MODULUS)


class BlobDecodeError(ValueError):
    """Invalid blob size or coefficient input."""


def _reverse_index(index: int) -> int:
    result = 0
    for _ in range(LOG2_FIELD_ELEMENTS_PER_BLOB):
        result = (result << 1) | (index & 1)
        index >>= 1
    return result


# Immutable tables constructed only once, at module import.
_BIT_REVERSAL_SWAPS = tuple(
    (index, reversed_index)
    for index in range(FIELD_ELEMENTS_PER_BLOB)
    if index < (reversed_index := _reverse_index(index))
)


def _make_twiddles(root: int) -> tuple[tuple[int, ...], ...]:
    stages = []
    width = 2
    while width <= FIELD_ELEMENTS_PER_BLOB:
        step = pow(root, FIELD_ELEMENTS_PER_BLOB // width, BLS_MODULUS)
        powers = [1]
        for _ in range(1, width // 2):
            powers.append(powers[-1] * step % BLS_MODULUS)
        stages.append(tuple(powers))
        width *= 2
    return tuple(stages)


_FORWARD_TWIDDLES = _make_twiddles(ROOT_OF_UNITY)
_INVERSE_TWIDDLES = _make_twiddles(INVERSE_ROOT_OF_UNITY)


def bit_reversal(values: list[int]) -> None:
    """Apply the fixed 12-bit index permutation in place."""
    if len(values) != FIELD_ELEMENTS_PER_BLOB:
        raise BlobDecodeError(
            f"expected {FIELD_ELEMENTS_PER_BLOB} values, got {len(values)}"
        )
    for index, reversed_index in _BIT_REVERSAL_SWAPS:
        values[index], values[reversed_index] = (
            values[reversed_index],
            values[index],
        )


def _ntt_in_place(values: list[int], *, inverse: bool = False) -> None:
    """Natural-order input/output iterative radix-2 DIT NTT, O(n log n)."""
    bit_reversal(values)
    stages = _INVERSE_TWIDDLES if inverse else _FORWARD_TWIDDLES
    modulus = BLS_MODULUS

    for twiddles in stages:
        half = len(twiddles)
        width = half * 2
        for start in range(0, FIELD_ELEMENTS_PER_BLOB, width):
            for offset, twiddle in enumerate(twiddles):
                left = start + offset
                right = left + half
                even = values[left]
                odd = values[right] * twiddle % modulus
                values[left] = (even + odd) % modulus
                values[right] = (even - odd) % modulus

    if inverse:
        for index, value in enumerate(values):
            values[index] = value * INVERSE_DOMAIN_SIZE % modulus


def coefficients_to_blob(coeffs: Iterable[int]) -> bytes:
    """Pad to 4096, FFT, bit-reverse evaluations, and serialize.

    Integer inputs are interpreted in Fr (reduced modulo BLS_MODULUS).
    decode_blobs returns Starknet felts, so exact integer round trips require
    coefficients in [0, STARKNET_MODULUS).
    """
    values = list(coeffs)
    if len(values) > FIELD_ELEMENTS_PER_BLOB:
        raise BlobDecodeError(
            f"too many coefficients: expected at most "
            f"{FIELD_ELEMENTS_PER_BLOB}, got {len(values)}"
        )
    for index, value in enumerate(values):
        if not isinstance(value, int):
            raise TypeError(f"coefficient {index} must be an integer")
        values[index] = value % BLS_MODULUS

    values.extend([0] * (FIELD_ELEMENTS_PER_BLOB - len(values)))
    _ntt_in_place(values)
    bit_reversal(values)
    return b"".join(
        value.to_bytes(BYTES_PER_FIELD_ELEMENT, "big") for value in values
    )


def decode_blobs(raw_blobs: Iterable[bytes]) -> list[int]:
    """Decode each blob to 4096 Starknet-felt integers and concatenate."""
    result: list[int] = []
    for blob_index, raw_blob in enumerate(raw_blobs):
        if len(raw_blob) != BYTES_PER_BLOB:
            raise BlobDecodeError(
                f"blob {blob_index}: expected {BYTES_PER_BLOB} bytes, "
                f"got {len(raw_blob)}"
            )
        values = [
            int.from_bytes(
                raw_blob[offset : offset + BYTES_PER_FIELD_ELEMENT], "big"
            )
            % BLS_MODULUS
            for offset in range(0, BYTES_PER_BLOB, BYTES_PER_FIELD_ELEMENT)
        ]
        bit_reversal(values)
        _ntt_in_place(values, inverse=True)
        result.extend(value % STARKNET_MODULUS for value in values)
    return result
