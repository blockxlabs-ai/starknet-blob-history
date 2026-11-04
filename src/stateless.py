"""Port of stateless_compression/utils.rs, compression version 0.

Wire layout:
    packed header
    unique buckets: 252, 125, 83, 62, 31, 15 bits
    packed repeating-value pointers
    packed bucket indices

The header has nine little-endian base-2**20 digits:
    version, data_length, six unique-bucket lengths, repeat_count.

Pointers use base n_unique_values, NOT fixed-width binary fields.
Bucket indices use base 7. Their packing capacities are nevertheless
computed using ceil(log2(base)), exactly as in the Rust.

decompress() consumes one frame from an iterator and leaves its suffix
untouched. Like the reference, it does not validate canonical padding,
bucket-length consistency, or complete consumption. Truncated/malformed
input can produce short output or raise an exception; this is not a
hardened untrusted-input validator. Rust panics become Python exceptions.

Inputs represent canonical Starknet felts. compress() validates this
Python-specific precondition; no implicit modular reduction is performed.
"""

from collections.abc import Iterable, Sequence
from itertools import islice


FELT_PRIME = 2**251 + 17 * 2**192 + 1

COMPRESSION_VERSION = 0
HEADER_ELM_N_BITS = 20
HEADER_ELM_BOUND = 1 << HEADER_ELM_N_BITS
N_UNIQUE_BUCKETS = 6
TOTAL_N_BUCKETS = N_UNIQUE_BUCKETS + 1
MAX_N_BITS = 251
HEADER_LEN = 1 + 1 + TOTAL_N_BUCKETS

# Serialization order, opposite the Rust BitLength enum declaration order.
BUCKET_BITS = (252, 125, 83, 62, 31, 15)


def get_n_elms_per_felt(elm_bound: int) -> int:
    """Reference capacity calculation, including bounds zero and one."""
    if elm_bound <= 1:
        return MAX_N_BITS
    return MAX_N_BITS // (elm_bound - 1).bit_length()


def pack_in_felts(elms: Sequence[int], elm_bound: int) -> list[int]:
    """Pack little-endian base-elm_bound digits in reference-sized chunks.

    Like the Rust helper, assumes elements satisfy their stated bound.
    """
    capacity = get_n_elms_per_felt(elm_bound)
    result = []
    for start in range(0, len(elms), capacity):
        word = 0
        for value in reversed(elms[start:start + capacity]):
            word = word * elm_bound + value
        result.append(word)
    return result


def unpack_felts_to(
    compressed: Iterable[int], n_elms: int, elm_bound: int
) -> list[int]:
    """Port of unpack_felts_to::<usize>, using Python integer results."""
    capacity = get_n_elms_per_felt(elm_bound)
    result = []
    for word in compressed:
        count = min(capacity, n_elms - len(result))
        for _ in range(count):
            word, value = divmod(word, elm_bound)
            result.append(value)
    return result


def get_bucket_offsets(bucket_lengths: Iterable[int]) -> list[int]:
    offsets = []
    offset = 0
    for length in bucket_lengths:
        offsets.append(offset)
        offset += length
    return offsets


def unpack_felts(
    compressed: Iterable[int], n_elms: int, length: int
) -> list[int]:
    """Port of unpack_felts::<LENGTH> for the five bit-array buckets."""
    if length not in BUCKET_BITS[1:]:
        raise ValueError("Expected a bit-array bucket width")
    capacity = max(MAX_N_BITS // length, 1)
    mask = (1 << length) - 1
    result = []
    for word in compressed:
        count = min(capacity, n_elms - len(result))
        for index in range(count):
            result.append((word >> (index * length)) & mask)
    return result


def _bucket_index(value: int) -> int:
    for index in range(N_UNIQUE_BUCKETS - 1, -1, -1):
        if value.bit_length() <= BUCKET_BITS[index]:
            return index
    raise ValueError("Value exceeds 252 bits")


def compress(data: Sequence[int]) -> list[int]:
    """Produce the same compressed felts as the reference compress()."""
    if len(data) >= HEADER_ELM_BOUND:
        raise ValueError(f"Data is too long: {len(data)} >= {HEADER_ELM_BOUND}")

    # Python dict preserves insertion order, matching Rust IndexMap.
    buckets: list[dict[int, int]] = [{} for _ in BUCKET_BITS]
    repeats: list[tuple[int, int]] = []
    bucket_indices = []

    for value in data:
        if type(value) is not int or not 0 <= value < FELT_PRIME:
            raise ValueError(f"Not a canonical Starknet felt: {value!r}")
        index = _bucket_index(value)
        bucket = buckets[index]
        if value in bucket:
            repeats.append((index, bucket[value]))
            bucket_indices.append(N_UNIQUE_BUCKETS)
        else:
            bucket[value] = len(bucket)
            bucket_indices.append(index)

    lengths = [len(bucket) for bucket in buckets]
    offsets = get_bucket_offsets(lengths)
    pointers = [offsets[index] + local for index, local in repeats]
    header = [COMPRESSION_VERSION, len(data), *lengths, len(repeats)]

    result = pack_in_felts(header, HEADER_ELM_BOUND)
    for bits, bucket in zip(BUCKET_BITS, buckets):
        values = list(bucket)
        if bits == 252:
            result.extend(values)
        else:
            result.extend(pack_in_felts(values, 1 << bits))

    result.extend(pack_in_felts(pointers, sum(lengths)))
    result.extend(pack_in_felts(bucket_indices, TOTAL_N_BUCKETS))
    return result


def decompress(compressed: Iterable[int]) -> list[int]:
    """Decode one frame, preserving the suffix when passed an iterator."""
    stream = iter(compressed)

    def unpack_chunk_to_usize(n_elms: int, bound: int) -> list[int]:
        capacity = get_n_elms_per_felt(bound)
        n_words = (n_elms + capacity - 1) // capacity
        return unpack_felts_to(islice(stream, n_words), n_elms, bound)

    def unpack_chunk(n_elms: int, length: int) -> list[int]:
        capacity = max(MAX_N_BITS // length, 1)
        n_words = (n_elms + capacity - 1) // capacity
        return unpack_felts(islice(stream, n_words), n_elms, length)

    header = unpack_chunk_to_usize(HEADER_LEN, HEADER_ELM_BOUND)
    if header[0] != COMPRESSION_VERSION:
        raise ValueError("Unsupported compression version")

    data_len = header[1]
    lengths = header[2:2 + N_UNIQUE_BUCKETS]
    n_repeats = header[2 + N_UNIQUE_BUCKETS]

    unique_values = list(islice(stream, lengths[0]))
    for length, count in zip(BUCKET_BITS[1:], lengths[1:]):
        unique_values.extend(unpack_chunk(count, length))

    pointers = unpack_chunk_to_usize(n_repeats, len(unique_values))
    repeating_values = [unique_values[pointer] for pointer in pointers]
    all_values = unique_values + repeating_values

    bucket_indices = unpack_chunk_to_usize(data_len, TOTAL_N_BUCKETS)
    trackers = get_bucket_offsets([*lengths, n_repeats])

    result = []
    for index in bucket_indices:
        result.append(all_values[trackers[index]])
        trackers[index] += 1
    return result
