"""Decode updateStateKzgDA calldata and locate the referenced OS header.

ABI offsets are relative to the arguments block, except bytes[] element
offsets, which are relative to the element-offset table AFTER its length.
We require aligned offsets, complete padded payloads, zero byte padding,
and non-overlapping occupied regions. Disjoint reordered tails, gaps, and
trailing words are accepted; this is not a canonical-encoding checker.

Header discovery never infers a bootloader/aggregator prefix format.
With an expected hash, the first matching offset in 0..64 is returned.
Without one, only offset zero is considered and it is marked unverified.

The supplied excerpt does not specify PreviousBlockNumber's genesis
sentinel encoding. Parsing preserves that felt; discovery only accepts
the task's ordinary numeric new_block_number > prev_block_number rule.
"""

from collections.abc import Sequence

from .stateless import FELT_PRIME


SELECTOR = bytes.fromhex("507ee528")
HEADER_FIELDS = (
    "initial_root",
    "final_root",
    "prev_block_number",
    "new_block_number",
    "prev_block_hash",
    "new_block_hash",
    "os_program_hash",
    "starknet_os_config_hash",
    "use_kzg_da",
    "full_output",
)


class CalldataError(ValueError):
    """Base class for invalid updateStateKzgDA calldata."""


class SelectorError(CalldataError):
    pass


class ABIError(CalldataError):
    pass


class HeaderError(ValueError):
    pass


def decode_calldata(data: bytes) -> tuple[list[int], list[bytes]]:
    if not isinstance(data, bytes):
        raise CalldataError("Calldata must be bytes")
    if data[:4] != SELECTOR:
        raise SelectorError("Unexpected function selector")

    body = data[4:]
    size = len(body)
    if size < 64 or size % 32:
        raise ABIError("Arguments must contain a complete two-word head")

    occupied: list[tuple[int, int]] = [(0, 64)]

    def word(pos: int) -> int:
        if pos < 0 or pos % 32 or pos + 32 > size:
            raise ABIError("Word is unaligned or outside calldata")
        return int.from_bytes(body[pos:pos + 32], "big")

    def occupy(start: int, end: int) -> None:
        if start < 0 or start % 32 or end < start or end > size:
            raise ABIError("ABI region is outside calldata")
        if any(start < other_end and other_start < end
               for other_start, other_end in occupied):
            raise ABIError("Overlapping ABI regions")
        occupied.append((start, end))

    def array_position(head_pos: int) -> int:
        pos = word(head_pos)
        if pos < 64 or pos % 32 or pos + 32 > size:
            raise ABIError("Invalid top-level array offset")
        return pos

    program_pos = array_position(0)
    proof_pos = array_position(32)

    program_count = word(program_pos)
    program_base = program_pos + 32
    if program_count > (size - program_base) // 32:
        raise ABIError("programOutput length exceeds calldata")
    occupy(program_pos, program_base + 32 * program_count)
    program = [word(program_base + 32 * i) for i in range(program_count)]

    proof_count = word(proof_pos)
    table_base = proof_pos + 32
    if proof_count > (size - table_base) // 32:
        raise ABIError("kzgProofs offset table exceeds calldata")
    table_end = table_base + 32 * proof_count
    occupy(proof_pos, table_end)

    proofs = []
    for i in range(proof_count):
        relative = word(table_base + 32 * i)
        if relative % 32 or relative < 32 * proof_count:
            raise ABIError("Invalid bytes[] element offset")
        element = table_base + relative
        length = word(element)
        payload = element + 32
        if length > size - payload:
            raise ABIError("Proof length exceeds calldata")
        padded_end = payload + ((length + 31) // 32) * 32
        occupy(element, padded_end)
        if any(body[payload + length:padded_end]):
            raise ABIError("Nonzero bytes padding")
        proofs.append(body[payload:payload + length])

    return program, proofs


def parse_os_output_header(program_output: Sequence[int]) -> dict:
    """Read exactly the ten common fields, leaving any suffix uninterpreted."""
    if len(program_output) < len(HEADER_FIELDS):
        raise HeaderError("OS header requires ten felts")
    values = program_output[:len(HEADER_FIELDS)]
    for name, value in zip(HEADER_FIELDS, values):
        if type(value) is not int or not 0 <= value < FELT_PRIME:
            raise HeaderError(f"Invalid felt in {name}")
    header = dict(zip(HEADER_FIELDS, values))
    for name in ("use_kzg_da", "full_output"):
        if header[name] not in (0, 1):
            raise HeaderError(f"{name} must be zero or one")
    if header["new_block_number"] >= 1 << 64:
        raise HeaderError("new_block_number does not fit Rust's u64")
    return header


def _candidate(program_output: Sequence[int], offset: int) -> dict:
    header = parse_os_output_header(program_output[offset:offset + 10])
    if header["use_kzg_da"] != 1:
        raise HeaderError("Candidate does not use KZG DA")
    if header["new_block_number"] <= header["prev_block_number"]:
        raise HeaderError("Candidate does not advance the block number")
    return header


def find_os_header(
    program_output: Sequence[int],
    expected_new_block_hash: int | None = None,
) -> tuple[int, dict]:
    if expected_new_block_hash is None:
        header = _candidate(program_output, 0)
        return 0, {**header, "verified": False}

    if (
        type(expected_new_block_hash) is not int
        or not 0 <= expected_new_block_hash < FELT_PRIME
    ):
        raise HeaderError("Expected block hash is not a felt")

    for offset in range(min(65, max(0, len(program_output) - 9))):
        try:
            header = _candidate(program_output, offset)
        except HeaderError:
            continue
        if header["new_block_hash"] == expected_new_block_hash:
            return offset, {**header, "verified": True}
    raise HeaderError("No OS header matches the public block hash")
