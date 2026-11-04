import random
import unittest

from src.aliases import AliasMap, apply, bootstrap_from_pairs
from src.os_state_diff import (
    ClassDeclaration,
    ContractDiff,
    StateDiff,
    StateDiffDecodeError,
    decode_da,
    parse_decompressed,
)
from src.stateless import (
    BUCKET_BITS,
    FELT_PRIME,
    HEADER_ELM_BOUND,
    compress,
    decompress,
    get_n_elms_per_felt,
    pack_in_felts,
    unpack_felts_to,
)


class StatelessTests(unittest.TestCase):
    def test_empty_and_repetitions(self):
        self.assertEqual(compress([]), [0])
        for data in (
            [],
            [0],
            [0] * 600,
            [7] * 600,
            [FELT_PRIME - 1] * 600,
            [1, 2] * 400,
        ):
            with self.subTest(length=len(data)):
                self.assertEqual(decompress(compress(data)), data)

    def test_known_wire_vector(self):
        # Unique bucket 15: [1, 2].
        # Repeated pointer: 0, in base 2.
        # Bucket indices: [5, 5, 6], in base 7.
        header = 3 * 2**20 + 2 * 2**140 + 2**160
        expected = [header, 1 + (2 << 15), 0, 5 + 5 * 7 + 6 * 49]
        self.assertEqual(compress([1, 2, 1]), expected)
        self.assertEqual(decompress(expected), [1, 2, 1])

    def test_all_bucket_sizes_and_boundaries(self):
        values = [0, 1]
        for bits in (15, 31, 62, 83, 125, 251):
            values.extend([(1 << bits) - 1, 1 << bits])
        values.append(FELT_PRIME - 1)

        # Fill every bucket past a packing boundary.
        for bits, lower in (
            (15, 0),
            (31, 1 << 15),
            (62, 1 << 31),
            (83, 1 << 62),
            (125, 1 << 83),
            (252, 1 << 125),
        ):
            count = max(251 // bits, 1) * 3 + 1
            values.extend(lower + i for i in range(count))

        values += list(reversed(values))
        self.assertEqual(decompress(compress(values)), values)
        self.assertEqual(BUCKET_BITS, (252, 125, 83, 62, 31, 15))

    def test_random_round_trips(self):
        rng = random.Random(0xDA)
        bounds = [1 << bits for bits in (15, 31, 62, 83, 125)]
        bounds.append(FELT_PRIME)
        for _ in range(120):
            data = []
            for _ in range(rng.randrange(800)):
                if data and rng.random() < 0.45:
                    data.append(rng.choice(data))
                else:
                    data.append(rng.randrange(rng.choice(bounds)))
            self.assertEqual(decompress(compress(data)), data)

    def test_radix_packing(self):
        self.assertEqual(get_n_elms_per_felt(0), 251)
        self.assertEqual(get_n_elms_per_felt(1), 251)
        self.assertEqual(get_n_elms_per_felt(7), 83)
        self.assertEqual(get_n_elms_per_felt(HEADER_ELM_BOUND), 12)

        digits = [0, 1, 2, 3, 4, 5, 6] * 40
        packed = pack_in_felts(digits, 7)
        self.assertEqual(unpack_felts_to(packed, len(digits), 7), digits)

    def test_iterator_suffix(self):
        stream = iter(compress([10, 20, 10]) + [999, 1000])
        self.assertEqual(decompress(stream), [10, 20, 10])
        self.assertEqual(list(stream), [999, 1000])

    def test_invalid_compression_inputs(self):
        for value in (-1, FELT_PRIME, True):
            with self.assertRaises(ValueError):
                compress([value])
        with self.assertRaises(ValueError):
            decompress([1])  # Unsupported compression version.


class StateDiffTests(unittest.TestCase):
    @staticmethod
    def example():
        large_storage = {1000 + i: 9000 + i for i in range(300)}

        # First contract: changed nonce 7, 300 updates, large-count flag,
        # class replacement. header = ((nonce * 2**64 + count) * 2) * 2 + 1.
        first_header = ((7 * (1 << 64) + 300) * 2 + 0) * 2 + 1

        # Second contract: unchanged nonce, two updates, small-count flag,
        # no class replacement.
        second_header = ((0 * 256 + 2) * 2 + 1) * 2 + 0

        raw = [2, 0x1234, first_header, 0xCAFE]
        for key, value in large_storage.items():
            raw.extend([key, value])
        raw.extend([
            0x5678, second_header,
            0, 11,
            127, 22,
            2,
            0xAAA, 0xBBB,
            0xCCC, 0xDDD,
        ])

        expected = StateDiff(
            [
                ContractDiff(0x1234, 7, 0xCAFE, large_storage),
                ContractDiff(0x5678, None, None, {0: 11, 127: 22}),
            ],
            [
                ClassDeclaration(0xAAA, 0xBBB),
                ClassDeclaration(0xCCC, 0xDDD),
            ],
        )
        return raw, expected

    def test_hand_built_partial_diff(self):
        raw, expected = self.example()
        self.assertEqual(parse_decompressed(raw, strict=True), expected)
        self.assertEqual(decode_da(compress(raw), strict=True), expected)

    def test_reference_compressed_prefix_raw_suffix(self):
        raw, expected = self.example()
        split = 27  # Deliberately split inside storage updates.
        wire = compress(raw[:split]) + raw[split:]
        self.assertEqual(decode_da(wire, strict=True), expected)

    def test_blob_padding_and_exhaustion(self):
        raw, expected = self.example()
        padded = compress(raw) + [0] * 100
        self.assertEqual(decode_da(padded), expected)
        with self.assertRaises(StateDiffDecodeError):
            decode_da(padded, strict=True)

    def test_update_count_boundary(self):
        for count in (0, 255, 256, 257):
            small = int(count < 256)
            bound = 256 if small else 1 << 64
            header = ((3 * bound + count) * 2 + small) * 2
            raw = [1, 17, header]
            for key in range(count):
                raw.extend([key, key + 10])
            raw.append(0)
            parsed = parse_decompressed(raw, strict=True)
            self.assertEqual(parsed.contracts[0].nonce, 3)
            self.assertEqual(len(parsed.contracts[0].storage), count)

    def test_zero_class_hash_is_present(self):
        # No updates, small-count flag, class flag; explicit class hash 0.
        parsed = parse_decompressed([1, 17, 3, 0, 0], strict=True)
        self.assertEqual(parsed.contracts[0].class_hash, 0)
        self.assertIsNone(parsed.contracts[0].nonce)

    def test_missing_field(self):
        with self.assertRaises(StateDiffDecodeError):
            parse_decompressed([1, 17])


class AliasTests(unittest.TestCase):
    def test_learning_and_applying(self):
        real_address = (1 << 200) + 10
        real_key = (1 << 190) + 20
        assignments = {0: 130, real_address: 128, real_key: 129}

        # Assignment record intentionally follows its consumers.
        aliased = StateDiff(
            [
                ContractDiff(128, 5, 129, {129: 128, 127: 129}),
                ContractDiff(2, None, None, assignments),
                ContractDiff(1, None, None, {129: 8}),
                ContractDiff(15, None, None, {129: 9}),
            ],
            [ClassDeclaration(128, 129)],
        )
        aliases = AliasMap()
        resolved = apply(aliased, aliases)

        self.assertEqual(
            resolved.contracts[0],
            ContractDiff(real_address, 5, 129, {real_key: 128, 127: 129}),
        )
        self.assertEqual(resolved.contracts[1].storage, assignments)
        self.assertEqual(resolved.contracts[2].storage, {129: 8})
        self.assertEqual(resolved.contracts[3].storage, {129: 9})
        self.assertEqual(resolved.classes, aliased.classes)
        self.assertEqual(aliases.next_free_alias, 130)
        self.assertEqual(aliases.resolve_address(128), real_address)
        self.assertEqual(aliases.resolve_key(129), real_key)

        # Input was not mutated.
        self.assertEqual(aliased.contracts[0].address, 128)
        self.assertEqual(aliased.contracts[0].storage, {129: 128, 127: 129})

        # Mapping survives into a later update with no 0x2 changes.
        later = StateDiff([ContractDiff(128, None, None, {129: 99})], [])
        self.assertEqual(
            apply(later, aliases).contracts[0].storage, {real_key: 99}
        )

    def test_numeric_threshold_not_bit_length(self):
        aliases = bootstrap_from_pairs([(1000, 128), (2000, 129)])
        self.assertEqual(aliases.resolve_address(127), 127)
        self.assertEqual(aliases.resolve_key(127), 127)
        self.assertEqual(aliases.resolve_address(128), 1000)
        self.assertEqual(aliases.resolve_key(129), 2000)

        # Address 16 is literal but its keys are eligible for compression.
        diff = StateDiff([ContractDiff(16, None, None, {129: 1})], [])
        self.assertEqual(apply(diff, aliases).contracts[0].storage, {2000: 1})

        # A small bit-length does not make alias 130 a literal value.
        with self.assertRaises(KeyError):
            aliases.resolve_key(130)

    def test_bootstrap_conflicts_and_identity_assignment(self):
        aliases = AliasMap().bootstrap_from_pairs([(128, 128), (1000, 129)])
        self.assertEqual(aliases.resolve_key(128), 128)
        aliases.bootstrap_from_pairs([(1000, 129)])  # Idempotent.
        with self.assertRaises(ValueError):
            aliases.bootstrap_from_pairs([(2000, 129)])
        with self.assertRaises(ValueError):
            aliases.bootstrap_from_pairs([(1000, 130)])
        with self.assertRaises(ValueError):
            aliases.bootstrap_from_pairs([(127, 130)])

    def test_counter_is_not_an_assignment(self):
        aliases = AliasMap()
        aliases.update_from_diff(
            StateDiff([ContractDiff(2, None, None, {0: 128})], [])
        )
        self.assertEqual(aliases.next_free_alias, 128)
        with self.assertRaises(KeyError):
            aliases.resolve_key(128)


if __name__ == "__main__":
    unittest.main()
