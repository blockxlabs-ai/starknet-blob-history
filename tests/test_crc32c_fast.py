"""N6a (Opus): the fast CRC-32C path must equal the pure-Python reference."""
import os

from src import ere_reader as e


def test_known_vector():
    assert e._crc32c_py(b"123456789") == 0xE3069283
    assert e._crc32c(b"123456789") == 0xE3069283


def test_random_buffers_match_reference():
    for n in (0, 1, 7, 64, 4096, 65536 + 3):
        data = os.urandom(n)
        assert e._crc32c(data) == e._crc32c_py(data)


def test_memoryview_input():
    data = os.urandom(1000)
    assert e._crc32c(memoryview(data)) == e._crc32c_py(data)
