"""Offline T6 tests. Run with: python -m pytest -q tests/test_t6.py"""

import io
import json
from urllib.error import HTTPError

import pytest

from src.cli import verified_header
from src.crosscheck import crosscheck, markdown_summary
from src.l1_update import (
    ABIError,
    SELECTOR,
    HeaderError,
    SelectorError,
    decode_calldata,
    find_os_header,
    parse_os_output_header,
)
from src.os_state_diff import ClassDeclaration, ContractDiff, StateDiff
from src.starknet_public import (
    PublicClient,
    RPCError,
    aggregate_state_updates,
)


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("Network access is forbidden in offline tests")
    monkeypatch.setattr("urllib.request.urlopen", blocked)
    monkeypatch.setattr("src.starknet_public.urlopen", blocked)


def word(value):
    return value.to_bytes(32, "big")


def encode_calldata(program, proofs):
    program_tail = word(len(program)) + b"".join(map(word, program))
    offset = 32 * len(proofs)
    offsets = []
    payloads = []
    for proof in proofs:
        offsets.append(word(offset))
        payload = word(len(proof)) + proof + b"\0" * (-len(proof) % 32)
        payloads.append(payload)
        offset += len(payload)
    proof_tail = word(len(proofs)) + b"".join(offsets + payloads)
    return (
        SELECTOR
        + word(64)
        + word(64 + len(program_tail))
        + program_tail
        + proof_tail
    )


def replace_word(calldata, body_offset, value):
    start = 4 + body_offset
    return calldata[:start] + word(value) + calldata[start + 32:]


def header():
    return [11, 12, 20, 23, 100, 101, 200, 201, 1, 0]


@pytest.mark.parametrize(
    "program,proofs",
    [
        ([], []),
        ([0, 1, 2**256 - 1], [b"", b"a", bytes(range(32)), b"x" * 33]),
        (header(), [b"proof"]),
    ],
)
def test_abi_round_trip(program, proofs):
    assert decode_calldata(encode_calldata(program, proofs)) == (program, proofs)


def test_abi_malformed():
    calldata = encode_calldata(header(), [b"abc"])
    proof_pos = int.from_bytes(calldata[36:68], "big")
    invalid = [
        replace_word(calldata, 0, 65),                  # unaligned
        replace_word(calldata, 0, 0),                   # points into head
        replace_word(calldata, 0, 2**255),               # out of bounds
        replace_word(calldata, 64, 2**255),              # huge uint[] length
        replace_word(calldata, 32, 64),                 # overlapping arrays
        replace_word(calldata, proof_pos, 2**255),      # huge offset table
        replace_word(calldata, proof_pos + 32, 0),      # points into table
        replace_word(calldata, proof_pos + 32, 2**255), # bad nested offset
        calldata[:-1],                                 # truncated padding
        calldata[:-1] + b"\x01",                        # nonzero padding
    ]
    for value in invalid:
        with pytest.raises(ABIError):
            decode_calldata(value)
    with pytest.raises(SelectorError):
        decode_calldata(b"\0" * 4 + calldata[4:])


def test_headers():
    values = header()
    parsed = parse_os_output_header(values + [999])
    assert len(parsed) == 10
    assert parsed["initial_root"] == 11
    assert parsed["new_block_number"] == 23
    assert parsed["new_block_hash"] == 101

    offset, unverified = find_os_header(values)
    assert offset == 0
    assert unverified["verified"] is False

    offset, verified = find_os_header(values, 101)
    assert offset == 0
    assert verified["verified"] is True

    prefixed = [999] * 7 + values
    offset, verified = find_os_header(prefixed, 101)
    assert offset == 7
    assert verified["new_block_number"] == 23
    with pytest.raises(HeaderError):
        find_os_header(prefixed)
    with pytest.raises(HeaderError):
        find_os_header(prefixed, 9999)
    with pytest.raises(HeaderError):
        find_os_header([999] * 65 + values, 101)
    assert find_os_header([999] * 64 + values, 101)[0] == 64

    bad = values.copy()
    bad[9] = 2
    with pytest.raises(HeaderError):
        parse_os_output_header(bad)
    with pytest.raises(HeaderError):
        parse_os_output_header(values[:9])


class FakeRPC:
    def __init__(self, aliases=None, hashes=None, updates=None):
        self.aliases = aliases or {}
        self.hashes = hashes or {}
        self.updates = updates or {}
        self.storage_calls = []
        self.block_calls = []

    def get_storage_at(self, key, block_number):
        self.storage_calls.append((key, block_number))
        return self.aliases.get(key, 0)

    def get_block_hash(self, number):
        self.block_calls.append(number)
        if number not in self.hashes:
            raise RPCError(24)
        return self.hashes[number]

    def get_state_update(self, number):
        return self.updates[number]


def test_public_verified_header_with_prefix():
    client = FakeRPC(hashes={23: 101})
    offset, parsed, diagnostics = verified_header([999] * 5 + header(), client)
    assert offset == 5
    assert parsed["verified"]
    assert client.block_calls == [23]
    assert diagnostics["structurally_rejected"] == 5


def test_aggregation_last_write_wins():
    updates = [
        {"state_diff": {
            "storage_diffs": [{
                "address": "0x100",
                "storage_entries": [
                    {"key": "0x200", "value": "0x1"},
                    {"key": "0x201", "value": "0x2"},
                ],
            }],
            "nonces": [{"contract_address": "0x100", "nonce": "0x1"}],
            "deployed_contracts": [{"address": "0x100", "class_hash": "0xa"}],
            "declared_classes": [
                {"class_hash": "0xabc", "compiled_class_hash": "0xdef"},
            ],
            "deprecated_declared_classes": ["0x123"],
        }},
        {"state_diff": {
            "storage_diffs": [{
                "address": "0x100",
                "storage_entries": [{"key": "0x200", "value": "0x9"}],
            }],
            "nonces": [{"contract_address": "0x100", "nonce": "0x0"}],
            "replaced_classes": [{"address": "0x100", "class_hash": "0xb"}],
            "declared_classes": [
                {"class_hash": "0xabc", "compiled_class_hash": "0xdef"},
                {"class_hash": "0x111", "compiled_class_hash": "0x222"},
            ],
            "deprecated_declared_classes": ["0x123", "0x124"],
        }},
    ]
    result = aggregate_state_updates(updates)
    assert isinstance(result, StateDiff)
    assert result.contracts == [
        ContractDiff(0x100, 0, 0xB, {0x200: 9, 0x201: 2})
    ]
    assert result.classes == [
        ClassDeclaration(0x111, 0x222),
        ClassDeclaration(0xABC, 0xDEF),
    ]
    assert result.deprecated_declared_classes == [0x123, 0x124]


def synthetic_pair():
    assignments = {0: 0x82, 0x1000: 0x80}
    ours = StateDiff(
        [
            ContractDiff(2, None, None, dict(assignments)),
            ContractDiff(0x80, 3, 0x555, {0x81: 7, 1: 8}),
            # System-contract keys stay literal even when >= 0x80.
            ContractDiff(1, None, None, {0x3000: 9}),
        ],
        [ClassDeclaration(0xAAA, 0xBBB)],
    )
    public = StateDiff(
        [
            ContractDiff(2, None, None, dict(assignments)),
            ContractDiff(0x1000, 3, 0x555, {0x2000: 7, 1: 8}),
            ContractDiff(1, None, None, {0x3000: 9}),
        ],
        [ClassDeclaration(0xAAA, 0xBBB)],
    )
    return ours, public


def test_crosscheck_and_injected_mismatch():
    ours, public = synthetic_pair()
    client = FakeRPC(aliases={0x2000: 0x81})
    report = crosscheck(ours, public, client, 23)
    assert report["ok"]
    assert report["mismatch_count"] == 0
    assert report["skipped_count"] == 0
    assert report["alias_contract_storage"]["equal"]
    assert report["declared_classes"]["equal"]
    assert report["sampled"]["nonce"]["matches"] == 1
    assert report["sampled"]["class_hash"]["matches"] == 1
    assert client.storage_calls == [(0x2000, 23)]
    assert "PASS (sampled)" in markdown_summary(report)
    json.dumps(report, allow_nan=False)

    ours.contracts[1].storage[0x81] = 999
    report = crosscheck(ours, public, FakeRPC({0x2000: 0x81}), 23)
    assert not report["ok"]
    assert report["mismatch_count"] == 1
    assert report["mismatches"][0]["field"] == "storage"
    assert report["mismatches"][0]["public"] == "0x7"


def test_missing_alias_is_counted_and_fails():
    ours, public = synthetic_pair()
    report = crosscheck(ours, public, FakeRPC(), 23)
    assert not report["ok"]
    assert report["alias_resolution"]["field_errors"] == 1
    assert report["sampled"]["storage"]["skipped"] == {
        "invalid_alias_assignment": 1
    }
    assert report["skipped_count"] == 1


def test_exact_categories_and_nonce_class_mismatches():
    ours, public = synthetic_pair()
    ours.contracts[0].storage[0] += 1
    ours.classes.clear()
    ours.contracts[1].nonce = 4
    ours.contracts[1].class_hash = 0x556
    report = crosscheck(
        ours, public, FakeRPC({0x2000: 0x81}), 23, sample=0
    )
    assert not report["ok"]
    assert report["alias_contract_storage"]["mismatches"] == 1
    assert report["declared_classes"]["mismatches"] == 1
    assert report["sampled"]["nonce"]["mismatches"] == 1
    assert report["sampled"]["class_hash"]["mismatches"] == 1
    assert report["mismatch_count"] == 4
    assert report["sampled"]["storage"]["skipped"]["sampling_limit"] == 5


def test_sampling_is_deterministic_and_accounted():
    ours = StateDiff([ContractDiff(1, None, None, dict.fromkeys(range(250), 7))], [])
    public = StateDiff([ContractDiff(1, None, None, dict.fromkeys(range(250), 8))], [])
    first = crosscheck(ours, public, FakeRPC(), 23, sample=17, seed=42)
    second = crosscheck(ours, public, FakeRPC(), 23, sample=17, seed=42)
    assert first == second
    stats = first["sampled"]["storage"]
    assert stats["population"] == 250
    assert stats["selected"] == 17
    assert stats["mismatches"] == 17
    assert stats["skipped"] == {"sampling_limit": 233}


def test_nonce_class_contract_cap():
    contracts = [
        ContractDiff(address, 1, 2, {})
        for address in range(0x1000, 0x1000 + 205)
    ]
    public = StateDiff(contracts, [])
    aliases = {c.address: 0x80 + index for index, c in enumerate(contracts)}
    ours = StateDiff([
        ContractDiff(aliases[c.address], c.nonce, c.class_hash, {})
        for c in contracts
    ], [])
    report = crosscheck(ours, public, FakeRPC(aliases), 23, sample=0)
    assert report["ok"]
    for field in ("nonce", "class_hash"):
        assert report["sampled"][field]["matches"] == 200
        assert report["sampled"][field]["skipped"] == {"sampling_limit": 5}


def test_rpc_cache_params_and_headers(tmp_path, monkeypatch):
    calls = []

    def fake_urlopen(request, timeout):
        payload = json.loads(request.data)
        calls.append(payload)
        assert timeout == 30
        assert request.get_header("User-agent") == "blockx-starknet-da-poc"
        assert payload["method"] == "starknet_getStorageAt"
        assert payload["params"] == {
            "contract_address": "0x2",
            "key": "0x1000",
            "block_id": {"block_number": 23},
        }
        return io.BytesIO(json.dumps({
            "jsonrpc": "2.0", "id": 1, "result": "0x80"
        }).encode())

    monkeypatch.setattr("src.starknet_public.urlopen", fake_urlopen)
    client = PublicClient("https://rpc.example.invalid", tmp_path)
    assert client.get_storage_at(0x1000, 23) == 0x80
    assert client.get_storage_at(0x1000, 23) == 0x80
    another = PublicClient("https://rpc.example.invalid", tmp_path)
    assert another.get_storage_at(0x1000, 23) == 0x80
    assert len(calls) == 1


def test_rpc_retry_and_rate_limit(tmp_path, monkeypatch):
    clock = [100.0]
    sleeps = []
    attempts = []

    def sleep(seconds):
        assert seconds >= 0
        sleeps.append(seconds)
        clock[0] += seconds

    def fake_urlopen(request, timeout):
        attempts.append(clock[0])
        if len(attempts) == 1:
            raise HTTPError(
                "https://rpc.example.invalid", 429, "limited", {}, None
            )
        if len(attempts) == 2:
            raise HTTPError(
                "https://rpc.example.invalid", 503, "unavailable", {}, None
            )
        return io.BytesIO(b'{"jsonrpc":"2.0","id":1,"result":"0x80"}')

    monkeypatch.setattr("src.starknet_public.time.monotonic", lambda: clock[0])
    monkeypatch.setattr("src.starknet_public.time.sleep", sleep)
    monkeypatch.setattr("src.starknet_public.urlopen", fake_urlopen)
    client = PublicClient("https://rpc.example.invalid", tmp_path, rate=2)
    assert client.get_storage_at(0x1000, 23) == 0x80
    assert client.get_storage_at(0x1001, 23) == 0x80
    assert len(attempts) == 4
    assert all(b - a >= 0.5 for a, b in zip(attempts, attempts[1:]))
    assert 1 in sleeps
    assert 2 in sleeps


def test_rpc_errors_not_cached_or_exposed(tmp_path, monkeypatch):
    attempts = []

    def fake_urlopen(request, timeout):
        attempts.append(1)
        return io.BytesIO(
            b'{"jsonrpc":"2.0","id":1,'
            b'"error":{"code":24,"message":"DO_NOT_EXPOSE"}}'
        )

    monkeypatch.setattr("src.starknet_public.urlopen", fake_urlopen)
    monkeypatch.setattr("src.starknet_public.time.sleep", lambda seconds: None)
    client = PublicClient("https://rpc.example.invalid", tmp_path)
    for _ in range(2):
        with pytest.raises(RPCError) as caught:
            client.get_block_hash(23)
        assert caught.value.code == 24
        assert "DO_NOT_EXPOSE" not in str(caught.value)
    assert len(attempts) == 2
    assert not list(tmp_path.rglob("*.json"))


def test_rpc_retry_limit(tmp_path, monkeypatch):
    attempts = []

    def fake_urlopen(request, timeout):
        attempts.append(1)
        raise HTTPError(
            "https://rpc.example.invalid", 503, "unavailable", {}, None
        )

    monkeypatch.setattr("src.starknet_public.urlopen", fake_urlopen)
    monkeypatch.setattr("src.starknet_public.time.sleep", lambda seconds: None)
    client = PublicClient("https://rpc.example.invalid", tmp_path)
    from src.starknet_public import PublicDataError
    with pytest.raises(PublicDataError, match="HTTP status 503"):
        client.get_storage_at(0x1000, 23)
    assert len(attempts) == 6  # Initial attempt plus five retries.
