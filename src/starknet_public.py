"""Small, synchronous, endpoint-agnostic Starknet JSON-RPC client.

Only successful JSON-RPC results are cached. Cache keys include method and
params; an endpoint-hash subdirectory prevents accidental cross-network
reuse without writing the endpoint URL to disk. Calls are rate-limited
including retries. max_retries means retries AFTER the initial attempt.

No authentication headers or URL userinfo are supported. Endpoint/error
bodies are deliberately excluded from exceptions and reports.

StateDiff has no deprecated-declaration field, so aggregation returns its
dataclass subclass AggregatedStateDiff, preserving the existing contracts
and classes API while keeping deprecated declarations separately.

Missing state-diff categories are treated as empty, accommodating RPC
versions that omit empty categories. Inputs must be supplied in ascending
block order: state-update responses themselves contain no block number.
Cairo-1 declarations are a union of (class_hash, compiled_class_hash)
pairs, not last-write-wins.
"""

from dataclasses import dataclass, field
import hashlib
import json
import math
import os
from pathlib import Path
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from .os_state_diff import ClassDeclaration, ContractDiff, StateDiff
from .stateless import FELT_PRIME


class PublicDataError(RuntimeError):
    pass


class RPCError(PublicDataError):
    def __init__(self, code: int | None):
        self.code = code
        super().__init__(f"JSON-RPC error code {code}")


class PublicFormatError(PublicDataError):
    pass


def felt(value) -> int:
    """Accept JSON-RPC hex felts, or integer felts for in-process callers."""
    if type(value) is int:
        result = value
    elif isinstance(value, str) and value.startswith("0x"):
        try:
            result = int(value, 16)
        except ValueError:
            raise PublicFormatError("Invalid hex felt") from None
    else:
        raise PublicFormatError("Expected a hex felt or integer")
    if not 0 <= result < FELT_PRIME:
        raise PublicFormatError("Felt outside Starknet field")
    return result


def atomic_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False
        ) as stream:
            temporary = Path(stream.name)
            json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


class PublicClient:
    """Single-threaded client; use separate instances for separate workers."""

    def __init__(
        self,
        url: str,
        cache_dir: str | Path,
        *,
        rate: float = 2.0,
        max_retries: int = 5,
        timeout: float = 30.0,
    ):
        try:
            parsed = urlsplit(url)
            valid = (
                parsed.scheme in {"http", "https"}
                and parsed.hostname
                and parsed.username is None
                and parsed.password is None
                and not parsed.fragment
            )
        except ValueError:
            valid = False
        if not valid:
            raise ValueError("Expected a public HTTP(S) URL without userinfo")
        if not math.isfinite(rate) or rate <= 0:
            raise ValueError("rate must be finite and positive")
        if not 0 <= max_retries <= 5:
            raise ValueError("max_retries must be between zero and five")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be finite and positive")
        self._url = url
        namespace = hashlib.sha256(url.encode("utf-8")).hexdigest()
        self.cache = Path(cache_dir) / namespace
        self.interval = 1.0 / rate
        self.max_retries = max_retries
        self.timeout = timeout
        self._next_request = 0.0

    def _throttle(self) -> None:
        delay = self._next_request - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        self._next_request = time.monotonic() + self.interval

    def call(self, method: str, params: dict):
        identity = json.dumps(
            {"method": method, "params": params},
            sort_keys=True, separators=(",", ":"), allow_nan=False,
        )
        key = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        path = self.cache / f"{key}.json"
        if path.exists():
            try:
                with path.open(encoding="utf-8") as stream:
                    cached = json.load(stream)
                return cached["result"]
            except (OSError, ValueError, KeyError, TypeError):
                raise PublicDataError("Invalid public-data cache entry") from None

        payload = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }).encode("utf-8")
        request = Request(
            self._url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "blockx-starknet-da-poc",
            },
            method="POST",
        )

        for attempt in range(self.max_retries + 1):
            self._throttle()
            try:
                with urlopen(request, timeout=self.timeout) as response:
                    raw = response.read()
            except HTTPError as exc:
                status = exc.code
                exc.close()
                if (
                    (status == 429 or 500 <= status <= 599)
                    and attempt < self.max_retries
                ):
                    time.sleep(min(2 ** attempt, 16))
                    continue
                raise PublicDataError(f"HTTP status {status}") from None
            except (URLError, OSError):
                raise PublicDataError("Public RPC transport failure") from None

            try:
                envelope = json.loads(raw)
            except (ValueError, UnicodeError):
                raise PublicDataError("Invalid RPC JSON response") from None
            if (
                not isinstance(envelope, dict)
                or envelope.get("jsonrpc") != "2.0"
                or type(envelope.get("id")) is not int
                or envelope["id"] != 1
            ):
                raise PublicDataError("Invalid JSON-RPC envelope")
            if "error" in envelope:
                error = envelope["error"]
                code = error.get("code") if isinstance(error, dict) else None
                raise RPCError(code if type(code) is int else None)
            if "result" not in envelope:
                raise PublicDataError("RPC response has no result")
            result = envelope["result"]
            atomic_json(path, {"result": result})
            return result

        raise AssertionError("Retry loop exhausted unexpectedly")

    def get_state_update(self, number: int) -> dict:
        result = self.call(
            "starknet_getStateUpdate",
            {"block_id": {"block_number": number}},
        )
        if not isinstance(result, dict) or not isinstance(
            result.get("state_diff"), dict
        ):
            raise PublicFormatError("Invalid state update")
        # Require a finalized, numbered-block response rather than pending data.
        for name in ("block_hash", "old_root", "new_root"):
            if name not in result:
                raise PublicFormatError("Incomplete finalized state update")
            felt(result[name])
        return result

    def get_storage_at(self, key: int, block_number: int) -> int:
        return felt(self.call(
            "starknet_getStorageAt",
            {
                "contract_address": "0x2",
                "key": hex(felt(key)),
                "block_id": {"block_number": block_number},
            },
        ))

    def get_block_hash(self, number: int) -> int:
        result = self.call(
            "starknet_getBlockWithTxHashes",
            {"block_id": {"block_number": number}},
        )
        if (
            not isinstance(result, dict)
            or type(result.get("block_number")) is not int
            or result["block_number"] != number
            or "block_hash" not in result
        ):
            raise PublicFormatError("Invalid numbered block response")
        return felt(result["block_hash"])


@dataclass
class AggregatedStateDiff(StateDiff):
    deprecated_declared_classes: list[int] = field(default_factory=list)


def aggregate_state_updates(updates) -> StateDiff:
    contracts: dict[int, ContractDiff] = {}
    declarations: dict[int, int] = {}  # Opus fix: class_hash -> latest compiled_class_hash
    deprecated: set[int] = set()

    def contract(address) -> ContractDiff:
        address = felt(address)
        if address not in contracts:
            contracts[address] = ContractDiff(address, None, None, {})
        return contracts[address]

    def records(diff: dict, name: str) -> list:
        result = diff.get(name, [])
        if not isinstance(result, list):
            raise PublicFormatError(f"{name} must be a list")
        return result

    try:
        for update in updates:
            diff = update["state_diff"]
            if not isinstance(diff, dict):
                raise PublicFormatError("state_diff must be an object")

            for item in records(diff, "storage_diffs"):
                target = contract(item["address"])
                for entry in records(item, "storage_entries"):
                    target.storage[felt(entry["key"])] = felt(entry["value"])

            for item in records(diff, "nonces"):
                contract(item["contract_address"]).nonce = felt(item["nonce"])

            # Within a block, replacement takes precedence if both are present.
            # Opus fix: RPC uses "address" for deployed_contracts but "contract_address" for replaced_classes.
            for name in ("deployed_contracts", "replaced_classes"):
                for item in records(diff, name):
                    addr = item["contract_address"] if "contract_address" in item else item["address"]
                    contract(addr).class_hash = felt(item["class_hash"])

            # Opus fix: the OS DA class section is a list of compiled-class-hash updates; public RPC splits
            # these into declared_classes and migrated_compiled_classes. Last write per class hash wins.
            for name in ("declared_classes", "migrated_compiled_classes"):
                for item in records(diff, name):
                    declarations[felt(item["class_hash"])] = felt(item["compiled_class_hash"])
            for value in records(diff, "deprecated_declared_classes"):
                deprecated.add(felt(value))
    except (KeyError, TypeError, AttributeError):
        raise PublicFormatError("Malformed state-diff record") from None

    return AggregatedStateDiff(
        contracts=[contracts[address] for address in sorted(contracts)],
        classes=[ClassDeclaration(*pair) for pair in sorted(declarations.items())],
        deprecated_declared_classes=sorted(deprecated),
    )
