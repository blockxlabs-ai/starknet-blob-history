"""Invert the alias contract's original -> alias storage mapping.

Source citations refer to exact lines/statements in the supplied
stateful_compression.rs, identified by function because the excerpt has
no line numbers:

* AliasUpdater::set_alias_in_storage:
      self.state.set_storage_at(self.alias_contract_address, alias_key, alias)
* AliasUpdater::insert_alias:
      self.set_alias_in_storage(*alias_key, alias_to_allocate)?;
* AliasCompressor::get_alias:
      let alias = self.state.get_storage_at(self.alias_contract_address, alias_key)?;

Thus contract 0x2 stores original addresses/keys AS STORAGE KEYS and their
allocated aliases AS STORAGE VALUES. Decoding builds alias -> original.
Key zero instead stores the NEXT free alias, not an assignment.

The reference constants/conditions are numeric, not bit-length bounds:
    MIN_VALUE_FOR_ALIAS_ALLOC = 0x80
    INITIAL_AVAILABLE_ALIAS = 0x80
    should_compress_address: address >= MIN_VALUE_FOR_ALIAS_ALLOC
    should_compress_storage_key:
        key >= MIN_VALUE_FOR_ALIAS_ALLOC
        && address > MAX_NON_COMPRESSED_CONTRACT_ADDRESS
    MAX_NON_COMPRESSED_CONTRACT_ADDRESS = 0xf

Accordingly addresses and ordinary storage keys below 128 are identities.
ALL storage keys of contracts 0x0 through 0xf remain literal, including
the original keys in contract 0x2. resolve_key(x) assumes ordinary-contract
context; apply() supplies the system-contract exception.

The supplied Rust accepts the alias-contract address as a parameter; this
module uses 0x2 as specified by the task. No aliases.cairo excerpt was
supplied, so no additional Cairo/version-specific rules are inferred.

Alias allocation begins at 128 and is persistent across updates. This
decoder learns assignments; it does not allocate aliases or infer missing
history. Missing aliases raise KeyError. Conflicting bootstrap/diff pairs
raise ValueError rather than silently corrupting the inverse map.
"""

from collections.abc import Iterable

from .os_state_diff import ClassDeclaration, ContractDiff, StateDiff


ALIAS_CONTRACT_ADDRESS = 0x2
ALIAS_COUNTER_STORAGE_KEY = 0
INITIAL_AVAILABLE_ALIAS = 0x80
MIN_VALUE_FOR_ALIAS_ALLOC = 0x80
MAX_NON_COMPRESSED_CONTRACT_ADDRESS = 0xF
PATRICIA_KEY_BOUND = 1 << 251


class AliasMap:
    def __init__(self) -> None:
        self._alias_to_original: dict[int, int] = {}
        self._original_to_alias: dict[int, int] = {}
        # None means the counter has not been observed. Bootstrapping
        # assignment pairs alone cannot establish the current counter.
        self.next_free_alias: int | None = None

    def bootstrap_from_pairs(
        self, pairs: Iterable[tuple[int, int]]
    ) -> "AliasMap":
        """Seed from (original, alias) pairs; repeated identical pairs are OK.

        Validation and installation are atomic for this batch.
        """
        forward = self._original_to_alias.copy()
        inverse = self._alias_to_original.copy()

        for original, alias in pairs:
            if (
                type(original) is not int
                or type(alias) is not int
                or not MIN_VALUE_FOR_ALIAS_ALLOC <= original < PATRICIA_KEY_BOUND
                or not INITIAL_AVAILABLE_ALIAS <= alias < PATRICIA_KEY_BOUND
            ):
                raise ValueError(f"Invalid alias assignment: {(original, alias)!r}")

            if original in forward and forward[original] != alias:
                raise ValueError(f"Original {original:#x} already has another alias")
            if alias in inverse and inverse[alias] != original:
                raise ValueError(f"Alias {alias:#x} already names another original")

            forward[original] = alias
            inverse[alias] = original

        self._original_to_alias = forward
        self._alias_to_original = inverse
        return self

    def _resolve(self, value: int) -> int:
        if type(value) is not int or not 0 <= value < PATRICIA_KEY_BOUND:
            raise ValueError(f"Invalid address/key: {value!r}")
        if value < MIN_VALUE_FOR_ALIAS_ALLOC:
            return value
        try:
            return self._alias_to_original[value]
        except KeyError:
            raise KeyError(
                f"Missing alias {value:#x}; bootstrap or replay earlier updates"
            ) from None

    def resolve_address(self, x: int) -> int:
        return self._resolve(x)

    def resolve_key(self, x: int) -> int:
        """Resolve a key of a contract above 0xf; see apply() for exceptions."""
        return self._resolve(x)

    def update_from_diff(self, diff: StateDiff) -> None:
        """Learn from a still-aliased diff before resolving any contracts.

        Contract 0x2 and its keys are never compressed, so its entries can
        be read directly even when its contract record occurs last.
        """
        pairs = []
        counter = self.next_free_alias

        for contract in diff.contracts:
            if contract.address != ALIAS_CONTRACT_ADDRESS:
                continue
            for original, alias in contract.storage.items():
                if original == ALIAS_COUNTER_STORAGE_KEY:
                    # AliasUpdater::new treats a zero stored counter as
                    # uninitialized. finalize_updates normally writes >=128.
                    if alias == 0:
                        counter = None
                    elif (
                        type(alias) is int
                        and INITIAL_AVAILABLE_ALIAS <= alias < PATRICIA_KEY_BOUND
                    ):
                        counter = alias
                    else:
                        raise ValueError(f"Invalid alias counter: {alias!r}")
                else:
                    pairs.append((original, alias))

        self.bootstrap_from_pairs(pairs)
        self.next_free_alias = counter


def bootstrap_from_pairs(pairs: Iterable[tuple[int, int]]) -> AliasMap:
    """Construct an AliasMap from externally obtained (original, alias) pairs."""
    return AliasMap().bootstrap_from_pairs(pairs)


def apply(diff: StateDiff, alias_map: AliasMap) -> StateDiff:
    """Learn this update's assignments, then return a newly resolved diff.

    Mutates alias_map, not diff. Storage values, nonces, class hashes, and
    declaration hashes are never alias-resolved. The 0x2 record is retained.
    """
    alias_map.update_from_diff(diff)

    contracts = []
    for contract in diff.contracts:
        address = alias_map.resolve_address(contract.address)
        if address <= MAX_NON_COMPRESSED_CONTRACT_ADDRESS:
            storage = dict(contract.storage)
        else:
            storage = {
                alias_map.resolve_key(key): value
                for key, value in contract.storage.items()
            }

        contracts.append(
            ContractDiff(address, contract.nonce, contract.class_hash, storage)
        )

    classes = [
        ClassDeclaration(item.class_hash, item.compiled_class_hash)
        for item in diff.classes
    ]
    return StateDiff(contracts, classes)
