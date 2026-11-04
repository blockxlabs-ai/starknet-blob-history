"""Compare an aliased decoded diff with an unaliased public aggregate.

Sampling is reproducible: sort inputs, then use independent seeded PRNGs.
Storage sampling is capped at 200 entries; nonce/class sampling is capped
at 200 contracts, checking both fields when present.

"This update's 0x2 entries" means the decoded diff's entries. They are
independently compared exactly against the public aggregate. Missing
assignments are fetched at the range's final block. Zero storage results
are NOT treated as identity aliases.

Totals are informational, not equality assertions: aggregated public
writes may include no-ops or changes reverted within the range. These
possibilities cannot be established from final diffs alone. No differing
count is silently explained away as a proven no-op.

Unselected fields and deprecated declarations are counted as skipped.
A selected field that cannot be alias-resolved is both a counted skip and
a resolution error; it prevents a successful report. Mismatch counts are
counts of failed assertions, not necessarily distinct underlying defects.
Exact 0x2 checks and sampled storage checks may cover the same entry.
"""

from collections import Counter
import random

from .aliases import (
    AliasMap,
    MAX_NON_COMPRESSED_CONTRACT_ADDRESS,
    MIN_VALUE_FOR_ALIAS_ALLOC,
    PATRICIA_KEY_BOUND,
)
from .os_state_diff import StateDiff
from .starknet_public import PublicDataError, felt


def _index(diff: StateDiff) -> dict:
    result = {}
    for contract in diff.contracts:
        if contract.address in result:
            raise ValueError("Duplicate contract records in StateDiff")
        result[contract.address] = contract
    return result


def _sample(items: list, limit: int, seed: int) -> list:
    if len(items) <= limit:
        return list(items)
    positions = sorted(random.Random(seed).sample(range(len(items)), limit))
    return [items[position] for position in positions]


def crosscheck(
    ours: StateDiff,
    public: StateDiff,
    client,
    new_block_number: int,
    *,
    sample: int = 200,
    seed: int = 0,
) -> dict:
    if type(sample) is not int or not 0 <= sample <= 200:
        raise ValueError("sample must be between zero and 200")

    ours_by_address = _index(ours)
    public_by_address = _index(public)
    ours_alias = ours_by_address.get(2)
    public_alias = public_by_address.get(2)
    assignments = ours_alias.storage if ours_alias else {}
    expected_assignments = public_alias.storage if public_alias else {}

    mismatches = []
    mismatch_count = 0

    def mismatch(field, **details):
        nonlocal mismatch_count
        mismatch_count += 1
        if len(mismatches) < 20:
            mismatches.append({"field": field, **details})

    def shown(value):
        return None if value is None else hex(value)

    alias_matches = alias_mismatches = 0
    for key in sorted(assignments.keys() | expected_assignments.keys()):
        actual = assignments.get(key)
        expected = expected_assignments.get(key)
        if actual == expected:
            alias_matches += 1
        else:
            alias_mismatches += 1
            mismatch(
                "alias_contract_storage",
                address="0x2", key=hex(key),
                ours=shown(actual), public=shown(expected),
            )

    ours_classes = {
        (item.class_hash, item.compiled_class_hash) for item in ours.classes
    }
    public_classes = {
        (item.class_hash, item.compiled_class_hash) for item in public.classes
    }
    for pair in sorted(ours_classes ^ public_classes):
        mismatch(
            "declared_class",
            class_hash=hex(pair[0]), compiled_class_hash=hex(pair[1]),
            ours=pair in ours_classes, public=pair in public_classes,
        )

    stats = {
        name: {
            "population": 0,
            "selected": 0,
            "matches": 0,
            "mismatches": 0,
            "skipped": {},
        }
        for name in ("storage", "nonce", "class_hash")
    }
    skips = {name: Counter() for name in stats}
    resolution_errors = 0
    error_examples = []
    resolved: dict[int, int] = {}
    failed: dict[int, str] = {}
    validation_map = AliasMap()
    alias_sources = Counter()

    class ResolutionFailure(Exception):
        pass

    def alias(original: int) -> int:
        if original < MIN_VALUE_FOR_ALIAS_ALLOC:
            return original
        if original in failed:
            raise ResolutionFailure(failed[original])
        if original in resolved:
            return resolved[original]
        try:
            if not 0 <= original < PATRICIA_KEY_BOUND:
                raise ValueError("Invalid original address/key")
            if original in assignments:
                value = assignments[original]
                source = "this_update"
            else:
                value = felt(client.get_storage_at(original, new_block_number))
                source = "public_storage"
            validation_map.bootstrap_from_pairs([(original, value)])
        except (PublicDataError, ValueError, KeyError) as exc:
            reason = (
                "public_lookup_failed"
                if isinstance(exc, PublicDataError)
                else "invalid_alias_assignment"
            )
            failed[original] = reason
            raise ResolutionFailure(reason) from None
        resolved[original] = value
        alias_sources[source] += 1
        return value

    def check(field: str, address: int, expected: int, key=None) -> None:
        nonlocal resolution_errors
        try:
            mapped_address = alias(address)
            mapped_key = key
            if key is not None and address > MAX_NON_COMPRESSED_CONTRACT_ADDRESS:
                mapped_key = alias(key)
        except ResolutionFailure as exc:
            reason = str(exc)
            skips[field][reason] += 1
            resolution_errors += 1
            if len(error_examples) < 20:
                error_examples.append({
                    "field": field,
                    "address": hex(address),
                    "key": shown(key),
                    "reason": reason,
                })
            return

        target = ours_by_address.get(mapped_address)
        if target is None:
            actual = None
        elif field == "storage":
            actual = target.storage.get(mapped_key)
        else:
            actual = getattr(target, field)

        if actual == expected:
            stats[field]["matches"] += 1
        else:
            stats[field]["mismatches"] += 1
            mismatch(
                field,
                address=hex(address),
                aliased_address=hex(mapped_address),
                key=shown(key),
                aliased_key=shown(mapped_key),
                ours=shown(actual),
                public=hex(expected),
            )

    storage_entries = sorted(
        (contract.address, key, value)
        for contract in public.contracts
        for key, value in contract.storage.items()
    )
    selected_storage = _sample(storage_entries, sample, seed)
    stats["storage"]["population"] = len(storage_entries)
    stats["storage"]["selected"] = len(selected_storage)
    skips["storage"]["sampling_limit"] = len(storage_entries) - len(selected_storage)
    for address, key, value in selected_storage:
        check("storage", address, value, key)

    changed_addresses = sorted(
        contract.address
        for contract in public.contracts
        if contract.nonce is not None or contract.class_hash is not None
    )
    selected_addresses = set(_sample(changed_addresses, 200, seed ^ 0xC1A55))
    for address in changed_addresses:
        contract = public_by_address[address]
        for field in ("nonce", "class_hash"):
            value = getattr(contract, field)
            if value is None:
                continue
            stats[field]["population"] += 1
            if address not in selected_addresses:
                skips[field]["sampling_limit"] += 1
                continue
            stats[field]["selected"] += 1
            check(field, address, value)

    for name in stats:
        stats[name]["skipped"] = {
            reason: count for reason, count in sorted(skips[name].items()) if count
        }

    ours_totals = {
        "contracts": len(ours.contracts),
        "storage_updates": sum(len(c.storage) for c in ours.contracts),
    }
    public_totals = {
        "contracts": len(public.contracts),
        "storage_updates": sum(len(c.storage) for c in public.contracts),
    }
    totals_equal = ours_totals == public_totals
    deprecated = sorted(set(getattr(public, "deprecated_declared_classes", [])))
    skipped_count = (
        sum(sum(reasons.values()) for reasons in skips.values()) + len(deprecated)
    )

    return {
        "ok": mismatch_count == 0 and resolution_errors == 0,
        "new_block_number": new_block_number,
        "sample": sample,
        "seed": seed,
        "alias_contract_storage": {
            "equal": assignments == expected_assignments,
            "ours_entries": len(assignments),
            "public_entries": len(expected_assignments),
            "matches": alias_matches,
            "mismatches": alias_mismatches,
        },
        "declared_classes": {
            "equal": ours_classes == public_classes,
            "ours": len(ours_classes),
            "public": len(public_classes),
            "matches": len(ours_classes & public_classes),
            "mismatches": len(ours_classes ^ public_classes),
        },
        "deprecated_declared_classes": {
            "values": [hex(value) for value in deprecated],
            "skipped": len(deprecated),
            "reason": "Cairo-0 declarations are reported but not compared",
        },
        "totals": {
            "ours": ours_totals,
            "public": public_totals,
            "equal": totals_equal,
            "difference_ours_minus_public": {
                name: ours_totals[name] - public_totals[name]
                for name in ours_totals
            },
            "explanation": (
                "Counts agree; this does not prove unsampled fields agree."
                if totals_equal else
                "Counts differ. Public no-op writes, writes reverted within "
                "the range, empty records, or a decoding/data discrepancy "
                "could account for this. No cause is established by this "
                "sampled check; prior-state analysis would be needed."
            ),
        },
        "sampled": stats,
        "alias_resolution": {
            "unique_assignments": len(resolved),
            "sources": dict(sorted(alias_sources.items())),
            "failed_originals": len(failed),
            "field_errors": resolution_errors,
            "examples": error_examples,
        },
        "skipped_count": skipped_count,
        "mismatch_count": mismatch_count,
        "mismatches": mismatches,
        "mismatch_examples_truncated": mismatch_count > len(mismatches),
        "scope": "Exact alias-contract/declaration checks; sampled other fields",
    }


def markdown_summary(report: dict) -> str:
    sampled = report["sampled"]
    matches = sum(item["matches"] for item in sampled.values())
    checked = matches + sum(item["mismatches"] for item in sampled.values())
    ours = report["totals"]["ours"]
    public = report["totals"]["public"]
    status = "PASS (sampled)" if report["ok"] else "FAIL"
    return (
        f"**{status}** — Starknet through block "
        f"{report['new_block_number']}.\n\n"
        f"- Alias-contract storage exact equality: "
        f"{report['alias_contract_storage']['equal']}.\n"
        f"- Cairo-1 declarations exact equality: "
        f"{report['declared_classes']['equal']}.\n"
        f"- Contracts, ours/public: {ours['contracts']}/{public['contracts']}; "
        f"storage entries: {ours['storage_updates']}/{public['storage_updates']}.\n"
        f"- Sampled field matches: {matches}/{checked}; "
        f"total failed assertions: {report['mismatch_count']}.\n"
        f"- Alias-resolution field errors: "
        f"{report['alias_resolution']['field_errors']}; "
        f"skipped items: {report['skipped_count']} "
        f"(reasons in JSON).\n"
        f"- {report['totals']['explanation']}\n"
    )
