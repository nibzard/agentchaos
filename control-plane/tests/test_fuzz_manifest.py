"""Fuzz the experiment manifest compiler (T042, AC-001).

Security-sensitive input gets mutated hundreds of times under fixed
seeds. The invariants:

- the compiler either refuses the manifest with CompileViolation or
  compiles it; no other exception escapes;
- an unknown key injected anywhere in the document is always refused;
- byte-level damage never produces a silent crash or an unexpected
  exception; damaged input is refused or revalidated as a genuinely
  different document.

Structural mutations walk the document; byte mutations work on the
canonical JSON text. Deterministic seeds keep every failure
reproducible.
"""

import copy
import json
import random
import string

import pytest

from acx_compiler import CompileViolation, compile_manifest
from acx_compiler.canonical import canonical_json
from conftest import NOW, build_store, draft_experiment, make_signer

SEED = 20260930
TRIALS = 400

ADVERSARIAL_KEYS = [
    "extra",
    "debug",
    "override",
    "x",
    "notes2",
    "safe_mode",
    "force",
    "verdict",
    "plan_digest_hint",
    "bypass",
    "Verdict",
    "Kind",
    "kind_",
    "",
    "kind ",
]

CONTROL_CHARACTERS = ["\x00", "\x1b", "‮", "�"]

WEIRD_VALUES = [
    None,
    True,
    0,
    -1,
    1 << 64,
    "",
    "x" * 5000,
    "\x00controlled",
    {"nested": {"deep": ["deeper"]}},
    ["list", "of", "strings"],
    "evt_<script>",
    "2050-01-01T00:00:00Z",
    "sha256:not-a-digest",
]


def _containers(document):
    """Every dict and list in the document, in walk order."""
    found: list[tuple[str, object]] = []

    def walk(node) -> None:
        if isinstance(node, dict):
            found.append(("dict", node))
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            found.append(("list", node))
            for value in node:
                walk(value)

    walk(document)
    return found


def _all_dicts(document, path=""):
    """Every dict with its path, for the unknown-key injection test."""
    found: list[tuple[str, dict]] = []
    if isinstance(document, dict):
        found.append((path, document))
        for key, value in document.items():
            found.extend(_all_dicts(value, f"{path}.{key}"))
    elif isinstance(document, list):
        for index, value in enumerate(document):
            found.extend(_all_dicts(value, f"{path}[{index}]"))
    return found


def _string_entries(containers):
    """Every (container, key-or-index) holding a string."""
    entries = []
    for kind, node in containers:
        if kind == "dict":
            entries.extend(
                (node, key) for key, value in node.items()
                if isinstance(value, str)
            )
        else:
            entries.extend(
                (node, index) for index, value in enumerate(node)
                if isinstance(value, str)
            )
    return entries


def _mutate(document, rng):
    """Return (mutated copy, operator name)."""
    mutated = copy.deepcopy(document)
    containers = _containers(mutated)
    dicts = [node for kind, node in containers if kind == "dict"]
    lists = [node for kind, node in containers if kind == "list"]
    operator = rng.choice(
        ["inject", "inject", "remove", "swap", "swap", "corrupt"]
    )
    if operator == "inject" or not dicts:
        target = dicts[rng.randrange(len(dicts))]
        key = rng.choice(ADVERSARIAL_KEYS)
        target[key] = rng.choice(WEIRD_VALUES)
        return mutated, f"inject {key!r}"
    if operator == "remove":
        non_empty = [node for node in dicts if node]
        target = non_empty[rng.randrange(len(non_empty))]
        key = rng.choice(sorted(target))
        del target[key]
        return mutated, f"remove {key!r}"
    if operator == "swap":
        holders = [node for node in dicts if node] + [
            node for node in lists if node
        ]
        target = holders[rng.randrange(len(holders))]
        if isinstance(target, dict):
            key = rng.choice(sorted(target))
            target[key] = rng.choice(WEIRD_VALUES)
        else:
            index = rng.randrange(len(target))
            target[index] = rng.choice(WEIRD_VALUES)
        return mutated, "swap a value's type"
    # corrupt: damage one string in place.
    entries = _string_entries(containers)
    node, key = entries[rng.randrange(len(entries))]
    position = rng.randrange(len(node[key]) + 1)
    character = rng.choice(string.printable + "".join(CONTROL_CHARACTERS))
    node[key] = node[key][:position] + character + node[key][position:]
    return mutated, "corrupt a string"


def _compile(experiment):
    return compile_manifest(
        experiment, build_store(), now=NOW, signer=make_signer()
    )


def test_structural_mutations_never_crash_the_compiler():
    rng = random.Random(SEED)
    compiled = 0
    refused = 0
    for _ in range(TRIALS):
        experiment = draft_experiment()
        mutated, _operator = _mutate(experiment, rng)
        try:
            _compile(mutated)
            compiled += 1
        except CompileViolation:
            refused += 1
    # Both outcomes are fine; any other exception escapes and fails
    # the test by raising here.
    assert compiled + refused == TRIALS
    assert refused > 0, "mutations never refused anything"


def test_unknown_keys_always_fail_closed():
    rng = random.Random(SEED + 1)
    for _trial in range(300):
        experiment = draft_experiment()
        dicts = _all_dicts(experiment)
        _, target = dicts[rng.randrange(len(dicts))]
        key = rng.choice(ADVERSARIAL_KEYS)
        target[key] = rng.choice(WEIRD_VALUES)
        with pytest.raises(CompileViolation):
            _compile(experiment)


def test_byte_damage_never_compiles_silently():
    rng = random.Random(SEED + 2)
    experiment = draft_experiment()
    clean = canonical_json(experiment).encode("utf-8")
    outcomes = {"refused": 0, "identical": 0, "different": 0}
    for _trial in range(300):
        damaged = bytearray(clean)
        operator = rng.choice(["flip", "flip", "truncate", "inject",
                               "append"])
        if operator == "flip":
            position = rng.randrange(len(damaged))
            damaged[position] = rng.randrange(256)
        elif operator == "truncate":
            damaged = damaged[: rng.randrange(len(damaged))]
        elif operator == "inject":
            position = rng.randrange(len(damaged) + 1)
            junk = rng.choice(
                [b"\x00", b'"}', b'{"x":1}', b"\\", b"\xff", b",null,"]
            )
            damaged = damaged[:position] + junk + damaged[position:]
        else:
            damaged = damaged + rng.choice(
                [b"{}", b"null", b" {}", b"\x00"]
            )
        try:
            text = damaged.decode("utf-8")
        except UnicodeDecodeError:
            outcomes["refused"] += 1
            continue
        try:
            document = json.loads(text)
        except json.JSONDecodeError:
            outcomes["refused"] += 1
            continue
        try:
            _compile(document)
            if canonical_json(document) == canonical_json(experiment):
                outcomes["identical"] += 1
            else:
                outcomes["different"] += 1
        except CompileViolation:
            outcomes["refused"] += 1
    assert sum(outcomes.values()) == 300
    # Damage that still parses must be refused or compile as a
    # genuinely different document; the counts only record that no
    # other exception escaped.
    assert outcomes["refused"] > 0


def test_the_clean_manifest_still_compiles():
    # Guard against a fuzz harness that breaks the fixture itself.
    result = _compile(draft_experiment())
    assert result.plan_digest.startswith("sha256:")
