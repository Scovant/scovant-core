"""The vendored UCP v2026-08-25 schemas stay byte-identical to their source.

`SOURCE.md` records a sha256 per vendored file. A file added, removed or edited
without its row changing fails here, and so does a `$ref` that points outside
the vendored set (the selection is `profile.json` plus everything its `$ref`s
reach) or a JSON pointer quoted in `FACTS.md` that no longer resolves.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path

import pytest

import scovant_core.parsers as parsers_pkg

VENDOR = Path(parsers_pkg.__file__).resolve().parent / "ucp_schemas" / "v2026-08-25"
_ROW = re.compile(r"^\|\s*`([^`]+\.json)`\s*\|\s*`([0-9a-f]{64})`\s*\|\s*$")


def _source_table(root: Path = VENDOR) -> dict[str, str]:
    rows: dict[str, str] = {}
    for line in (root / "SOURCE.md").read_text(encoding="utf-8").splitlines():
        row = _ROW.match(line.strip())
        if row:
            path, digest = row.groups()
            assert path not in rows, f"duplicate SOURCE.md row for {path}"
            rows[path] = digest
    return rows


def _vendored_json(root: Path = VENDOR) -> set[str]:
    return {p.relative_to(root).as_posix() for p in root.rglob("*.json")}


def _digest_problems(root: Path) -> list[str]:
    """Every way the tree at `root` disagrees with its own SOURCE.md."""
    table = _source_table(root)
    problems = [f"no SOURCE.md row: {rel}" for rel in sorted(_vendored_json(root) - set(table))]
    problems += [f"listed but missing: {rel}" for rel in sorted(set(table) - _vendored_json(root))]
    for rel, digest in sorted(table.items()):
        path = root / rel
        if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            problems.append(f"digest differs: {rel}")
    return problems


def _resolve(doc, pointer: str):
    for part in pointer.strip("/").split("/") if pointer.strip("/") else []:
        part = part.replace("~1", "/").replace("~0", "~")
        doc = doc[int(part)] if isinstance(doc, list) else doc[part]
    return doc


def _refs(node):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                yield value
            else:
                yield from _refs(value)
    elif isinstance(node, list):
        for value in node:
            yield from _refs(value)


def test_vendored_digests_match_source_md():
    assert _source_table(), "SOURCE.md lists no files"
    assert _digest_problems(VENDOR) == []


def test_digest_check_catches_a_one_byte_edit_and_an_unlisted_file(tmp_path):
    copy = tmp_path / "vendor"
    shutil.copytree(VENDOR, copy)
    assert _digest_problems(copy) == []
    target = copy / "service.json"
    data = bytearray(target.read_bytes())
    data[-2] = ord(" ") if data[-2] != ord(" ") else ord("\t")
    target.write_bytes(bytes(data))
    assert _digest_problems(copy) == ["digest differs: service.json"]
    (copy / "extra.json").write_text("{}")
    assert "no SOURCE.md row: extra.json" in _digest_problems(copy)


def test_every_id_names_its_own_path_under_one_base():
    """Validators build a local `$ref` registry keyed by `$id`; that only works if
    each id is exactly `<the upstream schemas base>/<vendored path>` (the base is
    read from `profile.json`'s own absolute `$id`, see SOURCE.md)."""
    profile_id = json.loads((VENDOR / "profile.json").read_text(encoding="utf-8"))["$id"]
    assert profile_id.startswith("https://") and profile_id.endswith("/schemas/profile.json")
    base = profile_id[: -len("profile.json")]
    for rel in sorted(_vendored_json()):
        doc = json.loads((VENDOR / rel).read_text(encoding="utf-8"))
        assert doc["$id"] == base + rel


def test_every_ref_resolves_inside_the_vendored_set():
    vendored = _vendored_json()
    for rel in sorted(vendored):
        doc = json.loads((VENDOR / rel).read_text(encoding="utf-8"))
        for ref in _refs(doc):
            assert not re.match(r"^[a-z]+:", ref), f"{rel}: absolute $ref {ref}"
            target, _, pointer = ref.partition("#")
            target_rel = (
                (Path(rel).parent / target).as_posix() if target else rel
            )
            target_rel = Path(target_rel).as_posix()
            # normalise "a/../b"
            parts: list[str] = []
            for seg in target_rel.split("/"):
                if seg == "..":
                    parts.pop()
                elif seg not in ("", "."):
                    parts.append(seg)
            target_rel = "/".join(parts)
            assert target_rel in vendored, f"{rel}: $ref {ref} leaves the vendored set"
            target_doc = json.loads((VENDOR / target_rel).read_text(encoding="utf-8"))
            _resolve(target_doc, pointer)


def test_vendored_files_are_valid_draft_2020_12_schemas():
    jsonschema = pytest.importorskip("jsonschema")
    for rel in sorted(_vendored_json()):
        doc = json.loads((VENDOR / rel).read_text(encoding="utf-8"))
        assert doc["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        jsonschema.Draft202012Validator.check_schema(doc)


def test_facts_md_pointers_resolve():
    facts = (VENDOR / "FACTS.md").read_text(encoding="utf-8")
    vendored = _vendored_json()
    quoted = re.findall(r"`([a-z_/]+\.json)#(/[^`]*)`", facts)
    local = [(f, p) for f, p in quoted if f in vendored]
    assert len(local) >= 20, "FACTS.md quotes fewer vendored pointers than expected"
    for rel, pointer in local:
        _resolve(json.loads((VENDOR / rel).read_text(encoding="utf-8")), pointer)


def test_facts_md_quotes_the_load_bearing_values():
    """The facts every later parser change reads, checked against the schema itself."""
    load = lambda rel: json.loads((VENDOR / rel).read_text(encoding="utf-8"))  # noqa: E731
    ucp, service, profile = load("ucp.json"), load("service.json"), load("profile.json")
    assert ucp["$defs"]["version"]["pattern"] == r"^\d{4}-\d{2}-\d{2}$"
    assert service["$defs"]["base"]["allOf"][1]["properties"]["transport"]["enum"] == [
        "rest", "mcp", "a2a", "embedded",
    ]
    assert "keys" in profile["$defs"]["base"]["properties"]
    assert "signing_keys" not in json.dumps(profile)
    assert profile["$defs"]["jwk_public_key"]["required"] == ["kid", "kty"]
    assert ucp["$defs"]["business_schema"]["allOf"][1]["required"] == [
        "services", "payment_handlers",
    ]
