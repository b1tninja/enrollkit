"""The dependency rule is enforced, not just written down.

DER and every wire format are ours, on asn1core. ``cryptography`` is admitted for primitives
only, so a module that parses a wire format must not import it, and no third-party ASN.1
library may appear in the package or in pyproject.toml.
"""

from __future__ import annotations

import ast
import pathlib
import sys
import tomllib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "enrollkit"
ALLOWED = set(sys.stdlib_module_names) | {"enrollkit", "asn1core", "cryptography"}
# Modules that hold primitives; everything else that reads a wire format stays free of it.
MAY_IMPORT_CRYPTOGRAPHY = {"protection.py", "trust.py"}


def imported_roots(path: pathlib.Path) -> set[str]:
    roots = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            roots |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def test_pyproject_declares_no_third_party_asn1_library():
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declared = " ".join(meta["project"]["dependencies"]).lower()
    for banned in ("asn1crypto", "pyasn1", "asn1tools"):
        assert banned not in declared
    assert "asn1core" in declared


@pytest.mark.parametrize("path", sorted(PACKAGE.rglob("*.py")), ids=lambda p: p.name)
def test_package_imports_only_stdlib_asn1core_and_cryptography(path):
    extra = imported_roots(path) - ALLOWED
    assert not extra, f"{path.name} imports {sorted(extra)}"
    if path.name not in MAY_IMPORT_CRYPTOGRAPHY:
        assert "cryptography" not in imported_roots(path), path.name + " must not use cryptography"
