#!/usr/bin/env python3
"""Enforce the Session Preserve package's stdlib-only import boundary."""

from __future__ import annotations

import ast
from importlib.machinery import EXTENSION_SUFFIXES
from pathlib import Path
import sys
import sysconfig
import tokenize
from typing import FrozenSet, List, Optional, Tuple


PACKAGE_NAME = "codex_preserve"


def stdlib_roots() -> FrozenSet[str]:
    """Use interpreter metadata; on 3.9 enumerate only stdlib directories.

    Do not inspect sys.path or import prospective dependencies: those routes
    would bless installed third-party packages or execute their code.
    """
    declared = getattr(sys, "stdlib_module_names", None)
    if declared is not None:
        return frozenset(declared)
    roots = set(sys.builtin_module_names)
    directories = {Path(sysconfig.get_path(key))
                   for key in ("stdlib", "platstdlib")}
    for directory in sorted(directories):
        for child in directory.iterdir():
            if child.is_file() and child.suffix == ".py":
                roots.add(child.stem)
            elif child.is_dir() and (child / "__init__.py").is_file():
                if child.name not in ("site-packages", "dist-packages"):
                    roots.add(child.name)
        extensions = directory / "lib-dynload"
        if extensions.is_dir():
            for child in extensions.iterdir():
                for suffix in EXTENSION_SUFFIXES:
                    if child.name.endswith(suffix):
                        roots.add(child.name[:-len(suffix)])
                        break
    return frozenset(roots)


def check_source(source: str, filename: str, package_depth: int,
                 allowed: FrozenSet[str]) -> List[Tuple[str, int, str]]:
    tree = ast.parse(source, filename=filename)
    findings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                if root not in allowed:
                    findings.append((filename, node.lineno,
                                     "disallowed import root: " + root))
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                if node.level > package_depth:
                    findings.append((filename, node.lineno,
                                     "relative import escapes product package"))
            else:
                root = (node.module or "").split(".", 1)[0]
                if root not in allowed:
                    findings.append((filename, node.lineno,
                                     "disallowed import root: " + root))
    return sorted(findings)


def check_package(package: Path) -> List[Tuple[str, int, str]]:
    if not package.is_dir() or package.name != PACKAGE_NAME:
        raise ValueError("expected the %s source package" % PACKAGE_NAME)
    allowed = stdlib_roots() | {PACKAGE_NAME}
    sources = sorted(package.rglob("*.py"))
    if not sources:
        raise ValueError("product source package has no Python files")
    findings = []
    for path in sources:
        relative = path.relative_to(package)
        filename = PACKAGE_NAME + "/" + relative.as_posix()
        # A root module (including __init__) has depth 1; a module in a
        # subpackage has depth 2, etc. More dots would leave the product.
        with tokenize.open(str(path)) as stream:
            source = stream.read()
        findings.extend(check_source(source, filename, len(relative.parts),
                                     allowed))
    return sorted(findings)


def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    package = (Path(args[0]) if args else
               Path(__file__).resolve().parents[1] / "src" / PACKAGE_NAME)
    try:
        findings = check_package(package)
    except (OSError, ValueError, SyntaxError) as error:
        print("PRODUCT_IMPORTS=FAIL: %s" % error)
        return 1
    for filename, line, detail in findings:
        print("%s:%d: %s" % (filename, line, detail))
    print("PRODUCT_IMPORTS=%s" % ("FAIL" if findings else "PASS"))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
