"""Executable product isolation checks against real temporary archive bytes."""

import contextlib
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import check_distribution_content as distributions
import check_product_imports as imports


class DistributionContentTests(unittest.TestCase):
    VERSION = "12.34.5"
    INFO = "session_preserve-" + VERSION + ".dist-info"
    PREFIX = "session_preserve-" + VERSION
    METADATA = ("Metadata-Version: 2.4\nName: session-preserve\nVersion: "
                + VERSION + "\n\n").encode()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def wheel(self, extras=(), top_level=b"codex_preserve\n", metadata=None):
        # Deliberately no project/version in the archive filename.
        path = self.root / "candidate.whl"
        files = [
            ("codex_preserve/__init__.py", b""),
            ("codex_preserve/runtime_control/__init__.py", b""),
            (self.INFO + "/METADATA", metadata or self.METADATA),
            (self.INFO + "/WHEEL", b"Wheel-Version: 1.0\n"),
            (self.INFO + "/licenses/LICENSE", b"license\n"),
            (self.INFO + "/RECORD", b""),
        ]
        if top_level is not None:
            files.append((self.INFO + "/top_level.txt", top_level))
        with zipfile.ZipFile(path, "w") as archive:
            for name, data in files + list(extras):
                archive.writestr(name, data)
        return path

    def sdist(self, extras=(), prefix=None, metadata=None):
        path = self.root / "candidate.tar.gz"
        prefix = prefix or self.PREFIX
        files = [
            ("PKG-INFO", metadata or self.METADATA),
            ("LICENSE", b"license\n"), ("MANIFEST.in", b"graft tests\n"),
            ("README.md", b"public readme\n"), ("pyproject.toml", b""),
            ("setup.cfg", b"[egg_info]\n"),
            ("src/codex_preserve/__init__.py", b""),
            ("src/codex_preserve/runtime_control/_cli.py", b""),
            ("src/session_preserve.egg-info/PKG-INFO", self.METADATA),
            ("src/session_preserve.egg-info/top_level.txt", b"codex_preserve\n"),
            ("src/session_preserve.egg-info/SOURCES.txt", b"README.md\n"),
            ("tests/fixtures/public.json", b"{}"),
            ("examples/pass/public.md", b"example\n"),
            ("tools/public_hygiene_scan.py", b""),
        ]
        with tarfile.open(path, "w:gz") as archive:
            # Real sdists include directory members as well as files.
            for directory in ("", "src", "src/codex_preserve", "tests", "tools",
                              "examples", "src/session_preserve.egg-info"):
                member = tarfile.TarInfo(prefix + ("/" + directory if directory else ""))
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
            for name, data in files + list(extras):
                member = tarfile.TarInfo(prefix + "/" + name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        return path

    def test_positive_wheel_and_sdist_metadata_derive_identity(self):
        expected = ("session-preserve", self.VERSION)
        wheel, sdist = self.wheel(), self.sdist()
        self.assertEqual(distributions.check_wheel(wheel), expected)
        self.assertEqual(distributions.check_sdist(sdist), expected)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(distributions.main([str(sdist), str(wheel)]), 0)
        self.assertIn("DISTRIBUTION_CONTENT=PASS", output.getvalue())

    def test_wheel_top_level_is_optional_but_exclusive(self):
        distributions.check_wheel(self.wheel(top_level=None))
        for value in (b"example_sibling\n", b"codex_preserve\nexample_sibling\n", b""):
            with self.subTest(value=value), self.assertRaises(distributions.DistributionError):
                distributions.check_wheel(self.wheel(top_level=value))

    def test_wheel_contamination_is_rejected(self):
        for name in ("apps/example-sibling/main.py", "example_sibling/__init__.py",
                     "codex_preserve/ContextBridge_helper.py",
                     self.INFO + "/CONTEXTBRIDGE.txt",
                     "other-1.0.dist-info/WHEEL", "codex_preserve/apps/sibling.py"):
            with self.subTest(name=name), self.assertRaises(distributions.DistributionError):
                distributions.check_wheel(self.wheel([(name, b"")]))

    def test_sdist_frozen_roots_and_source_subtrees_reject_widening(self):
        for name in ("apps/example-sibling/main.py", "docs/new-product.md",
                     "README.zh-CN.md", ".github/workflows/new-product.yml",
                     "src/example_sibling/__init__.py",
                     "tools/ContextBridge_helper.py", "tests/CONTEXTBRIDGE/data.json",
                     "src/session_preserve.egg-info/private.txt"):
            with self.subTest(name=name), self.assertRaises(distributions.DistributionError):
                distributions.check_sdist(self.sdist([(name, b"")]))

    def test_executable_negative_control_reads_contaminated_archive(self):
        wheel = self.wheel()
        sdist = self.sdist([("apps/example-sibling/main.py", b"synthetic only")])
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(distributions.main([str(wheel), str(sdist)]), 1)
        self.assertIn("outside frozen allowlist", output.getvalue())

    def test_normal_sdist_name_variants_and_metadata_mismatch(self):
        distributions.check_sdist(self.sdist(prefix="session-preserve-" + self.VERSION))
        for prefix in ("example-" + self.VERSION, "session_preserve-0.0.0"):
            with self.subTest(prefix=prefix), self.assertRaises(distributions.DistributionError):
                distributions.check_sdist(self.sdist(prefix=prefix))
        with self.assertRaises(distributions.DistributionError):
            distributions.check_wheel(self.wheel(metadata=b"Name: example\nVersion: 1\n"))

    def test_unsafe_paths_are_not_normalized_into_allowed_paths(self):
        for name in ("/codex_preserve/file.py", "codex_preserve/../other.py",
                     "codex_preserve//file.py", "codex_preserve/./file.py",
                     "codex_preserve\\other.py"):
            with self.subTest(name=name), self.assertRaises(distributions.DistributionError):
                distributions.check_wheel(self.wheel([(name, b"")]))

    def test_sdist_link_cannot_bypass_member_boundary(self):
        path = self.sdist()
        # Rebuild as gzip after adding a link; never extract the archive.
        with tarfile.open(path) as archive:
            members = [(item, archive.extractfile(item).read() if item.isfile() else None)
                       for item in archive.getmembers()]
        with tarfile.open(path, "w:gz") as archive:
            for member, data in members:
                archive.addfile(member, io.BytesIO(data) if data is not None else None)
            link = tarfile.TarInfo(self.PREFIX + "/tools/link")
            link.type = tarfile.SYMTYPE
            link.linkname = "../../outside"
            archive.addfile(link)
        with self.assertRaises(distributions.DistributionError):
            distributions.check_sdist(path)

    def test_command_requires_one_complete_consistent_pair(self):
        wheel, sdist = self.wheel(), self.sdist()
        with contextlib.redirect_stdout(io.StringIO()):
            for args in ([], [str(wheel)], [str(wheel), str(sdist), "other.txt"]):
                self.assertEqual(distributions.main(args), 1)
            other = b"Name: session-preserve\nVersion: 99.0\n"
            sdist = self.sdist(metadata=other, prefix="session_preserve-99.0")
            self.assertEqual(distributions.main([str(wheel), str(sdist)]), 1)


class ProductImportTests(unittest.TestCase):
    def setUp(self):
        self.allowed = imports.stdlib_roots() | {imports.PACKAGE_NAME}

    def check(self, source, depth=1):
        return imports.check_source(source, "synthetic.py", depth, self.allowed)

    def test_current_product_tree_passes(self):
        self.assertEqual(imports.check_package(ROOT / "src" / "codex_preserve"), [])

    def test_import_and_from_import_allow_only_stdlib_and_product(self):
        self.assertEqual(self.check(
            "import os.path, json, codex_preserve.cli\n"
            "from email.parser import BytesParser\n"
            "from __future__ import annotations\n"
            "from codex_preserve import verify\n"
            "from . import verify\nfrom .runtime_control import _cli\n"), [])
        findings = self.check(
            "import json, example_dependency as dep\n"
            "from example_sibling.api import thing\n")
        self.assertEqual(findings, [
            ("synthetic.py", 1, "disallowed import root: example_dependency"),
            ("synthetic.py", 2, "disallowed import root: example_sibling")])

    def test_strings_and_comments_are_not_imports(self):
        self.assertEqual(self.check(
            '# import example_sibling\ntext = "from example_dependency import x"\n'), [])

    def test_relative_imports_cannot_leave_product(self):
        self.assertTrue(self.check("from .. import example_sibling\n"))
        self.assertEqual(self.check("from .. import verify\n", depth=2), [])
        self.assertTrue(self.check("from ... import example_sibling\n", depth=2))

    def test_nested_source_files_are_checked(self):
        with tempfile.TemporaryDirectory() as temp:
            package = Path(temp) / "codex_preserve"
            nested = package / "nested"
            nested.mkdir(parents=True)
            (package / "__init__.py").write_text("import json\n", encoding="utf-8")
            (nested / "bad.py").write_text("from example_sibling import api\n", encoding="utf-8")
            findings = imports.check_package(package)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0][0], "codex_preserve/nested/bad.py")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(imports.main([str(package)]), 1)

    def test_python39_fallback_excludes_site_packages(self):
        with mock.patch.object(sys, "stdlib_module_names", None, create=True):
            roots = imports.stdlib_roots()
        for name in ("os", "json", "email", "sqlite3", "_socket", "_csv"):
            self.assertIn(name, roots)
        for name in ("setuptools", "pip", "example_sibling", "site-packages"):
            self.assertNotIn(name, roots)

    def test_empty_or_wrong_product_root_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            package = Path(temp) / "codex_preserve"
            package.mkdir()
            with self.assertRaises(ValueError):
                imports.check_package(package)
            with self.assertRaises(ValueError):
                imports.check_package(Path(temp))


if __name__ == "__main__":
    unittest.main()
