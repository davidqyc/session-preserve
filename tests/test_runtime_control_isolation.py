"""Fresh-process evidence for preservation imports and unchanged packaging."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from codex_preserve._provider_registry import PROVIDER_REGISTRY
from codex_preserve._v3_package import PACKAGE_SCHEMA_VERSION, write_v3_package
from tests.test_v3_package import spec
from tests.runtime_fixtures import authorization, encoded


class PreservationRuntimeIsolation(unittest.TestCase):
    def test_preservation_paths_do_not_import_runtime_in_fresh_processes(self):
        repo = Path(__file__).resolve().parents[1]
        script = '''
import sys, importlib.abc
class RuntimeImportForbidden(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "codex_preserve.runtime_control" or fullname.startswith("codex_preserve.runtime_control."):
            raise AssertionError("preservation imported runtime_control")
sys.meta_path.insert(0, RuntimeImportForbidden())
from codex_preserve.cli import main
code = main(sys.argv[1:])
assert not any(n.startswith("codex_preserve.runtime_control") for n in sys.modules)
print("RUNTIME_IMPORT_ABSENT")
raise SystemExit(code)
'''
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "package"
            write_v3_package(package, spec())
            artifact = root / "runtime.json"
            artifact.write_bytes(encoded(authorization()))
            env = dict(os.environ, PYTHONPATH=str(repo / "src"), PYTHONDONTWRITEBYTECODE="1", HOME=temp)
            cases = ((["--help"], 0), (["export", "--help"], 0),
                     (["export", "codex", "--help"], 0),
                     (["verify", str(package), "--json"], 0), (["pack", str(package)], 0),
                     (["verify", str(artifact), "--json"], 2))
            # argparse help exits itself; catch its SystemExit in the wrapper.
            script = script.replace("code = main(sys.argv[1:])", "try:\n    code = main(sys.argv[1:])\nexcept SystemExit as e:\n    code = e.code")
            for argv, expected in cases:
                with self.subTest(argv=argv[0:2]):
                    result = subprocess.run([os.sys.executable, "-B", "-c", script] + argv,
                                            cwd=temp, env=env, capture_output=True, text=True)
                    self.assertEqual(result.returncode, expected, result.stderr)
                    self.assertIn("RUNTIME_IMPORT_ABSENT", result.stdout)
                    self.assertNotIn("AssertionError", result.stderr)

    def test_registry_and_package_contract_unchanged(self):
        self.assertEqual(tuple(PROVIDER_REGISTRY), ("codex", "claude", "kimi", "zcode"))
        self.assertEqual(PACKAGE_SCHEMA_VERSION, "3.0")
        self.assertNotIn("runtime", PROVIDER_REGISTRY)

    def test_runtime_receipts_not_automatically_packed(self):
        from codex_preserve._v3_package import generate_v3_transfer_zip, verify_v3_package
        with tempfile.TemporaryDirectory() as temp:
            package = Path(temp) / "package"
            write_v3_package(package, spec())
            (package / "runtime-receipt.json").write_text("{}", encoding="utf-8")
            self.assertEqual(verify_v3_package(package)["verdict"], "FAIL")
            with self.assertRaises(ValueError):
                generate_v3_transfer_zip(package)


if __name__ == "__main__":
    unittest.main()
