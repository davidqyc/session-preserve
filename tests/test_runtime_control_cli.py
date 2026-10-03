"""P0 zero-state gates, passive static probe and local verification semantics."""

import builtins
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest import mock

from codex_preserve import cli
from codex_preserve._runtime_contract import P0_INACTIVE_VERBS, NOT_IMPLEMENTED_P0_EXIT
from codex_preserve.runtime_control import passive_probe
from codex_preserve.runtime_control import _cli as runtime_cli, _validation, _local
from tests.runtime_fixtures import authorization, binding, receipt, encoded


def invoke(args, main=cli.main):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(args)
    return code, out.getvalue(), err.getvalue()


class UnreadableStdin:
    def __getattr__(self, name):
        raise AssertionError("stdin must not be inspected")


class P0CLI(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def forbidden_io(self, stack):
        # Any of these calls would make an inactive verb exceed its P0 boundary.
        targets = ((builtins, "open"), (io, "open"), (os, "open"), (os, "stat"),
                   (os, "mkdir"), (os, "makedirs"), (os, "listdir"), (os, "scandir"),
                   (Path, "resolve"), (Path, "expanduser"), (Path, "mkdir"), (Path, "read_bytes"),
                   (subprocess, "Popen"), (subprocess, "run"), (subprocess, "check_output"),
                   (socket, "socket"), (socket, "create_connection"),
                   (json, "loads"), (argparse_module(), "ArgumentParser"),
                   (_validation, "validate_authorization"), (_validation, "validate_artifact"),
                   (_local, "read_regular_file"), (runtime_cli, "passive_probe"))
        for owner, name in targets:
            stack.enter_context(mock.patch.object(owner, name, side_effect=AssertionError("forbidden P0 work")))
        for name in ("system", "fork", "posix_spawn", "posix_spawnp", "execv", "execve", "spawnv"):
            if hasattr(os, name):
                stack.enter_context(mock.patch.object(os, name, side_effect=AssertionError("forbidden process work")))
        stack.enter_context(mock.patch("sys.stdin", UnreadableStdin()))

    def test_six_verbs_return_before_all_io_and_parsing(self):
        before = list(self.root.rglob("*"))
        expected = None
        for verb in P0_INACTIVE_VERBS:
            for main, prefix in ((cli.main, ["runtime"]), (runtime_cli.main, [])):
                with self.subTest(verb=verb, entry=main.__module__):
                    with ExitStack() as stack:
                        self.forbidden_io(stack)
                        code, out, err = invoke(prefix + [verb, "--authorization", "not-json", "--state-root", str(self.root / "state"), "--provider", "do-not-launch"], main)
                    self.assertEqual(code, NOT_IMPLEMENTED_P0_EXIT)
                    self.assertEqual(out, "")
                    result = json.loads(err)
                    self.assertEqual(result["status"], "NOT_IMPLEMENTED_P0")
                    self.assertFalse(result["state_created"])
                    expected = err if expected is None else expected
                    self.assertEqual(err, expected)
        self.assertEqual(list(self.root.rglob("*")), before)

    def test_inactive_verbs_in_fresh_subprocess_create_zero_state(self):
        repo = Path(__file__).resolve().parents[1]
        env = dict(os.environ, PYTHONPATH=str(repo / "src"), PYTHONDONTWRITEBYTECODE="1", HOME=str(self.root))
        script = '''
import sys, importlib.abc
class DenyRuntime(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith("codex_preserve.runtime_control"):
            raise AssertionError("inactive verbs must not import runtime")
sys.meta_path.insert(0, DenyRuntime())
from codex_preserve.cli import main
raise SystemExit(main(sys.argv[1:]))
'''
        for verb in P0_INACTIVE_VERBS:
            result = subprocess.run([os.sys.executable, "-B", "-c", script, "runtime", verb,
                                     "--state-root", str(self.root / "state")], cwd=self.root, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 3, result.stderr)
            self.assertEqual(json.loads(result.stderr)["status"], "NOT_IMPLEMENTED_P0")
            self.assertEqual(list(self.root.iterdir()), [])

    def test_surface_and_excluded_verbs(self):
        with self.assertRaises(SystemExit) as caught:
            with redirect_stdout(io.StringIO()) as output:
                cli.main(["runtime", "--help"])
        self.assertEqual(caught.exception.code, 0)
        for verb in ("probe", "verify") + P0_INACTIVE_VERBS:
            self.assertIn(verb, output.getvalue())
        for verb in ("computer-use", "resume", "retry", "exec", "daemon", "server", "queue"):
            with self.assertRaises(SystemExit) as caught:
                with redirect_stderr(io.StringIO()):
                    cli.main(["runtime", verb])
            self.assertEqual(caught.exception.code, 2)

    def test_probe_only_reads_static_metadata_and_stats_candidate(self):
        metadata = self.root / "metadata.json"
        metadata.write_bytes(encoded({"provider": "codex", "declared_runtime_version": "0.0.0-synthetic"}))
        binary = self.root / "synthetic-provider"
        binary.write_text("not a program; must never execute", encoding="utf-8")
        binary.chmod(0o755)
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        with ExitStack() as stack:
            for owner, name in ((subprocess, "Popen"), (subprocess, "run"), (os, "system"),
                                (socket, "socket"), (os, "mkdir"), (os, "makedirs"), (Path, "write_bytes"),
                                (Path, "write_text"), (Path, "mkdir")):
                stack.enter_context(mock.patch.object(owner, name, side_effect=AssertionError("active work forbidden")))
            code, out, err = invoke(["runtime", "probe", "--metadata", str(metadata), "--executable", str(binary)])
        self.assertEqual((code, err), (0, ""))
        result = json.loads(out)
        self.assertEqual(result["declared_runtime_version"], "0.0.0-synthetic")
        self.assertEqual(result["version_status"], "DECLARED")
        self.assertEqual(result["executable_status"], "REGULAR_FILE")
        self.assertEqual(result["live_capabilities"], "UNVERIFIED")
        self.assertFalse(result["execution_attested"])
        self.assertNotIn(str(self.root), out)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})

    def test_missing_or_insufficient_probe_is_unknown_or_unverified(self):
        self.assertEqual(passive_probe()["version_status"], "UNKNOWN")
        self.assertEqual(passive_probe(metadata=self.root / "missing")["version_status"], "UNVERIFIED")
        metadata = self.root / "metadata.json"
        for payload in (b"{}", b'{"provider":"codex","declared_runtime_version":"0.0.0","x":1}',
                        b'{"provider":"codex","provider":"codex","declared_runtime_version":"0.0.0"}',
                        b" " * 4097):
            metadata.write_bytes(payload)
            result = passive_probe(metadata=metadata)
            self.assertEqual(result["version_status"], "UNVERIFIED")
            self.assertIsNone(result["declared_runtime_version"])
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        self.assertEqual(passive_probe(metadata=fifo)["version_status"], "UNVERIFIED")

    def test_verify_three_schemas_and_explicit_pairs_only(self):
        paths = {}
        for name, value in (("authorization", authorization()), ("binding", binding()), ("receipt", receipt())):
            paths[name] = self.root / (name + ".json")
            paths[name].write_bytes(encoded(value))
            code, out, err = invoke(["runtime", "verify", str(paths[name])])
            self.assertEqual((code, err), (0, ""))
            result = json.loads(out)
            self.assertEqual(result["status"], "PASS")
            self.assertIn("does not attest", result["semantics"])
            self.assertFalse(result["execution_attested"])
        code, out, err = invoke(["runtime", "verify", str(paths["receipt"]), "--authorization", str(paths["authorization"]), "--binding", str(paths["binding"])])
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(len(json.loads(out)["paired_checks"]), 3)
        # No implicit sibling resolution. Only explicitly paired inputs are read.
        paths["authorization"].write_bytes(b"invalid")
        self.assertEqual(invoke(["runtime", "verify", str(paths["receipt"])])[0], 0)
        self.assertEqual(invoke(["runtime", "verify", str(paths["receipt"]), "--authorization", str(paths["authorization"])])[0], 2)

    def test_verify_diagnostics_do_not_echo_private_data(self):
        target = self.root / "artifact.json"
        target.write_bytes(b'{"SYNTHETIC_PRIVATE_SENTINEL":')
        code, out, err = invoke(["runtime", "verify", str(target)])
        self.assertEqual((code, out), (2, ""))
        self.assertNotIn("SYNTHETIC_PRIVATE_SENTINEL", err)
        self.assertNotIn(str(target), err)
        self.assertEqual(json.loads(err)["code"], "INVALID_JSON")
        code, out, err = invoke(["runtime", "verify", str(self.root / "missing")])
        self.assertEqual(json.loads(err)["code"], "LOCAL_FILE_UNREADABLE")
        self.assertNotIn(str(self.root), err)

    def test_top_preservation_verify_points_to_runtime_verify(self):
        for fixture in (authorization, binding, receipt):
            path = self.root / "artifact.json"
            path.write_bytes(encoded(fixture()))
            with mock.patch.object(cli.verify, "verify_package", side_effect=AssertionError("not a package")):
                code, out, err = invoke(["verify", str(path), "--json"])
            self.assertEqual((code, out), (2, ""))
            self.assertIn("session-preserve runtime verify", err)


def argparse_module():
    import argparse
    return argparse


if __name__ == "__main__":
    unittest.main()
