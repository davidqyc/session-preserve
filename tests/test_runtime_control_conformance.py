"""Public matrix inventory, target validity, schema tables and migration contract."""

import ast
import json
from pathlib import Path
import re
import unittest

from codex_preserve.runtime_control import validate_authorization, validate_binding
from tests.runtime_fixtures import authorization, binding, receipt, correction, encoded

ROOT = Path(__file__).resolve().parents[1]


def leaves(value, prefix=""):
    for key, item in value.items():
        path = prefix + key
        if type(item) is dict:
            yield from leaves(item, path + ".")
        else:
            yield path


class P0Conformance(unittest.TestCase):
    def test_matrix_inventory_and_every_target_exists(self):
        matrix = json.loads((ROOT / "docs/runtime-control-p0-conformance.json").read_text())
        self.assertEqual(matrix["reference_id"], "session-preserve-private-runtime-reference-p1/v1")
        self.assertEqual(matrix["contract_sha256"], "e3dcfe08480394b351b1905b29b205407a35a9bd2050ddc936ed89c76052b0d6")
        self.assertEqual(matrix["key_count"], 146)
        self.assertEqual(matrix["unexplained_omissions"], 0)
        rows = {row["key"]: row for row in matrix["entries"]}
        self.assertIn("generic no-CU", rows["runtime.route"]["reason"])
        self.assertIn("calculator_catalog_proven=false", rows["runtime.required_attestations"]["reason"])
        self.assertIn("other five capabilities remain true", rows["runtime.required_attestations"]["reason"])
        self.assertEqual(len(matrix["entries"]), matrix["key_count"])
        self.assertEqual(len({row["key"] for row in matrix["entries"]}), matrix["key_count"])
        counts = {}
        fixtures = {"authorization": authorization(), "binding": binding(), "receipt": receipt()}
        fixtures["receipt"]["corrections"] = [correction()]
        fixtures["receipt"]["cleanup"]["owned_resources"] = [{"kind": "HELPER"}]
        text = (ROOT / "docs/runtime-control-p0-conformance.md").read_text()
        for row in matrix["entries"]:
            classification = row["classification"]
            self.assertIn(classification, ("PUBLIC_SCHEMA", "PUBLIC_VALIDATOR", "PUBLIC_TEST", "NOT_CARRIED_WITH_REASON"))
            counts[classification] = counts.get(classification, 0) + 1
            self.assertTrue(row["reason"].strip())
            self.assertEqual(text.count("| `" + row["key"] + "` |"), 1)
            if classification == "PUBLIC_SCHEMA":
                for target in row["target"].split(","):
                    value = fixtures
                    for field in target.split("."):
                        array = field.endswith("[]")
                        value = value[field[:-2] if array else field]
                        if array:
                            value = value[0]
            else:
                path, symbol = row["target"].split("#", 1)
                source = ROOT / path
                self.assertTrue(source.is_file(), row)
                if classification != "NOT_CARRIED_WITH_REASON":
                    tree = ast.parse(source.read_text())
                    names = {node.name for node in ast.walk(tree) if isinstance(node, (ast.ClassDef, ast.FunctionDef))}
                    self.assertIn(symbol.split(".")[-1], names, row)
        self.assertEqual(counts, matrix["classification_counts"])
        self.assertEqual(set(matrix["sections"]), {"identity", "runtime", "lifecycle", "observe_reconcile", "live_steer", "computer_use", "receipts", "foreground_cleanup", "portability", "hard_boundaries"})

    def test_exhaustive_authorization_and_binding_tables(self):
        doc = (ROOT / "docs/runtime-control-p0.md").read_text()
        tables = (("Exhaustive authorization field table", "Exhaustive binding field table",
                   validate_authorization(encoded(authorization()))),
                  ("Exhaustive binding field table", "Canonical digests and refs",
                   validate_binding(encoded(binding()))))
        for heading, next_heading, value in tables:
            section = doc.split("## " + heading, 1)[1].split("## " + next_heading, 1)[0]
            fields = re.findall(r"^\| `([^`]+)` \|", section, re.MULTILINE)
            self.assertEqual(set(fields), set(leaves(value)))
            self.assertEqual(len(fields), len(set(fields)))
        self.assertIn("8192 byte", doc)
        self.assertIn("12288 byte", doc)
        self.assertIn("16384 bytes", doc)

    def test_migration_mapping_and_archival_limits(self):
        doc = (ROOT / "docs/runtime-control-p0.md").read_text()
        pairs = {
            "Contract, code, safe exports": "FILE_STATE_ONLY",
            "Runtime discovery, transport, ownership": "HOST_BINDING",
            "Accessibility / Screen Recording when required": "TCC_PERMISSION",
            "Signed app / LaunchServices": "SIGNING_REGISTRATION",
            "Provider login / control pairing": "ACCOUNT_OR_DEVICE_PAIRING",
            "Process/socket/session approval/deadline/snapshot": "EPHEMERAL",
            "Validated terminal receipt / explicitly public conformance evidence": "FILE_STATE_ONLY",
            "Non-terminal state, active grant, endpoint, process/socket identity": "EPHEMERAL",
        }
        for component, classification in pairs.items():
            self.assertIn("| " + component + " | " + classification + " |", doc)
        self.assertIn("Copying files grants no permissions", doc)
        self.assertIn("never actionable", (ROOT / "docs/runtime-control-p0-conformance.md").read_text())
        for phrase in ("Authorization, binding, ledger, provider-state", "control/migration authority is EPHEMERAL"):
            self.assertIn(phrase, doc)


if __name__ == "__main__":
    unittest.main()
