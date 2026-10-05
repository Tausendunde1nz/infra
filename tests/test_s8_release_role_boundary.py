"""Actual legacy controller boundaries; no prior GREEN becomes S8 authority."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import tu1nz_adult_commercial_s12_1_runtime as r
from tests.test_s11_s12_release_compatibility import function


class ReleaseRoleBoundaryTests(unittest.TestCase):
    def test_s12_partial_or_stale_success_root_blocks_before_any_action(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/"s8-execution"
            root.mkdir()
            old={"ok":True,"s11":"GREEN","s12":"GREEN","timestamp":"2026-09-01T00:00:00Z"}
            (root/"old-success.json").write_text(json.dumps(old))
            before=(root/"old-success.json").read_bytes()
            with mock.patch.object(r,"S8_EXECUTION_ROOT",root):
                for action in (r.read_only_preflight,r.recover,r.deploy,
                    lambda:r.contain_aborted_metadata(root/"never-read.json"),
                    lambda:r.reconcile_metadata(root/"never-read.json")):
                    with self.assertRaisesRegex(r.S12ControlError,"ISOLATED_S8_NO_RECOVERY_OR_DEPLOYMENT_AUTHORITY"):
                        action()
                with mock.patch.object(r,"_trusted_controller_digest"),mock.patch.object(r,"os") as operating:
                    # The real guard performs path lstat; no mutation API is
                    # reached, including the old metadata-error writer.
                    operating.geteuid.return_value=0
                    with mock.patch.object(r,"_MetadataErrors") as provenance,redirect_stdout(io.StringIO()):
                        self.assertEqual(r.main(["contain-aborted","--metadata-contract",str(root/"never-read.json")]),1)
                        provenance.assert_not_called()
            self.assertEqual(before,(root/"old-success.json").read_bytes())
            self.assertEqual(sorted(p.name for p in root.iterdir()),["old-success.json"])

    def test_s12_dangling_root_is_not_absence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/"s8";root.symlink_to("missing")
            with mock.patch.object(r,"S8_EXECUTION_ROOT",root):
                with self.assertRaisesRegex(r.S12ControlError,"ISOLATED_S8"):
                    r._reject_isolated_s8_authority()

    def test_s11_actual_guard_rejects_partial_and_stale_green(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/"s8";root.mkdir()
            (root/"old-success.json").write_text('{"ok":true}')
            # Only isolated path / root identity are supplied. The actual
            # source function performs lstat and its real denial itself.
            script="set -Eeuo pipefail\nS8_EXECUTION_ROOT="+shlex.quote(str(root))+"\n"
            script+="id() { echo 0; }\n"+function("fail")+function("require_no_isolated_s8_authority")
            script+="require_no_isolated_s8_authority\n"
            result=subprocess.run(["bash","-c",script],capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            (root/"old-success.json").unlink();root.rmdir()
            result=subprocess.run(["bash","-c",script],capture_output=True,text=True)
            self.assertEqual(result.returncode,0)


if __name__=="__main__":unittest.main()
