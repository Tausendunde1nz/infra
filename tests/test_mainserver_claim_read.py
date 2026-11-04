"""Local filesystem tests only; no host, privileged access or transaction."""
import os
from pathlib import Path
import tempfile
import unittest

from scripts import tu1nz_mainserver_claim_read as reader


class ReadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        fd = os.open(self.root, os.O_RDONLY|os.O_DIRECTORY)
        self.paths = reader.FixedPaths(fd)
        os.close(fd)

    def tearDown(self):
        self.paths.close()
        self.temp.cleanup()

    def test_absence_at_first_missing_parent_and_no_creation(self):
        (self.root/'etc').mkdir()
        self.assertEqual(self.paths.inspect('/etc/absent/claim'), {
            'state': 'ABSENT', 'first_absent_component': '/etc/absent', 'held_parent': '/etc'})
        self.paths.check()
        self.assertEqual(list((self.root/'etc').iterdir()), [])

    def test_symlink_ancestor_is_not_absence(self):
        (self.root/'link').symlink_to('/does-not-exist')
        with self.assertRaisesRegex(reader.Denied, 'NON_DIRECTORY_OR_SYMLINK_ANCESTOR'):
            self.paths.inspect('/link/claim')

    def test_final_dangling_symlink_is_present(self):
        (self.root/'claim').symlink_to('/does-not-exist')
        self.assertEqual(self.paths.inspect('/claim')['state'], 'PRESENT')
        self.paths.check()

    def test_new_claim_after_observation_denied(self):
        self.paths.inspect('/claim')
        (self.root/'claim').mkdir()
        with self.assertRaisesRegex(reader.Denied, 'TARGET_CHANGED_AT_END'):
            self.paths.check()

    def test_replaced_held_ancestor_denied(self):
        (self.root/'parent').mkdir()
        self.paths.inspect('/parent/claim')
        (self.root/'parent').rename(self.root/'old')
        (self.root/'parent').mkdir()
        with self.assertRaisesRegex(reader.Denied, 'ANCESTOR_REPLACED_AT_END'):
            self.paths.check()

    def test_non_directory_is_not_absence(self):
        (self.root/'file').write_bytes(b'not a directory')
        with self.assertRaisesRegex(reader.Denied, 'NON_DIRECTORY_OR_SYMLINK_ANCESTOR'):
            self.paths.inspect('/file/claim')

    def test_present_content_is_never_read(self):
        (self.root/'claim').write_bytes(b'private synthetic bytes')
        row = self.paths.inspect('/claim')
        self.assertEqual(row['state'], 'PRESENT')
        self.assertNotIn('private', str(row))
        self.paths.check()

    def test_fixed_scope_excludes_pilot_and_all_service_actions(self):
        self.assertEqual(len(reader.TARGETS), 16)
        self.assertEqual(len(set(reader.TARGETS)), 16)
        self.assertIn('/opt/tu1nz_repos/public-web-runtime-r5', reader.TARGETS)
        self.assertNotIn('173954685', ' '.join(reader.TARGETS))
        self.assertTrue(all(p.startswith('/') for p in reader.TARGETS))


if __name__ == '__main__':
    unittest.main()
