import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('guard', Path(__file__).parents[1] / 'scripts/tu1nz_spicymila_network_guard.py')
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class NetworkCoverageTests(unittest.TestCase):
    def fixtures(self):
        return ({'services': {m.NAME: {'networks': {'default': None}}},
                 'networks': {'default': {'name': 'isolated'}}},
                {'NetworkSettings': {'Networks': {'isolated': {'Aliases': []}}}})

    def test_exact_coverage(self):
        model, live = self.fixtures()
        m.require_compose_network_coverage(model, live)

    def test_additional_live_network_blocks(self):
        model, live = self.fixtures()
        live['NetworkSettings']['Networks']['unmodeled'] = {}
        with self.assertRaisesRegex(m.Refuse, 'recreation blocked'):
            m.require_compose_network_coverage(model, live)

    def test_missing_live_network_blocks(self):
        model, live = self.fixtures(); live['NetworkSettings']['Networks'] = {}
        with self.assertRaises(m.Refuse): m.require_compose_network_coverage(model, live)

    def test_unresolved_declared_network_blocks(self):
        model, live = self.fixtures(); model['networks']['default'] = {}
        with self.assertRaises(m.Refuse): m.require_compose_network_coverage(model, live)

    def test_missing_or_malformed_data_blocks(self):
        for model, live in [({}, {}), ({'services': {m.NAME: {'networks': None}}}, {}), self.fixtures()]:
            if model.get('networks'): model['services'][m.NAME]['networks'] = {}
            with self.assertRaises(m.Refuse): m.require_compose_network_coverage(model, live)

    def test_inputs_unchanged(self):
        model, live = self.fixtures(); saved = copy.deepcopy((model, live))
        m.require_compose_network_coverage(model, live)
        self.assertEqual((model, live), saved)

    def test_no_activation_surface(self):
        self.assertFalse(any(hasattr(m, name) for name in ('Runtime', 'activate', 'main', 'subprocess', 'os')))


if __name__ == '__main__': unittest.main()
