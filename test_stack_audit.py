"""Regression checks for stack audit units and evidence handling."""

import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from axf_inspector import ELFAnalyzer, StackDepthNode, StackFrameInfo, calculate_stack_budget


class StackBudgetTests(unittest.TestCase):
    def test_target_defined_units_and_alignment(self):
        budget = calculate_stack_budget(1960, 132, 1024, 4, 128, 32)
        self.assertEqual(budget['required_bytes'], 3138)
        self.assertEqual(budget['recommended_units'], 800)
        self.assertEqual(budget['recommended_bytes'], 3200)
        self.assertFalse(budget['model_exceeds_allocation'])

    def test_minimum_recommendation_is_policy_not_measured_usage(self):
        budget = calculate_stack_budget(16, 0, 128, 1, 128, 16)
        self.assertEqual(budget['recommendation_ratio'], 1)
        self.assertLess(budget['required_ratio'], 0.5)

    def test_rounding_and_over_budget(self):
        budget = calculate_stack_budget(100, 0, 50, 2, 0, 8, 1.001)
        self.assertEqual(budget['required_bytes'], 101)
        self.assertEqual(budget['recommended_units'], 56)
        self.assertTrue(budget['model_exceeds_allocation'])

    def test_allocation_unit_widths_are_architecture_neutral(self):
        for unit_bytes in (1, 2, 4, 8):
            with self.subTest(unit_bytes=unit_bytes):
                budget = calculate_stack_budget(64, 0, 64, unit_bytes, safety_factor=1)
                self.assertEqual(budget['recommended_units'], 64 // unit_bytes)
                self.assertEqual(budget['recommended_bytes'], 64)

    def test_zero_context_is_explicitly_supported(self):
        budget = calculate_stack_budget(64, 0, 64, 1, safety_factor=1)
        self.assertEqual(budget['context_bytes'], 0)
        self.assertEqual(budget['base_bytes'], 64)

    def test_invalid_input(self):
        for values in ((-1, 0, 128, 4), (1, 0, 0, 4),
                       (1, 0, 128, 0), (1, 0, 128, 4, 0, 0),
                       (True, 0, 128, 4)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                calculate_stack_budget(*values)
        for factor in (float('nan'), 0.5):
            with self.subTest(factor=factor), self.assertRaises(ValueError):
                calculate_stack_budget(1, 0, 128, 4, safety_factor=factor)


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = ELFAnalyzer.__new__(ELFAnalyzer)
        self.analyzer.path = __file__
        self.analyzer._symtab = None
        self.analyzer.get_symbol = Mock(return_value=None)
        branch = StackDepthNode('branch', 4, 8, 88, indirect_count=2, frame_source='dwarf_cfi')
        root = StackDepthNode('task', 2, 8, 100, children=[branch], frame_source='dwarf_cfi')
        target = StackDepthNode('callback', 6, 200, 200, frame_source='dwarf_cfi')
        self.analyzer.analyze_stack_depth = Mock(side_effect=lambda name, **kwargs: {'task': root, 'callback': target}.get(name))
        self.analyzer.analyze_stackframe = Mock(return_value=StackFrameInfo('task', 2, 2, True, stack_frame=8, source='dwarf_cfi'))
        self.manifest = {'schema_version': 2,
                 'allocation_policy': {'unit_name': 'test-unit', 'unit_bytes': 2,
                               'minimum_units': 16, 'granularity_units': 8},
                 'context': {'bytes': 24, 'evidence': 'test port evidence'},
                 'tasks': [{'entry': 'task', 'allocated_units': 256,
                                    'callback_paths': [{'path': ['task', 'callback'], 'evidence': 'registration'}]}]}

    def test_callback_and_all_branch_indirect_evidence(self):
        report = self.analyzer.audit_tasks(self.manifest, Path('.'))
        row = report['tasks'][0]
        self.assertEqual(row['modeled_bytes'], 208)
        self.assertEqual(row['indirect_sites_all_branches'], 2)
        self.assertEqual(row['deepest_path'], ['task', 'callback'])
        self.assertEqual(row['status'], 'INCOMPLETE')
        self.assertEqual(len(report['axf_sha256']), 64)

    def test_missing_symbol_does_not_become_zero(self):
        self.manifest['tasks'][0]['entry'] = 'absent'
        row = self.analyzer.audit_tasks(self.manifest, Path('.'))['tasks'][0]
        self.assertEqual(row['status'], 'MISSING_SYMBOL')
        self.assertNotIn('modeled_bytes', row)

    def test_duplicate_entries_rejected(self):
        self.manifest['tasks'] *= 2
        with self.assertRaises(ValueError):
            self.analyzer.audit_tasks(self.manifest, Path('.'))

    def test_self_recursion_is_reported(self):
        self.analyzer.get_symbol = Mock(return_value={'st_info': {'type': 'STT_FUNC'}, 'st_value': 3, 'st_size': 2})
        self.analyzer._build_addr_to_name_map = Mock()
        self.analyzer._read_bytes = Mock(return_value=b'\x00\xbf')
        self.analyzer._decode_bl_instructions_indirect = Mock(return_value=0)
        self.analyzer._decode_bl_instructions = Mock(return_value=[(2, 'task')])
        root = ELFAnalyzer.analyze_stack_depth(self.analyzer, 'task')
        self.assertTrue(root.children[0].is_cycle)

    def test_non_sp_cfi_is_not_treated_as_stack_depth(self):
        class Entry:
            def __getitem__(self, key):
                return 2

            def get_decoded(self):
                return SimpleNamespace(table=[{'cfa': SimpleNamespace(reg=7, offset=16, expr=None)}])

        self.analyzer._dwarf_info = SimpleNamespace(CFI_entries=lambda: [Entry()])
        self.analyzer._build_cfi_stack_map()
        self.assertNotIn(2, self.analyzer._cfi_stack_map)


if __name__ == '__main__':
    unittest.main()