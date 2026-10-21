"""config/settings.py must assign each top-level name only once (issue #77)."""

import ast
from collections import Counter
from pathlib import Path
from unittest import TestCase

SETTINGS = Path(__file__).resolve().parents[1] / 'settings.py'


def _top_level_names(tree: ast.Module):
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                yield target.id


class SettingsDuplicateAssignmentTests(TestCase):
    def test_no_duplicate_top_level_assignments(self):
        tree = ast.parse(SETTINGS.read_text(encoding='utf-8'))
        counts = Counter(_top_level_names(tree))
        duplicates = sorted(name for name, count in counts.items() if count > 1)
        self.assertEqual(duplicates, [], f'Assigned more than once in settings.py: {duplicates}')
