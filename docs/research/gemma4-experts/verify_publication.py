#!/usr/bin/env python3
"""Verify durable files and offline reproduction; no GPU or credentials needed."""
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    manifest = json.loads((ROOT / 'evidence-manifest.json').read_text())
    for name, entry in manifest['files'].items():
        path = ROOT / name
        assert path.is_file(), name
        assert path.stat().st_size == entry['bytes'], name
        assert digest(path) == entry['sha256'], name

    for path in ROOT.glob('*.md'):
        for target in re.findall(r'\]\(([^)]+)\)', path.read_text()):
            if not target.startswith(('http://', 'https://', '#')):
                assert (path.parent / target).exists(), (path.name, target)

    output_names = {
        '2026-10-06': ('memory-results.json', 'cache-by-context.csv',
                       'lora-by-rank.csv', 'illustrative-scenarios.csv'),
        'contest-4l4-32k': ('contest-results.json', 'cache-by-context.csv',
                          'lora-by-rank.csv', 'scenarios.csv'),
    }
    scripts = {'2026-10-06': 'calculate_memory.py',
               'contest-4l4-32k': 'calculate_contest.py'}
    with tempfile.TemporaryDirectory(prefix='gemma4-publication-') as tmp:
        copy = Path(tmp) / 'research'
        shutil.copytree(ROOT, copy)
        for folder, script in scripts.items():
            subprocess.run([sys.executable, str(copy / folder / script)],
                           check=True, capture_output=True, text=True)
            for name in output_names[folder]:
                assert digest(copy / folder / name) == digest(ROOT / folder / name), (folder, name)
    print(json.dumps({'artifact_hashes': len(manifest['files']),
                      'offline_calculators': 2, 'reproduced_outputs': 8,
                      'local_document_links': 'ok', 'status': 'ok'}))


if __name__ == '__main__':
    main()
