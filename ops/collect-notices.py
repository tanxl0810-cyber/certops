"""Collect installed Python package metadata and original license files."""
import argparse
from importlib import metadata
from pathlib import Path
import re


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    sections = ['Python third-party notices\nGenerated from the installed distributions.\n']
    for distribution in sorted(metadata.distributions(), key=lambda item: item.metadata['Name'].lower()):
        item = distribution.metadata
        expression = item.get('License-Expression') or item.get('License') or 'See original license files'
        sections.append(f'\n{"=" * 72}\n{item["Name"]} {distribution.version}\nLicense: {expression}\n')
        for url in item.get_all('Project-URL', []):
            sections.append(f'{url}\n')
        for relative in distribution.files or []:
            if not re.match(r'^(licen[cs]e|copying|notice)(\.|-|$)', relative.name, re.I):
                continue
            path = distribution.locate_file(relative)
            if path.is_file():
                sections.append(f'\n--- {relative.name} ---\n{path.read_text(encoding="utf-8", errors="replace")}\n')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(''.join(sections), encoding='utf-8')


if __name__ == '__main__':
    main()
