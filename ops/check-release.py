"""Check public source candidates without printing matched credential values."""
import ipaddress
import os
from pathlib import Path
import re
import subprocess

ROOT_FILES = {'.gitignore', '.dockerignore', '.gitattributes', '.env.example',
              'Dockerfile', 'LICENSE', 'NOTICE', 'README.md', 'SERVICES.md',
              'SECURITY.md', 'CONTRIBUTING.md', 'THIRD_PARTY_NOTICES.md',
              'compose.yaml', 'requirements.txt', 'CHANGELOG.md'}
SOURCE_DIRS = {'app', 'ui', 'ops', 'tests', 'deploy', 'docs', '.github', 'third_party'}
SKIP_DIRS = {'.git', '.venv', 'venv', '__pycache__', 'node_modules', '.pytest_cache',
             '.ruff_cache', 'private', 'backups', 'data', 'dist'}
SOURCE_SUFFIXES = {'.py', '.js', '.mjs', '.vue', '.css', '.html', '.json', '.md',
                   '.yaml', '.yml', '.sh', '.example', '.toml', '.txt'}
DOCUMENT_IMAGES = {'docs/images/overview.png', 'docs/images/relationships.png',
                   'docs/images/deployment-preview.png', 'docs/images/tasks.png'}
PATTERNS = {
    'private-key': re.compile(r'-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----\s+[A-Za-z0-9+/=]{32,}'),
    'cloud-access-key': re.compile(r'\b(?:LTAI[A-Za-z0-9]{16,32}|(?:AKIA|ASIA)[A-Z0-9]{16})\b'),
    'github-token': re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b'),
    'feishu-webhook': re.compile(r'https://open\.feishu\.cn/open-apis/bot/v2/hook/[0-9a-f-]{32,}', re.I),
    'personal-windows-path': re.compile(r'(?:C:[/\\]+User[s][/\\]+|/mnt/c/User[s]/)', re.I),
}
IP = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')
PRIVATE_NETWORKS = [ipaddress.ip_network(value) for value in
                    ((0x0A000000, 8), (0xAC100000, 12), (0xC0A80000, 16))]


def release_files(root):
    root = Path(root)
    files = []
    for directory, names, filenames in os.walk(root):
        relative_dir = Path(directory).relative_to(root)
        names[:] = sorted(name for name in names if name not in SKIP_DIRS
            and not (relative_dir == Path('app') and name == 'static')
            and (relative_dir != Path('.') or name in SOURCE_DIRS))
        for name in sorted(filenames):
            path = Path(directory) / name
            relative = path.relative_to(root)
            if path.is_symlink():
                raise ValueError(f'Symlink is not a release source file: {relative.as_posix()}')
            if len(relative.parts) == 1:
                if name in ROOT_FILES:
                    files.append(path)
            elif (relative.parts[0] in SOURCE_DIRS and (path.suffix in SOURCE_SUFFIXES
                  or relative.as_posix() in DOCUMENT_IMAGES)
                  and not name.startswith('.env') and not name.endswith('.incomplete')):
                files.append(path)
    return sorted(files)


def plain_png(path):
    """Approved screenshots allow pixel data only, without text/EXIF metadata."""
    data = path.read_bytes()
    if len(data) > 3 * 1024 * 1024 or data[:8] != b'\x89PNG\r\n\x1a\n':
        return False
    position = 8
    while position + 12 <= len(data):
        length = int.from_bytes(data[position:position + 4], 'big')
        kind = data[position + 4:position + 8]
        if kind not in (b'IHDR', b'IDAT', b'IEND') or position + length + 12 > len(data):
            return False
        position += length + 12
        if kind == b'IEND':
            return length == 0 and position == len(data)
    return False


def findings(root):
    issues = []
    for path in release_files(root):
        relative = path.relative_to(root).as_posix()
        if relative in DOCUMENT_IMAGES:
            if not plain_png(path):
                issues.append(f'{relative}: invalid PNG structure or unapproved metadata')
            # Pixel content is synthetic and reviewed visually; text scanning is separate.
            continue
        try:
            content = path.read_text(encoding='utf-8')
        except (UnicodeError, OSError):
            issues.append(f'{relative}: not readable UTF-8 source')
            continue
        for number, line in enumerate(content.splitlines(), 1):
            for label, pattern in PATTERNS.items():
                if pattern.search(line):
                    issues.append(f'{relative}:{number}: {label}')
            for match in IP.finditer(line):
                try:
                    address = ipaddress.ip_address(match.group())
                except ValueError:
                    continue
                if any(address in network for network in PRIVATE_NETWORKS):
                    issues.append(f'{relative}:{number}: private-network-example')
        # PEM bodies span lines, unlike placeholder strings used in source code.
        if PATTERNS['private-key'].search(content):
            issues.append(f'{relative}: private-key-block')
    return issues


def main():
    root = Path(__file__).resolve().parents[1]
    issues = findings(root)
    if (root / '.git').exists():
        tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode().split('\0')
        candidates = {path.relative_to(root).as_posix() for path in release_files(root)}
        for name in tracked:
            if name and name not in candidates:
                issues.append(f'{name}: tracked file is outside the public source allowlist')
    if issues:
        print('\n'.join(issues))
        raise SystemExit(1)
    print(f'PASS public source check: {len(release_files(root))} files; no matched values were printed')


if __name__ == '__main__':
    main()
