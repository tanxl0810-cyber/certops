"""Package public sources and reviewed screenshots without Git history or local secrets."""
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import zipfile


def main():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location('release_check', root / 'ops' / 'check-release.py')
    check = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(check)
    issues = check.findings(root)
    if issues:
        raise SystemExit('Release source check failed:\n' + '\n'.join(issues))
    directory = root / 'dist'
    directory.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    archive = directory / f'CertOps-source-{stamp}.zip'
    files = check.release_files(root)
    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in files:
            bundle.write(path, 'CertOps/' + path.relative_to(root).as_posix())
    print(f'Packaged {len(files)} public source files: dist/{archive.name}')


if __name__ == '__main__':
    main()
