"""Input collection helpers."""
from pathlib import Path
from .engine import Component, Finding, parse_manifest, analyze_workflow

MANIFESTS = {"requirements.txt", "requirements-dev.txt", "package.json", "package-lock.json", "npm-shrinkwrap.json", "pyproject.toml"}


def scan_path(path: str) -> tuple[list[Component], list[Finding], list[str]]:
    root = Path(path).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(root)
    files = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file() and (p.name in MANIFESTS or (".github/workflows" in p.as_posix() and p.suffix.lower() in {".yml", ".yaml"})))
    components: list[Component] = []
    findings: list[Finding] = []
    scanned: list[str] = []
    for file in files:
        try:
            rel = str(file.relative_to(root)) if root.is_dir() else file.name
            if file.name in MANIFESTS:
                parsed, extra = parse_manifest(file.name, file.read_text(encoding="utf-8"))
                components.extend(parsed)
                findings.extend(extra)
            elif ".github/workflows" in file.as_posix():
                findings.extend(analyze_workflow(file.read_text(encoding="utf-8"), rel))
            scanned.append(rel)
        except (UnicodeDecodeError, ValueError):
            continue
    return components, findings, scanned
