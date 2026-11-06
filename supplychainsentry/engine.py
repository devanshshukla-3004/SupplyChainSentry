"""Offline-first dependency manifest analysis and CycloneDX SBOM generation."""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

KNOWN_CONFUSABLES = {
    "reqeusts": "requests", "requets": "requests", "colourama": "colorama",
    "python-dateutilx": "python-dateutil", "urllib": "urllib3",
    "crossenv": "cross-env", "lodahs": "lodash", "expresss": "express",
    "typscript": "typescript", "reactt": "react",
}
HIGH_RISK_SCRIPTS = ("curl ", "wget ", "powershell", "Invoke-WebRequest", "bash -c", "sh -c", "base64 -d")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


@dataclass
class Component:
    name: str
    version: str = ""
    ecosystem: str = "unknown"
    direct: bool = True
    source: str = ""
    purl: str = ""

    def __post_init__(self) -> None:
        self.name = self.name.strip()
        self.version = str(self.version or "").strip()
        if not self.purl and self.name:
            ecosystem = "pypi" if self.ecosystem == "pypi" else "npm" if self.ecosystem == "npm" else self.ecosystem
            self.purl = f"pkg:{ecosystem}/{self.name.lower()}@{self.version}" if self.version else f"pkg:{ecosystem}/{self.name.lower()}"


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    description: str
    component: str = ""
    evidence: str = ""
    recommendation: str = ""


def _finding(rule: str, severity: str, title: str, desc: str, component: str = "", evidence: str = "", fix: str = "") -> Finding:
    return Finding(rule, severity, title, desc, component, evidence, fix)


def parse_requirements(text: str, source: str = "requirements.txt") -> list[Component]:
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-", "git+", "http://", "https://")):
            continue
        line = line.split(";", 1)[0].strip()
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*(.*)$", line)
        if not match:
            continue
        name, spec = match.groups()
        version_match = re.match(r"^(?:==|===)([^,\s]+)$", spec.strip())
        version = version_match.group(1) if version_match else ""
        out.append(Component(name, version, "pypi", True, source))
    return out


def parse_package_json(data: dict[str, Any], source: str = "package.json") -> list[Component]:
    out: list[Component] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(section, {})
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            spec = str(spec)
            exact = spec[1:] if spec.startswith(("^", "~")) else spec
            version = exact if re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][\w.-]+)?", exact) else ""
            out.append(Component(str(name), version, "npm", True, f"{source}:{section}"))
    return out


def parse_package_lock(data: dict[str, Any], source: str = "package-lock.json") -> list[Component]:
    out: list[Component] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, item in packages.items():
            if not path or not isinstance(item, dict):
                continue
            name = item.get("name") or path.split("node_modules/")[-1]
            if not name or name == path:
                continue
            out.append(Component(str(name), str(item.get("version", "")), "npm", not path.count("node_modules/") > 1, source))
    elif isinstance(data.get("dependencies"), dict):
        def walk(deps: dict[str, Any], direct: bool = True) -> None:
            for name, item in deps.items():
                if not isinstance(item, dict):
                    continue
                out.append(Component(name, str(item.get("version", "")), "npm", direct, source))
                children = item.get("dependencies")
                if isinstance(children, dict):
                    walk(children, False)
        walk(data["dependencies"])
    return out


def parse_pyproject(data: dict[str, Any], source: str = "pyproject.toml") -> list[Component]:
    project = data.get("project", {}) if isinstance(data, dict) else {}
    deps = project.get("dependencies", []) if isinstance(project, dict) else []
    return parse_requirements("\n".join(str(x) for x in deps), source)


def parse_manifest(filename: str, content: str) -> tuple[list[Component], list[Finding]]:
    lower = filename.lower()
    findings: list[Finding] = []
    if lower.endswith("requirements.txt") or lower.endswith(".in"):
        return parse_requirements(content, filename), findings
    if lower.endswith("package.json"):
        data = json.loads(content)
        components = parse_package_json(data, filename)
        scripts = data.get("scripts", {}) if isinstance(data, dict) else {}
        if isinstance(scripts, dict):
            for script, command in scripts.items():
                command = str(command)
                if any(token.lower() in command.lower() for token in HIGH_RISK_SCRIPTS):
                    findings.append(_finding("SCS006", "high", "Risky package lifecycle command", "A package script contains a shell or remote-download pattern that deserves manual review.", filename, f"{script}: {command[:180]}", "Inspect the command, pin downloaded artifacts and avoid executing untrusted remote content."))
        return components, findings
    if lower.endswith("package-lock.json") or lower.endswith("npm-shrinkwrap.json"):
        return parse_package_lock(json.loads(content), filename), findings
    if lower.endswith("pyproject.toml"):
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore
        return parse_pyproject(tomllib.loads(content), filename), findings
    raise ValueError(f"Unsupported manifest: {filename}")


def analyze_components(components: list[Component], extra_findings: list[Finding] | None = None) -> dict[str, Any]:
    findings = list(extra_findings or [])
    seen: set[tuple[str, str, str]] = set()
    for comp in components:
        if not NAME_RE.match(comp.name):
            findings.append(_finding("SCS001", "high", "Unusual package identifier", "The dependency name contains unexpected characters.", comp.name, comp.name, "Verify the package name and its source before installation."))
        key = (comp.ecosystem, comp.name.lower(), comp.version)
        if key in seen:
            findings.append(_finding("SCS002", "low", "Duplicate dependency entry", "The same package and version appears more than once in the supplied inputs.", comp.name, comp.purl, "Deduplicate manifest inputs and review dependency ownership."))
        seen.add(key)
        if comp.name.lower() in KNOWN_CONFUSABLES:
            target = KNOWN_CONFUSABLES[comp.name.lower()]
            findings.append(_finding("SCS003", "critical", "Known lookalike package name", f"This name matches a built-in lookalike watchlist entry for {target}. This is a lead, not proof of maliciousness.", comp.name, comp.name, f"Confirm the intended package with the maintainer and replace it with {target} if this is a typo."))
        if comp.direct and not comp.version:
            findings.append(_finding("SCS004", "medium", "Dependency version is not exact", "The manifest entry is not pinned to an exact version; resolution may change between builds.", comp.name, comp.source, "Use a lockfile and reproducible installation; review and commit lockfile changes."))
    counts = {s: sum(1 for f in findings if f.severity == s) for s in ("critical", "high", "medium", "low", "info")}
    score = min(100, counts["critical"] * 25 + counts["high"] * 15 + counts["medium"] * 7 + counts["low"] * 2)
    return {
        "summary": {"components": len(components), "direct": sum(c.direct for c in components), "transitive": sum(not c.direct for c in components), "findings": len(findings), "risk_score": score, "severity": counts},
        "components": [asdict(c) for c in components],
        "findings": [asdict(f) for f in findings],
        "analysis_mode": "offline-static",
        "limitations": ["Name heuristics are indicators, not proof of maliciousness.", "No dependency code is executed.", "No live vulnerability database is queried by the offline analyzer.", "Risk score is a prioritization heuristic, not a probability."],
    }


def generate_cyclonedx(components: list[Component], project_name: str = "analyzed-project") -> dict[str, Any]:
    bom_components = []
    for c in components:
        item: dict[str, Any] = {"type": "library", "name": c.name, "bom-ref": c.purl or f"pkg:generic/{c.name}"}
        if c.version:
            item["version"] = c.version
        if c.ecosystem:
            item["purl"] = c.purl
        bom_components.append(item)
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "metadata": {"component": {"type": "application", "name": project_name}}, "components": bom_components}


def analyze_workflow(text: str, filename: str = "workflow.yml") -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    for idx, line in enumerate(lines, 1):
        stripped = line.strip()
        if re.search(r"uses:\s*[^@\s]+@(main|master|HEAD)\b", stripped):
            findings.append(_finding("SCS007", "high", "GitHub Action uses a moving reference", "A workflow action is referenced by a mutable branch or HEAD instead of an immutable commit SHA.", filename, f"line {idx}: {stripped}", "Pin third-party actions to a verified full commit SHA and update them deliberately."))
        if re.search(r"pull_request_target", stripped):
            findings.append(_finding("SCS008", "high", "Privileged pull_request_target trigger", "This trigger can expose a privileged workflow context to untrusted pull request content if checkout and execution are unsafe.", filename, f"line {idx}: {stripped}", "Avoid executing fork-controlled code in privileged contexts; minimize permissions and separate untrusted validation."))
        if re.search(r"permissions:\s*write-all", stripped):
            findings.append(_finding("SCS009", "high", "Workflow grants write-all permissions", "The workflow requests broad write permissions.", filename, f"line {idx}: {stripped}", "Declare least-privilege workflow permissions at job or workflow scope."))
    return findings
