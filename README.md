# SupplyChainSentry

**Offline-first software supply-chain and dependency risk analyzer.**

SupplyChainSentry inspects dependency manifests, npm lockfiles and GitHub Actions workflow YAML for supply-chain risk signals. It provides a Python engine, CLI, FastAPI service, browser dashboard and CycloneDX 1.5 SBOM export.

## Capabilities

- Parse Python requirements and `pyproject.toml` dependencies.
- Parse npm `package.json`, package-lock v2/v3 and npm shrinkwrap package entries.
- Flag unpinned direct dependencies, known lookalike names from a small transparent watchlist, duplicate inputs and risky package lifecycle commands.
- Review GitHub Actions for mutable action refs, privileged `pull_request_target` triggers and `write-all` permissions.
- Generate CycloneDX JSON SBOMs.
- Scan a project folder using the CLI; output JSON or human-readable results.
- Serve the dashboard and API locally.

## Quick start

Python 3.10+ is required.

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m uvicorn supplychainsentry.api:app --reload
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000) and [API docs](http://127.0.0.1:8000/docs).

## CLI

```powershell
scs scan . --format text
scs scan . --format json --output report.json
scs scan . --sbom sbom.cyclonedx.json
```

Or without installing the entry point:

```powershell
python -m supplychainsentry.cli scan .
```

## API

- `GET /api/health`
- `POST /api/analyze` — JSON body: `{"filename":"requirements.txt","content":"requests==2.31.0"}`
- `POST /api/sbom` — same body, optional `project_name`.

Interactive OpenAPI docs: `/docs`.

## Detection rules

See [docs/rules.md](docs/rules.md) for rule IDs, severity and limitations.

## Security and accuracy boundaries

- Offline static analysis only. No AWS, package registry, GitHub or vulnerability database credentials are used.
- No package code, install hooks or workflow steps are executed.
- The lookalike watchlist is intentionally small and heuristic. A match is a review signal, not proof of typosquatting or malware.
- This version does not perform live CVE/OSV matching, full dependency resolution, package provenance verification, signature validation or malware analysis.
- The risk score is a simple prioritization heuristic, not a probability or a compliance result.
- CycloneDX output contains components extracted from supplied inputs; it is not a claim of complete transitive inventory when a manifest does not provide one.

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

## Roadmap

- Optional OSV advisory enrichment with explicit online mode.
- Provenance and artifact attestation checks.
- Broader ecosystem lockfile coverage.
- Dependency graph visualization and change-to-change drift reports.

## License

MIT
