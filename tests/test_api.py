from fastapi.testclient import TestClient
from supplychainsentry.api import app
client = TestClient(app)

def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"

def test_analyze_api():
    r = client.post("/api/analyze", json={"filename":"requirements.txt","content":"reqeusts==1.0"})
    assert r.status_code == 200
    assert r.json()["summary"]["findings"] >= 1

def test_sbom_api():
    r = client.post("/api/sbom", json={"filename":"requirements.txt","content":"requests==2.31.0"})
    assert r.status_code == 200
    assert r.json()["bomFormat"] == "CycloneDX"

def test_bad_input():
    r = client.post("/api/analyze", json={"filename":"unknown.txt","content":"x"})
    assert r.status_code == 400
