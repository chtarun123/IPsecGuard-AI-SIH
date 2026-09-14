"""
Automated Integration Test Suite for IPsecGuard AI
Tests all API endpoints, scoring engine, report generator, PCAP parsing, and configuration comparison.
"""

from main import app
from fastapi.testclient import TestClient

def test_all():
    client = TestClient(app)

    print("=== TEST 1: HEALTH CHECK ===")
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "online"
    print("[PASS] PASSED: Health check OK")

    print("\n=== TEST 2: SAMPLE DATASETS ===")
    r = client.get("/api/sample-configurations")
    assert r.status_code == 200
    samples = r.json()["samples"]
    assert len(samples) == 5
    print("[PASS] PASSED: 5 sample datasets loaded")

    print("\n=== TEST 3: STRONG ENTERPRISE EVALUATION ===")
    strong_cfg = samples[0]["config"]
    r_strong = client.post("/api/analyze", json=strong_cfg)
    assert r_strong.status_code == 200
    res_s = r_strong.json()
    score_s = res_s["security_assessment"]["score"]
    risk_s = res_s["security_assessment"]["risk_level"]
    assert score_s >= 85, f"Expected score >= 85, got {score_s}"
    assert risk_s == "LOW"
    analysis_id = res_s["analysis_id"]
    print(f"[PASS] PASSED: Strong VPN evaluated - Score: {score_s}/100, Risk: {risk_s}")

    print("\n=== TEST 4: LEGACY VPN EVALUATION ===")
    legacy_cfg = samples[1]["config"]
    r_legacy = client.post("/api/analyze", json=legacy_cfg)
    assert r_legacy.status_code == 200
    res_l = r_legacy.json()
    score_l = res_l["security_assessment"]["score"]
    risk_l = res_l["security_assessment"]["risk_level"]
    assert score_l < 50, f"Expected score < 50, got {score_l}"
    assert risk_l in ["HIGH", "CRITICAL"]
    print(f"[PASS] PASSED: Legacy VPN evaluated - Score: {score_l}/100, Risk: {risk_l}")

    print("\n=== TEST 5: REPORT GENERATION (JSON & HTML) ===")
    r_rep = client.get(f"/api/report/{analysis_id}")
    assert r_rep.status_code == 200
    assert "executive_report" in r_rep.json()
    r_html = client.get(f"/api/report/{analysis_id}?format=html")
    assert r_html.status_code == 200
    assert "<!DOCTYPE html>" in r_html.text
    print("[PASS] PASSED: Executive report JSON and formatted HTML export OK")

    print("\n=== TEST 6: PCAP UPLOAD ===")
    with open("uploads/enterprise_sample.pcap", "rb") as f:
        r_pcap = client.post(
            "/api/upload-pcap",
            files={"file": ("enterprise_sample.pcap", f, "application/vnd.tcpdump.pcap")}
        )
    assert r_pcap.status_code == 200
    res_p = r_pcap.json()
    assert res_p["traffic_metrics"]["esp_detected"] is True
    assert len(res_p["pcap_summary"]["detected_spis"]) > 0
    print(f"[PASS] PASSED: PCAP parsed successfully, {res_p['traffic_metrics']['packet_count']} packets detected")

    print("\n=== TEST 7: CONFIGURATION COMPARISON ===")
    r_comp = client.post("/api/compare", json={
        "config_a": legacy_cfg,
        "config_b": strong_cfg,
        "label_a": "Legacy VPN",
        "label_b": "Strong Enterprise VPN"
    })
    assert r_comp.status_code == 200
    res_c = r_comp.json()
    assert res_c["score_delta"] > 0
    assert res_c["superior_configuration"] == "Strong Enterprise VPN"
    print(f"[PASS] PASSED: Comparison completed, score delta: +{res_c['score_delta']} pts")

    print("\n=======================================================")
    print("ALL 7 INTEGRATION TESTS PASSED WITH ZERO ERRORS!")
    print("=======================================================")

if __name__ == "__main__":
    test_all()
