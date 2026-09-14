"""
IPsecGuard AI - FastAPI Main Backend Server
Provides REST APIs for:
- IPsec configuration security analysis
- PCAP/PCAPNG packet capture upload & inspection
- AI-assisted protocol classification
- Threat matrix and security association reporting
- Dual configuration comparison
- Executive & technical report generation
"""

import os
import uuid
import time
from typing import Dict, Any, Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel

from sample_data import SAMPLE_CONFIGURATIONS, generate_sample_pcap
from analyzer import ProtocolAnalyzer
from security_engine import SecurityAssessmentEngine
from report_generator import ReportGenerator

app = FastAPI(
    title="IPsecGuard AI Backend",
    description="AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework",
    version="1.0.0"
)

# Enable CORS for local React/Vite development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# In-memory storage for analysis reports
ANALYSIS_STORE: Dict[str, Any] = {}

# Ensure default sample PCAP files exist on startup
SAMPLE_PCAP_PATH = os.path.join(UPLOAD_DIR, "enterprise_sample.pcap")
LEGACY_PCAP_PATH = os.path.join(UPLOAD_DIR, "legacy_sample.pcap")
try:
    generate_sample_pcap(SAMPLE_PCAP_PATH, "strong-enterprise")
    generate_sample_pcap(LEGACY_PCAP_PATH, "legacy-vpn")
except Exception as e:
    print(f"Warning generating initial PCAPs: {e}")


class VPNConfigModel(BaseModel):
    ike_version: str = "IKEv2"
    mode: str = "Tunnel"
    encryption: str = "AES-256"
    authentication: str = "HMAC-SHA256"
    dh_group: str = "Group 14"
    pfs: bool = True
    ip_version: str = "IPv4"
    traffic_type: str = "Web Browsing"
    replay_protection: bool = True
    key_lifetime: int = 28800


class CompareRequestModel(BaseModel):
    config_a: VPNConfigModel
    config_b: VPNConfigModel
    label_a: Optional[str] = "Configuration A"
    label_b: Optional[str] = "Configuration B"


@app.get("/api/health")
def health_check():
    return {
        "status": "online",
        "service": "IPsecGuard AI",
        "timestamp": time.time(),
        "version": "1.0.0"
    }


@app.get("/api/sample-configurations")
def get_sample_configurations():
    """Returns the 5 built-in demo datasets for instant hackathon demonstration."""
    return {
        "count": len(SAMPLE_CONFIGURATIONS),
        "samples": SAMPLE_CONFIGURATIONS
    }


@app.get("/api/download-sample-pcap/{sample_id}")
def download_sample_pcap(sample_id: str = "strong-enterprise"):
    """Downloads a synthesized valid binary PCAP file for offline testing."""
    target_path = os.path.join(UPLOAD_DIR, f"{sample_id}.pcap")
    generate_sample_pcap(target_path, sample_id)
    return FileResponse(
        path=target_path,
        filename=f"ipsec_{sample_id}.pcap",
        media_type="application/vnd.tcpdump.pcap"
    )


def _perform_analysis(config_dict: Dict[str, Any], pcap_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    analysis_id = f"IPSEC-{uuid.uuid4().hex[:8].upper()}"
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    # 1. Run AI Classification Engine
    ai_classification = ProtocolAnalyzer.classify_and_score_confidence(config_dict, pcap_info)

    # 2. Run Security Assessment Engine
    security_assessment = SecurityAssessmentEngine.assess_configuration(config_dict)

    # 3. Assemble Realistic Security Association (SA) Data
    matched_sample = next(
        (s for s in SAMPLE_CONFIGURATIONS if s["config"]["encryption"] == config_dict.get("encryption") and s["config"]["ike_version"] == config_dict.get("ike_version")),
        SAMPLE_CONFIGURATIONS[0]
    )
    
    inbound_spi = pcap_info["detected_spis"][0] if pcap_info and pcap_info.get("detected_spis") else matched_sample["traffic_metrics"]["inbound_spi"]
    outbound_spi = pcap_info["detected_spis"][1] if pcap_info and len(pcap_info.get("detected_spis", [])) > 1 else matched_sample["traffic_metrics"]["outbound_spi"]
    src_ip = pcap_info["source_ips"][0] if pcap_info and pcap_info.get("source_ips") else matched_sample["traffic_metrics"]["source_ip"]
    dest_ip = pcap_info["dest_ips"][0] if pcap_info and pcap_info.get("dest_ips") else matched_sample["traffic_metrics"]["dest_ip"]

    security_association = {
        "inbound_spi": inbound_spi,
        "outbound_spi": outbound_spi,
        "mode": config_dict.get("mode", "Tunnel"),
        "source_gateway": src_ip,
        "destination_gateway": dest_ip,
        "encryption": config_dict.get("encryption", "AES-256"),
        "authentication": config_dict.get("authentication", "HMAC-SHA256"),
        "dh_group": config_dict.get("dh_group", "Group 14"),
        "pfs_status": "Enabled" if config_dict.get("pfs", True) else "Disabled",
        "replay_protection": "Enabled (Window: 64)" if config_dict.get("replay_protection", True) else "Disabled",
        "key_lifetime": f"{config_dict.get('key_lifetime', 28800)} seconds ({config_dict.get('key_lifetime', 28800) // 3600}h)"
    }

    # 4. Traffic Metrics
    if pcap_info:
        traffic_metrics = {
            "packet_count": pcap_info["total_packets"],
            "avg_packet_size": pcap_info["avg_packet_size"],
            "encrypted_ratio": pcap_info["encrypted_ratio"],
            "esp_detected": pcap_info["esp_detected"],
            "ah_detected": pcap_info["ah_detected"],
            "ike_detected": pcap_info["ike_detected"],
            "source_ip": src_ip,
            "dest_ip": dest_ip,
            "protocol_breakdown": {
                "ESP": pcap_info["esp_packets"],
                "IKE": pcap_info["ike_packets"],
                "NAT-T": pcap_info["nat_t_packets"],
                "Other": pcap_info["other_packets"]
            },
            "size_distribution": pcap_info["size_distribution"]
        }
    else:
        traffic_metrics = matched_sample["traffic_metrics"]

    analysis_payload = {
        "analysis_id": analysis_id,
        "timestamp": timestamp,
        "config": config_dict,
        "security_assessment": security_assessment,
        "ai_classification": ai_classification,
        "security_association": security_association,
        "traffic_metrics": traffic_metrics,
        "pcap_source": bool(pcap_info)
    }

    # 5. Generate Full Reports
    reports = ReportGenerator.generate_full_report(analysis_payload)
    analysis_payload["reports"] = reports

    # Store in memory
    ANALYSIS_STORE[analysis_id] = analysis_payload
    return analysis_payload


@app.post("/api/analyze")
def analyze_configuration(config: VPNConfigModel):
    """Analyzes a user-defined or sample IPsec VPN configuration."""
    return _perform_analysis(config.model_dump())


@app.post("/api/upload-pcap")
async def upload_pcap(file: UploadFile = File(...)):
    """
    Accepts .pcap or .pcapng file, parses headers safely, extracts detected fields,
    identifies what requires deeper payload decryption, and runs security evaluation.
    """
    if not file.filename.endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(status_code=400, detail="Only .pcap and .pcapng files are supported.")

    file_path = os.path.join(UPLOAD_DIR, f"{uuid.uuid4().hex}_{file.filename}")
    with open(file_path, "wb") as buffer:
        content = await file.read()
        buffer.write(content)

    try:
        pcap_info = ProtocolAnalyzer.parse_pcap_file(file_path)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Failed to parse PCAP: {str(e)}")

    # Map detected fields to inferred configuration
    detected_ike = pcap_info.get("detected_ike_version") or "IKEv2"
    detected_ip = pcap_info.get("detected_ip_version") or "IPv4"

    # Default fallback values for fields that cannot be decrypted without secret keys
    config_dict = {
        "ike_version": detected_ike,
        "mode": "Tunnel" if pcap_info.get("esp_detected") else "Transport",
        "encryption": "AES-256",  # Tagged as inferred in AI analysis
        "authentication": "HMAC-SHA256",  # Tagged as inferred in AI analysis
        "dh_group": "Group 14",
        "pfs": True,
        "ip_version": detected_ip,
        "traffic_type": "Web Browsing",
        "replay_protection": True,
        "key_lifetime": 28800
    }

    analysis_res = _perform_analysis(config_dict, pcap_info)
    analysis_res["pcap_summary"] = {
        "filename": file.filename,
        "file_size_bytes": len(content),
        "total_packets": pcap_info["total_packets"],
        "esp_packets": pcap_info["esp_packets"],
        "ike_packets": pcap_info["ike_packets"],
        "detected_spis": pcap_info["detected_spis"],
        "detected_fields": [
            {"field": "IPsec Encapsulation (ESP/AH)", "status": "DETECTED", "value": f"ESP: {pcap_info['esp_packets']} packets"},
            {"field": "IKE Negotiation Port 500", "status": "DETECTED" if pcap_info['ike_detected'] else "NOT OBSERVED", "value": f"{pcap_info['ike_packets']} frames"},
            {"field": "Security Parameter Index (SPI)", "status": "DETECTED", "value": ", ".join(pcap_info["detected_spis"][:3]) or "None"},
            {"field": "IP Stack Version", "status": "DETECTED", "value": detected_ip},
            {"field": "Payload Encryption Cipher", "status": "REDUCES TO CIPHERTEXT", "value": "Requires SA Pre-Shared Key / Private Key for Decryption"},
            {"field": "Internal Subnet Addressing", "status": "PROTECTED BY TUNNEL", "value": "Encapsulated inside ESP payload"}
        ]
    }

    return analysis_res


@app.get("/api/report/{analysis_id}")
def get_report(analysis_id: str, format: str = "json"):
    """Fetches stored analysis report or returns downloadable HTML document."""
    if analysis_id not in ANALYSIS_STORE:
        raise HTTPException(status_code=404, detail="Analysis report ID not found.")

    data = ANALYSIS_STORE[analysis_id]
    if format == "html":
        return HTMLResponse(content=data["reports"]["html_report"])
    return data["reports"]


@app.post("/api/compare")
def compare_configurations(req: CompareRequestModel):
    """
    Compares two VPN configurations side-by-side.
    Calculates differential scores, identifies security gaps, and provides comparative AI explanation.
    """
    res_a = _perform_analysis(req.config_a.model_dump())
    res_b = _perform_analysis(req.config_b.model_dump())

    score_a = res_a["security_assessment"]["score"]
    score_b = res_b["security_assessment"]["score"]

    diff = score_b - score_a
    winner = req.label_b if diff > 0 else (req.label_a if diff < 0 else "Equal")

    comparison_details = [
        {
            "parameter": "Security Score",
            "val_a": f"{score_a}/100",
            "val_b": f"{score_b}/100",
            "winner": winner
        },
        {
            "parameter": "Risk Tier",
            "val_a": res_a["security_assessment"]["risk_level"],
            "val_b": res_b["security_assessment"]["risk_level"],
            "winner": "Lower Risk"
        },
        {
            "parameter": "IKE Protocol",
            "val_a": req.config_a.ike_version,
            "val_b": req.config_b.ike_version,
            "comparison": "IKEv2 has superior anti-DoS cookie mechanism and resilient state machine."
        },
        {
            "parameter": "Confidentiality Cipher",
            "val_a": req.config_a.encryption,
            "val_b": req.config_b.encryption,
            "comparison": "AES-256 and AES-GCM offer superior security margin over AES-128 and CBC modes."
        },
        {
            "parameter": "Authentication / Integrity",
            "val_a": req.config_a.authentication,
            "val_b": req.config_b.authentication,
            "comparison": "SHA-256/384/512 prevents collision attacks inherent to deprecated SHA-1/MD5."
        },
        {
            "parameter": "Diffie-Hellman Group",
            "val_a": req.config_a.dh_group,
            "val_b": req.config_b.dh_group,
            "comparison": "Groups 14, 19, 20 withstand discrete log attacks; Group 2 is vulnerable to Logjam."
        },
        {
            "parameter": "Perfect Forward Secrecy (PFS)",
            "val_a": "Enabled" if req.config_a.pfs else "Disabled",
            "val_b": "Enabled" if req.config_b.pfs else "Disabled",
            "comparison": "PFS prevents retroactive decryption if long-term private keys are ever leaked."
        }
    ]

    return {
        "label_a": req.label_a,
        "label_b": req.label_b,
        "score_a": score_a,
        "score_b": score_b,
        "score_delta": diff,
        "superior_configuration": winner,
        "comparison_matrix": comparison_details,
        "summary": f"{req.label_b} scores {abs(diff)} points {'higher' if diff > 0 else 'lower'} than {req.label_a}."
    }


# Serve built React frontend if dist directory exists
FRONTEND_DIST = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "dist"))
if os.path.exists(FRONTEND_DIST):
    from fastapi.staticfiles import StaticFiles
    app.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True), name="static_frontend")

