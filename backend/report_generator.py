"""
IPsecGuard AI - Report Generation Engine
Generates Executive Security Reports, Technical Audit Breakdowns,
and downloadable self-contained HTML/PDF-ready security reports.
"""

import time
import uuid
from typing import Dict, Any

class ReportGenerator:
    """
    Assembles structured executive summaries, deep technical audits,
    and formatted downloadable audit reports.
    """

    @staticmethod
    def generate_full_report(analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        analysis_id = analysis_result.get("analysis_id", f"IPSEC-AUDIT-{uuid.uuid4().hex[:8].upper()}")
        timestamp = analysis_result.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()))
        
        config = analysis_result.get("config", {})
        security = analysis_result.get("security_assessment", {})
        ai = analysis_result.get("ai_classification", {})
        traffic = analysis_result.get("traffic_metrics", {})
        sa = analysis_result.get("security_association", {})

        # Executive Report Structure
        executive_report = {
            "title": "IPsec VPN Executive Security Summary",
            "analysis_id": analysis_id,
            "timestamp": timestamp,
            "security_score": security.get("score", 0),
            "risk_level": security.get("risk_level", "UNKNOWN"),
            "risk_summary": security.get("risk_summary", ""),
            "ai_confidence": ai.get("overall_confidence", 0.0),
            "protocol_summary": f"{config.get('ike_version', 'IKEv2')} {config.get('mode', 'Tunnel')} Mode ({config.get('encryption', 'AES-256')} / {config.get('authentication', 'SHA-256')})",
            "major_findings": [f for f in security.get("findings", []) if f.get("severity") in ["Critical", "High"]],
            "strengths": security.get("strengths", []),
            "weaknesses": security.get("weaknesses", []),
            "actionable_recommendations": security.get("recommendations", [])
        }

        # Technical Report Structure
        technical_report = {
            "analysis_id": analysis_id,
            "timestamp": timestamp,
            "target_configuration": config,
            "security_association": sa,
            "cryptographic_breakdown": {
                "ike_version": config.get("ike_version"),
                "mode": config.get("mode"),
                "encryption": config.get("encryption"),
                "authentication": config.get("authentication"),
                "dh_group": config.get("dh_group"),
                "pfs_enabled": config.get("pfs"),
                "replay_protection": config.get("replay_protection"),
                "key_lifetime_seconds": config.get("key_lifetime")
            },
            "ai_classification_evidence": ai.get("classifications", []),
            "traffic_telemetry": traffic,
            "detailed_findings": security.get("findings", []),
            "threat_matrix": security.get("threat_matrix", []),
            "metadata_exposure": security.get("metadata_exposure", {})
        }

        # Generate Standalone Downloadable HTML Report
        html_content = ReportGenerator._render_html_report(executive_report, technical_report)

        return {
            "analysis_id": analysis_id,
            "timestamp": timestamp,
            "executive_report": executive_report,
            "technical_report": technical_report,
            "html_report": html_content
        }

    @staticmethod
    def _render_html_report(exec_rep: Dict[str, Any], tech_rep: Dict[str, Any]) -> str:
        score = exec_rep["security_score"]
        score_color = "#10B981" if score >= 80 else ("#F59E0B" if score >= 60 else "#EF4444")
        
        findings_html = ""
        for f in tech_rep["detailed_findings"]:
            badge_color = "#EF4444" if f["severity"] == "Critical" else ("#F97316" if f["severity"] == "High" else ("#F59E0B" if f["severity"] == "Medium" else "#3B82F6"))
            findings_html += f"""
            <div style="background: #1e293b; border-left: 4px solid {badge_color}; padding: 12px 16px; margin-bottom: 12px; border-radius: 4px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <strong style="color: #f8fafc; font-size: 15px;">{f['finding']}</strong>
                    <span style="background: {badge_color}22; color: {badge_color}; border: 1px solid {badge_color}; padding: 2px 8px; border-radius: 12px; font-size: 12px; font-weight: bold;">{f['severity']}</span>
                </div>
                <p style="color: #94a3b8; margin: 4px 0; font-size: 13px;"><strong>Explanation:</strong> {f['explanation']}</p>
                <p style="color: #fca5a5; margin: 4px 0; font-size: 13px;"><strong>Impact:</strong> {f['impact']}</p>
                <p style="color: #6ee7b7; margin: 4px 0; font-size: 13px;"><strong>Remediation:</strong> {f['recommendation']}</p>
            </div>
            """

        threats_html = ""
        for t in tech_rep["threat_matrix"]:
            status_color = "#10B981" if t["status"] == "Mitigated" else ("#EF4444" if t["status"] == "Vulnerable" else "#F59E0B")
            threats_html += f"""
            <tr style="border-bottom: 1px solid #334155;">
                <td style="padding: 10px; color: #f8fafc;">{t['threat']}</td>
                <td style="padding: 10px;"><span style="color: {'#EF4444' if t['severity'] in ['Critical', 'High'] else '#94a3b8'};">{t['severity']}</span></td>
                <td style="padding: 10px; color: #94a3b8;">{t['likelihood']}</td>
                <td style="padding: 10px; color: #94a3b8;">{t['impact']}</td>
                <td style="padding: 10px;"><span style="color: {status_color}; font-weight: 600;">{t['status']}</span></td>
                <td style="padding: 10px; color: #cbd5e1; font-size: 12px;">{t['recommendation']}</td>
            </tr>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>IPsecGuard AI - Security Assessment Report ({exec_rep['analysis_id']})</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 40px; }}
        .container {{ max-width: 900px; margin: 0 auto; background: #111827; border-radius: 12px; border: 1px solid #1f2937; padding: 32px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5); }}
        .header {{ border-bottom: 2px solid #374151; padding-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }}
        .score-card {{ text-align: center; background: #1e293b; padding: 16px 24px; border-radius: 8px; border: 2px solid {score_color}; }}
        .score {{ font-size: 42px; font-weight: 800; color: {score_color}; margin: 0; }}
        .grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin: 24px 0; }}
        .card {{ background: #1e293b; padding: 16px; border-radius: 8px; border: 1px solid #334155; }}
        .card h4 {{ margin: 0 0 6px 0; color: #94a3b8; font-size: 12px; text-transform: uppercase; }}
        .card p {{ margin: 0; font-size: 16px; font-weight: 600; color: #f8fafc; }}
        h2 {{ color: #38bdf8; border-bottom: 1px solid #334155; padding-bottom: 8px; margin-top: 32px; font-size: 18px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; text-align: left; font-size: 13px; }}
        th {{ background: #1e293b; padding: 10px; color: #94a3b8; font-weight: 600; border-bottom: 2px solid #334155; }}
        .footer {{ margin-top: 40px; border-top: 1px solid #334155; padding-top: 16px; text-align: center; color: #64748b; font-size: 12px; }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <h1 style="margin: 0; color: #f8fafc; font-size: 24px;">IPsecGuard AI</h1>
            <p style="margin: 4px 0 0 0; color: #38bdf8; font-size: 14px;">AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework</p>
            <p style="margin: 4px 0 0 0; color: #64748b; font-size: 12px;">Report ID: {exec_rep['analysis_id']} | Generated: {exec_rep['timestamp']}</p>
        </div>
        <div class="score-card">
            <div class="score">{score} / 100</div>
            <div style="font-size: 13px; font-weight: bold; color: {score_color}; text-transform: uppercase;">{exec_rep['risk_level']} RISK</div>
        </div>
    </div>

    <div class="grid">
        <div class="card">
            <h4>IKE Version</h4>
            <p>{tech_rep['cryptographic_breakdown']['ike_version']}</p>
        </div>
        <div class="card">
            <h4>Encryption Suite</h4>
            <p>{tech_rep['cryptographic_breakdown']['encryption']}</p>
        </div>
        <div class="card">
            <h4>Integrity Algorithm</h4>
            <p>{tech_rep['cryptographic_breakdown']['authentication']}</p>
        </div>
        <div class="card">
            <h4>Diffie-Hellman Group</h4>
            <p>{tech_rep['cryptographic_breakdown']['dh_group']}</p>
        </div>
        <div class="card">
            <h4>Perfect Forward Secrecy</h4>
            <p style="color: {'#10B981' if tech_rep['cryptographic_breakdown']['pfs_enabled'] else '#EF4444'};">
                {'ENABLED' if tech_rep['cryptographic_breakdown']['pfs_enabled'] else 'DISABLED'}
            </p>
        </div>
        <div class="card">
            <h4>AI Confidence Metric</h4>
            <p style="color: #38bdf8;">{exec_rep['ai_confidence']}%</p>
        </div>
    </div>

    <h2>Executive Summary</h2>
    <p style="color: #cbd5e1; line-height: 1.6;">{exec_rep['risk_summary']}</p>

    <h2>Security Findings & Vulnerabilities</h2>
    {findings_html}

    <h2>Interactive Threat Matrix</h2>
    <table>
        <thead>
            <tr>
                <th>Threat Vector</th>
                <th>Severity</th>
                <th>Likelihood</th>
                <th>Impact</th>
                <th>Mitigation Status</th>
                <th>Actionable Recommendation</th>
            </tr>
        </thead>
        <tbody>
            {threats_html}
        </tbody>
    </table>

    <h2>Security Association (SA) Telemetry</h2>
    <div class="grid" style="grid-template-columns: repeat(2, 1fr);">
        <div class="card">
            <h4>Inbound SPI</h4>
            <p>{tech_rep['security_association'].get('inbound_spi', '0x8F3C92A1')}</p>
        </div>
        <div class="card">
            <h4>Outbound SPI</h4>
            <p>{tech_rep['security_association'].get('outbound_spi', '0x4E12B07D')}</p>
        </div>
        <div class="card">
            <h4>Replay Window Protection</h4>
            <p>{'ACTIVE (64-packet window)' if tech_rep['cryptographic_breakdown']['replay_protection'] else 'DISABLED (Vulnerable)'}</p>
        </div>
        <div class="card">
            <h4>SA Key Lifetime</h4>
            <p>{tech_rep['cryptographic_breakdown']['key_lifetime_seconds']} seconds</p>
        </div>
    </div>

    <div class="footer">
        Generated automatically by IPsecGuard AI &bull; Smart India Hackathon Prototype &bull; Defensive Security Audit Tool
    </div>
</div>
</body>
</html>
"""
        return html
