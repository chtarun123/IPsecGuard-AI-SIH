import React, { useState } from 'react';
import { FileText, Download, ShieldCheck, AlertTriangle, CheckCircle2, Lock, Cpu, ExternalLink } from 'lucide-react';
import { fetchReport } from '../api';

export default function ReportPanel({ analysisData }) {
  const [activeReportType, setActiveReportType] = useState('executive');
  const [downloading, setDownloading] = useState(false);

  if (!analysisData) return null;

  const reports = analysisData.reports || {};
  const exec = reports.executive_report || {};
  const tech = reports.technical_report || {};
  const score = exec.security_score ?? 0;

  const handleDownloadHtml = async () => {
    setDownloading(true);
    try {
      const htmlText = await fetchReport(analysisData.analysis_id, 'html');
      const blob = new Blob([htmlText], { type: 'text/html' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `IPsecGuard_Security_Audit_${analysisData.analysis_id}.html`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      alert(`Download failed: ${err.message}`);
    } finally {
      setDownloading(false);
    }
  };

  const handleDownloadSamplePcap = (sampleId) => {
    window.open(`/api/download-sample-pcap/${sampleId}`, '_blank');
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Report Controls & Action Header */}
      <div className="card-section">
        <div className="card-section-header">
          <div className="section-title">
            <FileText style={{ width: 18, height: 18, color: 'var(--cyan)' }} />
            Security Assessment Reporting Engine
          </div>
          <div style={{ display: 'flex', gap: '10px' }}>
            <button
              className={`btn ${activeReportType === 'executive' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setActiveReportType('executive')}
            >
              Executive Summary
            </button>
            <button
              className={`btn ${activeReportType === 'technical' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setActiveReportType('technical')}
            >
              Technical Audit
            </button>
            <button
              className="btn btn-outline-cyan"
              onClick={handleDownloadHtml}
              disabled={downloading}
            >
              <Download style={{ width: 16, height: 16 }} />
              {downloading ? 'Exporting...' : 'Download Report (HTML/PDF)'}
            </button>
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Report Reference: <strong style={{ color: 'var(--cyan)' }}>{exec.analysis_id}</strong> &bull; Generated: {exec.timestamp}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Sample PCAP Trace Generators:</span>
            <button 
              className="btn btn-secondary" 
              style={{ padding: '4px 8px', fontSize: '11px' }}
              onClick={() => handleDownloadSamplePcap('strong-enterprise')}
            >
              <Download style={{ width: 12, height: 12 }} /> Enterprise.pcap
            </button>
            <button 
              className="btn btn-secondary" 
              style={{ padding: '4px 8px', fontSize: '11px' }}
              onClick={() => handleDownloadSamplePcap('legacy-vpn')}
            >
              <Download style={{ width: 12, height: 12 }} /> Legacy.pcap
            </button>
          </div>
        </div>
      </div>

      {/* EXECUTIVE REPORT VIEW */}
      {activeReportType === 'executive' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Executive Score & Headline */}
          <div className="card-section" style={{ borderLeft: `6px solid ${score >= 80 ? 'var(--emerald)' : (score >= 60 ? 'var(--amber)' : 'var(--rose)')}` }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
              <div>
                <h2 style={{ fontSize: '20px', fontWeight: 800, color: 'var(--text-primary)' }}>
                  Executive Security Assessment: {exec.risk_level} RISK
                </h2>
                <p style={{ color: 'var(--text-secondary)', fontSize: '14px', marginTop: '6px' }}>
                  Target Suite: <strong>{exec.protocol_summary}</strong>
                </p>
              </div>
              <div style={{
                background: 'var(--bg-secondary)',
                padding: '12px 24px',
                borderRadius: '8px',
                textAlign: 'center',
                border: '1px solid var(--border-color)'
              }}>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Security Score</div>
                <div style={{
                  fontSize: '32px',
                  fontWeight: 800,
                  color: score >= 80 ? 'var(--emerald)' : (score >= 60 ? 'var(--amber)' : 'var(--rose)')
                }}>
                  {score} / 100
                </div>
              </div>
            </div>

            <div style={{
              marginTop: '16px',
              padding: '14px',
              background: 'var(--bg-secondary)',
              borderRadius: '8px',
              fontSize: '13px',
              lineHeight: '1.6',
              color: 'var(--text-primary)'
            }}>
              <strong>Strategic Overview: </strong>
              {exec.risk_summary}
            </div>
          </div>

          {/* Strengths & Weaknesses Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '20px' }}>
            <div className="card-section">
              <div className="section-title" style={{ marginBottom: '14px', color: 'var(--emerald)' }}>
                <CheckCircle2 style={{ width: 18, height: 18 }} />
                Identified Security Strengths ({exec.strengths?.length || 0})
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {exec.strengths?.map((str, idx) => (
                  <div key={idx} style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', fontSize: '13px', color: 'var(--text-secondary)' }}>
                    <span style={{ color: 'var(--emerald)', fontWeight: 700 }}>&bull;</span>
                    <span>{str}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="card-section">
              <div className="section-title" style={{ marginBottom: '14px', color: 'var(--rose)' }}>
                <AlertTriangle style={{ width: 18, height: 18 }} />
                Identified Security Weaknesses ({exec.weaknesses?.length || 0})
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {exec.weaknesses?.length === 0 ? (
                  <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>No major weaknesses identified in this configuration.</p>
                ) : (
                  exec.weaknesses?.map((w, idx) => (
                    <div key={idx} style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', fontSize: '13px', color: 'var(--text-secondary)' }}>
                      <span style={{ color: 'var(--rose)', fontWeight: 700 }}>&bull;</span>
                      <span>{w}</span>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* Actionable Executive Recommendations */}
          <div className="card-section">
            <div className="section-title" style={{ marginBottom: '16px', color: 'var(--cyan)' }}>
              <ShieldCheck style={{ width: 18, height: 18 }} />
              Prioritized Remediation Road-map
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {exec.actionable_recommendations?.map((rec, idx) => (
                <div key={idx} style={{
                  background: 'var(--bg-secondary)',
                  padding: '12px 16px',
                  borderRadius: '6px',
                  fontSize: '13px',
                  color: 'var(--text-primary)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '12px',
                  borderLeft: '3px solid var(--cyan)'
                }}>
                  <span style={{
                    width: 22,
                    height: 22,
                    borderRadius: '50%',
                    background: 'rgba(6, 182, 212, 0.2)',
                    color: 'var(--cyan)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '11px',
                    fontWeight: 700
                  }}>
                    {idx + 1}
                  </span>
                  <span>{rec}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TECHNICAL AUDIT VIEW */}
      {activeReportType === 'technical' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div className="card-section">
            <div className="section-title" style={{ marginBottom: '16px' }}>
              <Lock style={{ width: 18, height: 18, color: 'var(--purple)' }} />
              Cryptographic Suite Specification &amp; RFC Compliance
            </div>
            <div style={{ overflowX: 'auto' }}>
              <table className="cyber-table">
                <thead>
                  <tr>
                    <th>Protocol Layer</th>
                    <th>Configured Primitive</th>
                    <th>RFC Specification</th>
                    <th>Cryptanalytic Compliance Tier</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>Key Management / IKE</td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>{tech.cryptographic_breakdown?.ike_version}</td>
                    <td>{tech.cryptographic_breakdown?.ike_version === 'IKEv2' ? 'RFC 7296' : 'RFC 2409'}</td>
                    <td>{tech.cryptographic_breakdown?.ike_version === 'IKEv2' ? 'CNSA Approved' : 'Deprecated'}</td>
                  </tr>
                  <tr>
                    <td>Payload Encryption</td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>{tech.cryptographic_breakdown?.encryption}</td>
                    <td>RFC 3602 / RFC 4106</td>
                    <td>FIPS 197 Validated</td>
                  </tr>
                  <tr>
                    <td>HMAC Authentication</td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>{tech.cryptographic_breakdown?.authentication}</td>
                    <td>RFC 4868</td>
                    <td>FIPS 180-4 Validated</td>
                  </tr>
                  <tr>
                    <td>Diffie-Hellman Key Exchange</td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>{tech.cryptographic_breakdown?.dh_group}</td>
                    <td>RFC 5114</td>
                    <td>{tech.cryptographic_breakdown?.dh_group?.includes('Group 2') ? 'Vulnerable (Logjam)' : 'NIST Approved'}</td>
                  </tr>
                  <tr>
                    <td>Forward Secrecy (PFS)</td>
                    <td>{tech.cryptographic_breakdown?.pfs_enabled ? 'Active (Independent DH)' : 'Inactive'}</td>
                    <td>RFC 4301 Child SA</td>
                    <td>{tech.cryptographic_breakdown?.pfs_enabled ? 'Compliant' : 'Non-Compliant'}</td>
                  </tr>
                  <tr>
                    <td>Anti-Replay Mechanism</td>
                    <td>{tech.cryptographic_breakdown?.replay_protection ? 'Active Window (64 packets)' : 'Disabled'}</td>
                    <td>RFC 4303 Section 3.4.3</td>
                    <td>{tech.cryptographic_breakdown?.replay_protection ? 'Protected' : 'Vulnerable'}</td>
                  </tr>
                  <tr>
                    <td>Rekey Cryptoperiod</td>
                    <td>{tech.cryptographic_breakdown?.key_lifetime_seconds} seconds</td>
                    <td>NIST SP 800-57 Part 1</td>
                    <td>Standard Cryptoperiod</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
