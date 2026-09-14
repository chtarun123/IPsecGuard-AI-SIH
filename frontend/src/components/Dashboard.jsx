import React from 'react';
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  Cpu, 
  Lock, 
  Activity, 
  Radio, 
  CheckCircle2, 
  AlertTriangle, 
  XCircle,
  Zap
} from 'lucide-react';

export default function Dashboard({ 
  analysisData, 
  sampleConfigs, 
  activePresetId, 
  onSelectPreset, 
  onAnalyze, 
  loading,
  setActiveTab 
}) {
  if (!analysisData) {
    return (
      <div className="card-section" style={{ textAlign: 'center', padding: '60px 20px' }}>
        <Activity className="pulse-dot" style={{ width: 32, height: 32, margin: '0 auto 16px' }} />
        <h3>Loading IPsecGuard AI Engine...</h3>
      </div>
    );
  }

  const score = analysisData.security_assessment?.score ?? 0;
  const riskLevel = analysisData.security_assessment?.risk_level ?? 'UNKNOWN';
  const confidence = analysisData.ai_classification?.overall_confidence ?? 0;
  const config = analysisData.config || {};
  const sa = analysisData.security_association || {};
  const traffic = analysisData.traffic_metrics || {};

  const getScoreBorderClass = () => {
    if (score >= 80) return 'border-emerald';
    if (score >= 60) return 'border-amber';
    return 'border-rose';
  };

  const getScoreColor = () => {
    if (score >= 80) return 'var(--emerald)';
    if (score >= 60) return 'var(--amber)';
    return 'var(--rose)';
  };

  const getRiskBadgeClass = () => {
    if (riskLevel === 'LOW') return 'low';
    if (riskLevel === 'MEDIUM') return 'medium';
    if (riskLevel === 'HIGH') return 'high';
    return 'critical';
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Quick Demo Dataset Selection Bar */}
      <div className="card-section" style={{ padding: '16px 20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Zap style={{ width: 18, height: 18, color: 'var(--cyan)' }} />
            <span style={{ fontSize: '13px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              Quick Demo Datasets:
            </span>
          </div>
          <div className="preset-pills" style={{ margin: 0 }}>
            {sampleConfigs.map((sample) => (
              <button
                key={sample.id}
                className={`preset-pill ${activePresetId === sample.id ? 'active' : ''}`}
                onClick={() => onSelectPreset(sample.id)}
              >
                <span style={{
                  width: 8,
                  height: 8,
                  borderRadius: '50%',
                  background: sample.id.includes('strong') || sample.id.includes('modern') 
                    ? 'var(--emerald)' 
                    : (sample.id.includes('legacy') || sample.id.includes('misconfigured') ? 'var(--rose)' : 'var(--purple)')
                }} />
                {sample.name}
              </button>
            ))}
          </div>
          <button 
            className="btn btn-primary" 
            onClick={onAnalyze} 
            disabled={loading}
            style={{ padding: '6px 16px', fontSize: '12px' }}
          >
            {loading ? 'Analyzing...' : 'Run Live Analysis'}
          </button>
        </div>
      </div>

      {/* Hero Scorecard & Key Indicators */}
      <div className="scorecard-grid">
        {/* Security Score Hero Card */}
        <div className={`score-hero-card ${getScoreBorderClass()}`}>
          <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
            Overall Security Score
          </div>
          <div className="score-circle-wrapper">
            <svg width="130" height="130" viewBox="0 0 130 130">
              <circle cx="65" cy="65" r="54" fill="none" stroke="var(--border-color)" strokeWidth="10" />
              <circle 
                cx="65" 
                cy="65" 
                r="54" 
                fill="none" 
                stroke={getScoreColor()} 
                strokeWidth="10"
                strokeDasharray="339.29"
                strokeDashoffset={339.29 - (339.29 * score) / 100}
                strokeLinecap="round"
                transform="rotate(-90 65 65)"
                style={{ transition: 'stroke-dashoffset 0.8s ease' }}
              />
            </svg>
            <div style={{ position: 'absolute', textAlign: 'center' }}>
              <div className="score-number" style={{ color: getScoreColor() }}>{score}</div>
              <div className="score-total">/ 100</div>
            </div>
          </div>
          <div className={`risk-badge-lg ${getRiskBadgeClass()}`}>
            {riskLevel} RISK
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '8px' }}>
            Audit ID: {analysisData.analysis_id}
          </div>
        </div>

        {/* 8 Primary Security Attributes Grid */}
        <div className="metrics-grid">
          <div className="metric-card">
            <div className="metric-header">
              <span>AI Confidence</span>
              <Cpu style={{ width: 16, height: 16, color: 'var(--cyan)' }} />
            </div>
            <div className="metric-value" style={{ color: 'var(--cyan)' }}>
              {confidence}%
            </div>
            <div className="metric-sub">
              {analysisData.ai_classification?.detected_count} Detected / {analysisData.ai_classification?.inferred_count} Inferred
            </div>
          </div>

          <div className="metric-card">
            <div className="metric-header">
              <span>Protocol Status</span>
              <Radio style={{ width: 16, height: 16, color: 'var(--emerald)' }} />
            </div>
            <div className="metric-value" style={{ color: 'var(--text-primary)', fontSize: '16px' }}>
              IPsec Detected
            </div>
            <div className="metric-sub">
              {traffic.esp_detected ? 'ESP Encapsulation Active' : 'Transport Mode'}
            </div>
          </div>

          <div className="metric-card">
            <div className="metric-header">
              <span>IKE Version</span>
              <Lock style={{ width: 16, height: 16, color: config.ike_version === 'IKEv2' ? 'var(--emerald)' : 'var(--rose)' }} />
            </div>
            <div className="metric-value" style={{ color: config.ike_version === 'IKEv2' ? 'var(--emerald)' : 'var(--rose)' }}>
              {config.ike_version}
            </div>
            <div className="metric-sub">
              {config.ike_version === 'IKEv2' ? 'RFC 7296 Compliant' : 'Legacy RFC 2409 (Weak)'}
            </div>
          </div>

          <div className="metric-card">
            <div className="metric-header">
              <span>VPN Mode</span>
              <Activity style={{ width: 16, height: 16, color: config.mode === 'Tunnel' ? 'var(--emerald)' : 'var(--amber)' }} />
            </div>
            <div className="metric-value" style={{ fontSize: '16px' }}>
              {config.mode} Mode
            </div>
            <div className="metric-sub">
              {config.mode === 'Tunnel' ? 'Inner Headers Encapsulated' : 'Header Exposed (Host-to-Host)'}
            </div>
          </div>

          <div className="metric-card">
            <div className="metric-header">
              <span>Encryption</span>
              <ShieldCheck style={{ width: 16, height: 16, color: config.encryption.includes('256') || config.encryption.includes('GCM') ? 'var(--emerald)' : 'var(--amber)' }} />
            </div>
            <div className="metric-value" style={{ fontSize: '16px' }}>
              {config.encryption}
            </div>
            <div className="metric-sub">
              {config.encryption.includes('GCM') ? 'AEAD Authenticated' : (config.encryption.includes('256') ? '256-bit Strong' : '128-bit Moderate')}
            </div>
          </div>

          <div className="metric-card">
            <div className="metric-header">
              <span>Authentication</span>
              <Shield style={{ width: 16, height: 16, color: config.authentication.includes('SHA1') ? 'var(--rose)' : 'var(--emerald)' }} />
            </div>
            <div className="metric-value" style={{ fontSize: '15px' }}>
              {config.authentication}
            </div>
            <div className="metric-sub">
              {config.authentication.includes('SHA1') ? 'Deprecated Collision Risk' : 'SHA-2 Family (Secure)'}
            </div>
          </div>

          <div className="metric-card">
            <div className="metric-header">
              <span>DH Group</span>
              <Cpu style={{ width: 16, height: 16, color: config.dh_group.includes('Group 2') ? 'var(--rose)' : 'var(--emerald)' }} />
            </div>
            <div className="metric-value" style={{ fontSize: '15px' }}>
              {config.dh_group}
            </div>
            <div className="metric-sub">
              {config.dh_group.includes('Group 2') ? '1024-bit (Logjam Vulnerable)' : '>= 2048-bit / ECC Modern'}
            </div>
          </div>

          <div className="metric-card">
            <div className="metric-header">
              <span>PFS Status</span>
              {config.pfs ? (
                <CheckCircle2 style={{ width: 16, height: 16, color: 'var(--emerald)' }} />
              ) : (
                <XCircle style={{ width: 16, height: 16, color: 'var(--rose)' }} />
              )}
            </div>
            <div className="metric-value" style={{ color: config.pfs ? 'var(--emerald)' : 'var(--rose)' }}>
              {config.pfs ? 'ENABLED' : 'DISABLED'}
            </div>
            <div className="metric-sub">
              {config.pfs ? 'Forward Confidentiality Assured' : 'Compromise Exposes History'}
            </div>
          </div>
        </div>
      </div>

      {/* Two Columns: Executive Summary + Key Security Findings Preview */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '20px' }}>
        {/* Executive Summary Card */}
        <div className="card-section">
          <div className="card-section-header">
            <div className="section-title">
              <Shield style={{ width: 18, height: 18, color: 'var(--cyan)' }} />
              Executive Assessment Summary
            </div>
            <button className="btn btn-outline-cyan" onClick={() => setActiveTab('reports')} style={{ padding: '4px 10px', fontSize: '11px' }}>
              Full Report &rarr;
            </button>
          </div>
          <p style={{ color: 'var(--text-secondary)', fontSize: '14px', lineHeight: '1.6', marginBottom: '16px' }}>
            {analysisData.security_assessment?.risk_summary}
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
              Cryptographic Strengths
            </div>
            {analysisData.security_assessment?.strengths?.slice(0, 3).map((s, idx) => (
              <div key={idx} style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', fontSize: '13px', color: 'var(--emerald)' }}>
                <CheckCircle2 style={{ width: 16, height: 16, flexShrink: 0, marginTop: 2 }} />
                <span>{s}</span>
              </div>
            ))}

            {analysisData.security_assessment?.weaknesses?.length > 0 && (
              <>
                <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginTop: '10px' }}>
                  Identified Weaknesses
                </div>
                {analysisData.security_assessment?.weaknesses?.slice(0, 3).map((w, idx) => (
                  <div key={idx} style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', fontSize: '13px', color: 'var(--rose)' }}>
                    <AlertTriangle style={{ width: 16, height: 16, flexShrink: 0, marginTop: 2 }} />
                    <span>{w}</span>
                  </div>
                ))}
              </>
            )}
          </div>
        </div>

        {/* Security Association (SA) Quick Snapshot */}
        <div className="card-section">
          <div className="card-section-header">
            <div className="section-title">
              <Lock style={{ width: 18, height: 18, color: 'var(--purple)' }} />
              Active Security Association (SA) Telemetry
            </div>
            <button className="btn btn-outline-cyan" onClick={() => setActiveTab('analysis')} style={{ padding: '4px 10px', fontSize: '11px' }}>
              Deep Inspect &rarr;
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '14px' }}>
            <div style={{ background: 'var(--bg-secondary)', padding: '12px', borderRadius: '8px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Inbound SPI</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '14px', color: 'var(--cyan)', marginTop: '4px', fontWeight: 600 }}>
                {sa.inbound_spi || '0x8F3C92A1'}
              </div>
            </div>
            <div style={{ background: 'var(--bg-secondary)', padding: '12px', borderRadius: '8px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Outbound SPI</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '14px', color: 'var(--cyan)', marginTop: '4px', fontWeight: 600 }}>
                {sa.outbound_spi || '0x4E12B07D'}
              </div>
            </div>
            <div style={{ background: 'var(--bg-secondary)', padding: '12px', borderRadius: '8px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Source Gateway</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', color: 'var(--text-primary)', marginTop: '4px' }}>
                {sa.source_gateway || '198.51.100.15'}
              </div>
            </div>
            <div style={{ background: 'var(--bg-secondary)', padding: '12px', borderRadius: '8px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Destination Gateway</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', color: 'var(--text-primary)', marginTop: '4px' }}>
                {sa.destination_gateway || '203.0.113.88'}
              </div>
            </div>
            <div style={{ background: 'var(--bg-secondary)', padding: '12px', borderRadius: '8px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Anti-Replay Window</div>
              <div style={{ fontSize: '13px', color: config.replay_protection ? 'var(--emerald)' : 'var(--rose)', marginTop: '4px', fontWeight: 600 }}>
                {sa.replay_protection || 'Enabled'}
              </div>
            </div>
            <div style={{ background: 'var(--bg-secondary)', padding: '12px', borderRadius: '8px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Key Lifetime</div>
              <div style={{ fontSize: '13px', color: 'var(--text-primary)', marginTop: '4px', fontWeight: 600 }}>
                {sa.key_lifetime || '28800s (8h)'}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
