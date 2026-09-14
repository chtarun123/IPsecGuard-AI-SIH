import React, { useState } from 'react';
import { Sliders, ShieldCheck, ArrowRight, CheckCircle2, AlertTriangle, XCircle, Zap } from 'lucide-react';
import { compareConfigs } from '../api';

export default function ComparePanel({ sampleConfigs }) {
  const defaultA = sampleConfigs.find(s => s.id === 'legacy-vpn')?.config || {
    ike_version: 'IKEv1',
    mode: 'Tunnel',
    encryption: 'AES-128',
    authentication: 'HMAC-SHA1',
    dh_group: 'Group 2',
    pfs: false,
    ip_version: 'IPv4',
    traffic_type: 'Email',
    replay_protection: false,
    key_lifetime: 86400
  };

  const defaultB = sampleConfigs.find(s => s.id === 'strong-enterprise')?.config || {
    ike_version: 'IKEv2',
    mode: 'Tunnel',
    encryption: 'AES-256',
    authentication: 'HMAC-SHA256',
    dh_group: 'Group 20',
    pfs: true,
    ip_version: 'IPv4',
    traffic_type: 'Web Browsing',
    replay_protection: true,
    key_lifetime: 28800
  };

  const [configA, setConfigA] = useState(defaultA);
  const [configB, setConfigB] = useState(defaultB);
  const [labelA, setLabelA] = useState('Legacy VPN (Baseline)');
  const [labelB, setLabelB] = useState('Strong Enterprise VPN');
  const [comparisonResult, setComparisonResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleRunComparison = async () => {
    setLoading(true);
    try {
      const res = await compareConfigs(configA, configB, labelA, labelB);
      setComparisonResult(res);
    } catch (err) {
      alert(`Comparison failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const loadPresetInto = (presetId, target) => {
    const sample = sampleConfigs.find(s => s.id === presetId);
    if (!sample) return;
    if (target === 'A') {
      setConfigA(sample.config);
      setLabelA(sample.name);
    } else {
      setConfigB(sample.config);
      setLabelB(sample.name);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Overview Intro */}
      <div className="card-section">
        <div className="card-section-header">
          <div className="section-title">
            <Sliders style={{ width: 18, height: 18, color: 'var(--cyan)' }} />
            VPN Security Policy Comparative Differential Engine
          </div>
          <button
            className="btn btn-primary"
            onClick={handleRunComparison}
            disabled={loading}
          >
            {loading ? 'Evaluating...' : 'Compare Configurations'}
          </button>
        </div>
        <p style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
          Evaluate cryptographic posture differentials between two VPN configurations. Analyze how upgrading from legacy protocols (e.g., IKEv1, SHA-1, DH2) to modern suites (IKEv2, AES-256, DH20, PFS) eliminates attack vectors and bolsters resilience.
        </p>
      </div>

      {/* Side-by-Side Configuration Selectors */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))', gap: '20px' }}>
        {/* Configuration A */}
        <div className="card-section" style={{ borderTop: '4px solid var(--rose)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
            <strong style={{ color: 'var(--rose)', fontSize: '15px' }}>Configuration A: {labelA}</strong>
            <div style={{ display: 'flex', gap: '4px' }}>
              <button 
                className="btn btn-secondary" 
                style={{ padding: '4px 8px', fontSize: '11px' }}
                onClick={() => loadPresetInto('legacy-vpn', 'A')}
              >
                Legacy Preset
              </button>
              <button 
                className="btn btn-secondary" 
                style={{ padding: '4px 8px', fontSize: '11px' }}
                onClick={() => loadPresetInto('misconfigured-vpn', 'A')}
              >
                High-Risk Preset
              </button>
            </div>
          </div>

          <div className="config-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
            <div className="form-group">
              <label className="form-label">IKE Version</label>
              <select className="form-select" value={configA.ike_version} onChange={e => setConfigA({...configA, ike_version: e.target.value})}>
                <option value="IKEv1">IKEv1</option>
                <option value="IKEv2">IKEv2</option>
              </select>
            </div>
            <div className="form-group">
              <label className="form-label">Encryption</label>
              <select className="form-select" value={configA.encryption} onChange={e => setConfigA({...configA, encryption: e.target.value})}>
                <option value="AES-128">AES-128</option>
                <option value="AES-256">AES-256</option>
                <option value="AES-GCM">AES-GCM</option>
                <option value="3DES">3DES</option>
              </select>
            </div>
            <div className="form-group">
              <label className="form-label">Authentication</label>
              <select className="form-select" value={configA.authentication} onChange={e => setConfigA({...configA, authentication: e.target.value})}>
                <option value="HMAC-SHA1">HMAC-SHA1</option>
                <option value="HMAC-SHA256">HMAC-SHA256</option>
                <option value="HMAC-SHA512">HMAC-SHA512</option>
              </select>
            </div>
            <div className="form-group">
              <label className="form-label">DH Group</label>
              <select className="form-select" value={configA.dh_group} onChange={e => setConfigA({...configA, dh_group: e.target.value})}>
                <option value="Group 2">Group 2 (1024-bit)</option>
                <option value="Group 14">Group 14 (2048-bit)</option>
                <option value="Group 20">Group 20 (384-bit ECP)</option>
              </select>
            </div>
            <div className="form-group">
              <label className="form-label">PFS Status</label>
              <select className="form-select" value={configA.pfs ? 'true' : 'false'} onChange={e => setConfigA({...configA, pfs: e.target.value === 'true'})}>
                <option value="false">Disabled</option>
                <option value="true">Enabled</option>
              </select>
            </div>
            <div className="form-group">
              <label className="form-label">Mode</label>
              <select className="form-select" value={configA.mode} onChange={e => setConfigA({...configA, mode: e.target.value})}>
                <option value="Tunnel">Tunnel</option>
                <option value="Transport">Transport</option>
              </select>
            </div>
          </div>
        </div>

        {/* Configuration B */}
        <div className="card-section" style={{ borderTop: '4px solid var(--emerald)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
            <strong style={{ color: 'var(--emerald)', fontSize: '15px' }}>Configuration B: {labelB}</strong>
            <div style={{ display: 'flex', gap: '4px' }}>
              <button 
                className="btn btn-secondary" 
                style={{ padding: '4px 8px', fontSize: '11px' }}
                onClick={() => loadPresetInto('strong-enterprise', 'B')}
              >
                Enterprise Preset
              </button>
              <button 
                className="btn btn-secondary" 
                style={{ padding: '4px 8px', fontSize: '11px' }}
                onClick={() => loadPresetInto('modern-vpn', 'B')}
              >
                Modern Preset
              </button>
            </div>
          </div>

          <div className="config-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
            <div className="form-group">
              <label className="form-label">IKE Version</label>
              <select className="form-select" value={configB.ike_version} onChange={e => setConfigB({...configB, ike_version: e.target.value})}>
                <option value="IKEv2">IKEv2</option>
                <option value="IKEv1">IKEv1</option>
              </select>
            </div>
            <div className="form-group">
              <label className="form-label">Encryption</label>
              <select className="form-select" value={configB.encryption} onChange={e => setConfigB({...configB, encryption: e.target.value})}>
                <option value="AES-256">AES-256</option>
                <option value="AES-GCM">AES-GCM</option>
                <option value="AES-128">AES-128</option>
              </select>
            </div>
            <div className="form-group">
              <label className="form-label">Authentication</label>
              <select className="form-select" value={configB.authentication} onChange={e => setConfigB({...configB, authentication: e.target.value})}>
                <option value="HMAC-SHA256">HMAC-SHA256</option>
                <option value="HMAC-SHA384">HMAC-SHA384</option>
                <option value="HMAC-SHA512">HMAC-SHA512</option>
              </select>
            </div>
            <div className="form-group">
              <label className="form-label">DH Group</label>
              <select className="form-select" value={configB.dh_group} onChange={e => setConfigB({...configB, dh_group: e.target.value})}>
                <option value="Group 20">Group 20 (384-bit ECP)</option>
                <option value="Group 19">Group 19 (256-bit ECP)</option>
                <option value="Group 14">Group 14 (2048-bit)</option>
              </select>
            </div>
            <div className="form-group">
              <label className="form-label">PFS Status</label>
              <select className="form-select" value={configB.pfs ? 'true' : 'false'} onChange={e => setConfigB({...configB, pfs: e.target.value === 'true'})}>
                <option value="true">Enabled</option>
                <option value="false">Disabled</option>
              </select>
            </div>
            <div className="form-group">
              <label className="form-label">Mode</label>
              <select className="form-select" value={configB.mode} onChange={e => setConfigB({...configB, mode: e.target.value})}>
                <option value="Tunnel">Tunnel</option>
                <option value="Transport">Transport</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* Comparison Results */}
      {comparisonResult && (
        <div className="card-section">
          <div className="card-section-header">
            <div className="section-title">
              <ShieldCheck style={{ width: 18, height: 18, color: 'var(--emerald)' }} />
              Comparative Security Evaluation
            </div>
            <div style={{
              fontSize: '14px',
              fontWeight: 700,
              color: comparisonResult.score_delta > 0 ? 'var(--emerald)' : 'var(--rose)'
            }}>
              Score Delta: {comparisonResult.score_delta > 0 ? `+${comparisonResult.score_delta}` : comparisonResult.score_delta} Points
            </div>
          </div>

          {/* Differential Scorecard Header */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px', marginBottom: '20px' }}>
            <div style={{ background: 'var(--bg-secondary)', padding: '16px', borderRadius: '8px', textAlign: 'center', border: '1px solid var(--border-color)' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>{comparisonResult.label_a}</div>
              <div style={{ fontSize: '28px', fontWeight: 800, color: 'var(--rose)', marginTop: '4px' }}>
                {comparisonResult.score_a} / 100
              </div>
            </div>

            <div style={{ background: 'var(--bg-secondary)', padding: '16px', borderRadius: '8px', textAlign: 'center', border: '1px solid var(--cyan)' }}>
              <div style={{ fontSize: '11px', color: 'var(--cyan)', textTransform: 'uppercase', fontWeight: 700 }}>Recommended Choice</div>
              <div style={{ fontSize: '16px', fontWeight: 700, color: '#fff', marginTop: '10px' }}>
                {comparisonResult.superior_configuration}
              </div>
            </div>

            <div style={{ background: 'var(--bg-secondary)', padding: '16px', borderRadius: '8px', textAlign: 'center', border: '1px solid var(--border-color)' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>{comparisonResult.label_b}</div>
              <div style={{ fontSize: '28px', fontWeight: 800, color: 'var(--emerald)', marginTop: '4px' }}>
                {comparisonResult.score_b} / 100
              </div>
            </div>
          </div>

          <div style={{
            background: 'rgba(16, 185, 129, 0.08)',
            border: '1px solid rgba(16, 185, 129, 0.3)',
            borderRadius: '8px',
            padding: '14px 18px',
            marginBottom: '20px',
            fontSize: '13px',
            color: 'var(--text-primary)',
            lineHeight: '1.5'
          }}>
            <strong>Comparative AI Verdict: </strong>
            {comparisonResult.summary}
          </div>

          {/* Differential Attributes Table */}
          <div style={{ overflowX: 'auto' }}>
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>Cryptographic Parameter</th>
                  <th>{comparisonResult.label_a}</th>
                  <th>{comparisonResult.label_b}</th>
                  <th>Security Impact &amp; Rationale</th>
                </tr>
              </thead>
              <tbody>
                {comparisonResult.comparison_matrix?.map((row, idx) => (
                  <tr key={idx}>
                    <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{row.parameter}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--rose)' }}>{row.val_a}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--emerald)' }}>{row.val_b}</td>
                    <td style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                      {row.comparison || (row.winner ? `Superior: ${row.winner}` : 'Equivalent')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
