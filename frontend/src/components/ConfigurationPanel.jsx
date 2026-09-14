import React, { useRef } from 'react';
import { Sliders, Shield, Play, Upload, Zap, FileCode, CheckCircle2 } from 'lucide-react';

export default function ConfigurationPanel({
  config,
  onChangeConfig,
  onAnalyze,
  loading,
  sampleConfigs,
  activePresetId,
  onSelectPreset,
  onUploadPCAP,
  uploading
}) {
  const fileInputRef = useRef(null);

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      onUploadPCAP(e.target.files[0]);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Demo Preset Selector Bar */}
      <div className="card-section">
        <div className="card-section-header">
          <div className="section-title">
            <Zap style={{ width: 18, height: 18, color: 'var(--cyan)' }} />
            Select Predefined Demo Scenarios (One-Click Hackathon Evaluation)
          </div>
          <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Instant ground-truth cryptographic profiles
          </span>
        </div>

        <div className="preset-pills">
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

        {/* Selected Preset Description */}
        {activePresetId && (
          <div style={{
            background: 'var(--bg-secondary)',
            borderLeft: '4px solid var(--cyan)',
            padding: '12px 16px',
            borderRadius: '4px',
            fontSize: '13px',
            color: 'var(--text-secondary)'
          }}>
            <strong>Selected Scenario: </strong>
            {sampleConfigs.find(s => s.id === activePresetId)?.description}
          </div>
        )}
      </div>

      {/* Main Configuration Form Grid */}
      <div className="card-section">
        <div className="card-section-header">
          <div className="section-title">
            <Sliders style={{ width: 18, height: 18, color: 'var(--cyan)' }} />
            VPN Security Association Parameters
          </div>
          <div style={{ display: 'flex', gap: '10px' }}>
            <button
              className="btn btn-primary"
              onClick={onAnalyze}
              disabled={loading}
              style={{ minWidth: '160px' }}
            >
              <Play style={{ width: 16, height: 16, fill: '#fff' }} />
              {loading ? 'ANALYZING...' : 'ANALYZE VPN'}
            </button>
          </div>
        </div>

        <div className="config-grid">
          {/* IPsec Protocol */}
          <div className="form-group">
            <label className="form-label">Protocol Framework</label>
            <select className="form-select" value="IPsec" disabled>
              <option value="IPsec">IPsec (RFC 4301 / ESP & AH)</option>
            </select>
          </div>

          {/* IKE Version */}
          <div className="form-group">
            <label className="form-label">IKE Protocol Version</label>
            <select
              className="form-select"
              value={config.ike_version}
              onChange={(e) => onChangeConfig('ike_version', e.target.value)}
            >
              <option value="IKEv2">IKEv2 (RFC 7296 - Recommended)</option>
              <option value="IKEv1">IKEv1 (RFC 2409 - Legacy/Weak)</option>
            </select>
          </div>

          {/* VPN Mode */}
          <div className="form-group">
            <label className="form-label">VPN Encapsulation Mode</label>
            <select
              className="form-select"
              value={config.mode}
              onChange={(e) => onChangeConfig('mode', e.target.value)}
            >
              <option value="Tunnel">Tunnel Mode (Site-to-Site Gateway)</option>
              <option value="Transport">Transport Mode (Host-to-Host)</option>
            </select>
          </div>

          {/* Encryption Algorithm */}
          <div className="form-group">
            <label className="form-label">Confidentiality Encryption</label>
            <select
              className="form-select"
              value={config.encryption}
              onChange={(e) => onChangeConfig('encryption', e.target.value)}
            >
              <option value="AES-256">AES-256 (Strong / High Security)</option>
              <option value="AES-GCM">AES-GCM (Modern AEAD Cipher)</option>
              <option value="AES-128">AES-128 (Standard Baseline)</option>
              <option value="AES-CBC">AES-CBC (CBC Padding Risk)</option>
              <option value="3DES">3DES (Deprecated / Sweet32 Risk)</option>
            </select>
          </div>

          {/* Authentication Algorithm */}
          <div className="form-group">
            <label className="form-label">Integrity Authentication</label>
            <select
              className="form-select"
              value={config.authentication}
              onChange={(e) => onChangeConfig('authentication', e.target.value)}
            >
              <option value="HMAC-SHA256">HMAC-SHA256 (Recommended)</option>
              <option value="HMAC-SHA384">HMAC-SHA384 (CNSA High-Grade)</option>
              <option value="HMAC-SHA512">HMAC-SHA512 (Maximum Margin)</option>
              <option value="HMAC-SHA1">HMAC-SHA1 (Deprecated / Collision Risk)</option>
              <option value="HMAC-MD5">HMAC-MD5 (Critical Vulnerability)</option>
            </select>
          </div>

          {/* Diffie-Hellman Group */}
          <div className="form-group">
            <label className="form-label">Diffie-Hellman Key Exchange</label>
            <select
              className="form-select"
              value={config.dh_group}
              onChange={(e) => onChangeConfig('dh_group', e.target.value)}
            >
              <option value="Group 20">Group 20 (384-bit ECP - Elliptic Curve)</option>
              <option value="Group 19">Group 19 (256-bit ECP - Elliptic Curve)</option>
              <option value="Group 14">Group 14 (2048-bit MODP Baseline)</option>
              <option value="Group 5">Group 5 (1536-bit MODP - Substandard)</option>
              <option value="Group 2">Group 2 (1024-bit MODP - Logjam Weak)</option>
            </select>
          </div>

          {/* Perfect Forward Secrecy */}
          <div className="form-group">
            <label className="form-label">Perfect Forward Secrecy (PFS)</label>
            <select
              className="form-select"
              value={config.pfs ? 'true' : 'false'}
              onChange={(e) => onChangeConfig('pfs', e.target.value === 'true')}
            >
              <option value="true">Enabled (Independent Child SA Keys)</option>
              <option value="false">Disabled (Retroactive Compromise Risk)</option>
            </select>
          </div>

          {/* IP Version */}
          <div className="form-group">
            <label className="form-label">Internet Protocol Stack</label>
            <select
              className="form-select"
              value={config.ip_version}
              onChange={(e) => onChangeConfig('ip_version', e.target.value)}
            >
              <option value="IPv4">IPv4 Stack</option>
              <option value="IPv6">IPv6 Stack</option>
            </select>
          </div>

          {/* Traffic Type Simulation */}
          <div className="form-group">
            <label className="form-label">Simulated Tunnel Payload</label>
            <select
              className="form-select"
              value={config.traffic_type}
              onChange={(e) => onChangeConfig('traffic_type', e.target.value)}
            >
              <option value="Web Browsing">Web Browsing (HTTP/2, TLS bursts)</option>
              <option value="VoIP">VoIP (Constant Small Packets, Low Jitter)</option>
              <option value="Video Streaming">Video Streaming (Large MTU frames)</option>
              <option value="Email">Email (Intermittent SMTP/IMAP)</option>
              <option value="ICMP">ICMP (Ping Periodic Keepalive)</option>
            </select>
          </div>

          {/* Replay Protection */}
          <div className="form-group">
            <label className="form-label">Anti-Replay Window</label>
            <select
              className="form-select"
              value={config.replay_protection ? 'true' : 'false'}
              onChange={(e) => onChangeConfig('replay_protection', e.target.value === 'true')}
            >
              <option value="true">Enabled (64-packet sequence window)</option>
              <option value="false">Disabled (Vulnerable to Replay)</option>
            </select>
          </div>

          {/* Key Lifetime */}
          <div className="form-group">
            <label className="form-label">SA Key Lifetime</label>
            <select
              className="form-select"
              value={config.key_lifetime}
              onChange={(e) => onChangeConfig('key_lifetime', parseInt(e.target.value, 10))}
            >
              <option value="3600">3,600 sec (1 Hour - High Security)</option>
              <option value="14400">14,400 sec (4 Hours)</option>
              <option value="28800">28,800 sec (8 Hours - Enterprise Baseline)</option>
              <option value="86400">86,400 sec (24 Hours - Prolonged Cryptoperiod)</option>
              <option value="172800">172,800 sec (48 Hours - High Risk)</option>
            </select>
          </div>
        </div>
      </div>

      {/* Mode 2: PCAP / PCAPNG File Upload Dropzone */}
      <div className="card-section">
        <div className="card-section-header">
          <div className="section-title">
            <Upload style={{ width: 18, height: 18, color: 'var(--emerald)' }} />
            Mode 2 — Upload Packet Capture (.pcap / .pcapng)
          </div>
          <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Safe defensive header parsing &amp; metadata inspection
          </span>
        </div>

        <input
          type="file"
          ref={fileInputRef}
          onChange={handleFileChange}
          accept=".pcap,.pcapng,.cap"
          style={{ display: 'none' }}
        />

        <div
          className="dropzone"
          onClick={() => fileInputRef.current?.click()}
        >
          <div style={{
            width: 50,
            height: 50,
            borderRadius: '50%',
            background: 'rgba(6, 182, 212, 0.1)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--cyan)'
          }}>
            <Upload style={{ width: 24, height: 24 }} />
          </div>
          <div>
            <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>
              {uploading ? 'Parsing Packet Capture...' : 'Click to Upload .PCAP or .PCAPNG File'}
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
              Detects ESP, AH, IKE UDP 500, NAT-T 4500, SPIs, and sequence timing side-channels
            </div>
          </div>
          <div style={{ display: 'flex', gap: '10px', marginTop: '8px' }}>
            <span className="soc-badge">
              <CheckCircle2 style={{ width: 12, height: 12 }} /> Scapy Deep Inspection
            </span>
            <span className="soc-badge">
              <CheckCircle2 style={{ width: 12, height: 12 }} /> Binary Fallback Parser
            </span>
            <span className="soc-badge">
              <CheckCircle2 style={{ width: 12, height: 12 }} /> Zero Secret Exfiltration
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
