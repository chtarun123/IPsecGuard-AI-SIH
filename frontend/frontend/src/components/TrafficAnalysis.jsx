import React from 'react';
import { Activity, BarChart3, Radio, ShieldCheck, CheckCircle2, XCircle, ArrowUpRight } from 'lucide-react';

export default function TrafficAnalysis({ analysisData }) {
  if (!analysisData) return null;

  const traffic = analysisData.traffic_metrics || {};
  const config = analysisData.config || {};
  const sizeDist = traffic.size_distribution || [];
  const protocols = traffic.protocol_breakdown || { ESP: 12000, IKE: 240, 'NAT-T': 40 };

  const maxBucketCount = Math.max(...sizeDist.map(b => b.count), 1);
  const totalPackets = traffic.packet_count || 1;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Telemetry Summary Cards Grid */}
      <div className="metrics-grid">
        <div className="metric-card">
          <div className="metric-header">
            <span>Total Captured Packets</span>
            <Activity style={{ width: 16, height: 16, color: 'var(--cyan)' }} />
          </div>
          <div className="metric-value" style={{ color: 'var(--cyan)' }}>
            {traffic.packet_count?.toLocaleString()}
          </div>
          <div className="metric-sub">
            Deterministic baseline telemetry
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-header">
            <span>Encrypted Traffic Ratio</span>
            <ShieldCheck style={{ width: 16, height: 16, color: 'var(--emerald)' }} />
          </div>
          <div className="metric-value" style={{ color: 'var(--emerald)' }}>
            {traffic.encrypted_ratio}%
          </div>
          <div className="metric-sub">
            ESP ciphertext encapsulation
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-header">
            <span>Average Packet Size</span>
            <BarChart3 style={{ width: 16, height: 16, color: 'var(--purple)' }} />
          </div>
          <div className="metric-value">
            {traffic.avg_packet_size} Bytes
          </div>
          <div className="metric-sub">
            Payload + IPsec ESP Overhead
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-header">
            <span>Tunnel Payload Type</span>
            <Radio style={{ width: 16, height: 16, color: 'var(--amber)' }} />
          </div>
          <div className="metric-value" style={{ fontSize: '16px' }}>
            {config.traffic_type}
          </div>
          <div className="metric-sub">
            AI Heuristic Classification
          </div>
        </div>
      </div>

      {/* Protocol Detection Flags Row */}
      <div className="card-section" style={{ padding: '16px 24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '13px', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)' }}>
              Protocol Detection Flags:
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '20px', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px' }}>
              {traffic.esp_detected ? (
                <CheckCircle2 style={{ width: 16, height: 16, color: 'var(--emerald)' }} />
              ) : (
                <XCircle style={{ width: 16, height: 16, color: 'var(--rose)' }} />
              )}
              <strong>ESP (Protocol 50):</strong>
              <span style={{ color: traffic.esp_detected ? 'var(--emerald)' : 'var(--text-muted)' }}>
                {traffic.esp_detected ? 'Detected' : 'Not Present'}
              </span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px' }}>
              {traffic.ah_detected ? (
                <CheckCircle2 style={{ width: 16, height: 16, color: 'var(--emerald)' }} />
              ) : (
                <XCircle style={{ width: 16, height: 16, color: 'var(--text-muted)' }} />
              )}
              <strong>AH (Protocol 51):</strong>
              <span style={{ color: traffic.ah_detected ? 'var(--emerald)' : 'var(--text-muted)' }}>
                {traffic.ah_detected ? 'Detected' : 'Not Present'}
              </span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px' }}>
              {traffic.ike_detected ? (
                <CheckCircle2 style={{ width: 16, height: 16, color: 'var(--emerald)' }} />
              ) : (
                <XCircle style={{ width: 16, height: 16, color: 'var(--rose)' }} />
              )}
              <strong>ISAKMP / IKE (Port 500):</strong>
              <span style={{ color: traffic.ike_detected ? 'var(--emerald)' : 'var(--text-muted)' }}>
                {traffic.ike_detected ? 'Detected' : 'Not Present'}
              </span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px' }}>
              <span className="badge badge-info">
                {config.ip_version} Stack
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Two Chart Columns: Packet Size Distribution + Protocol Distribution */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))', gap: '20px' }}>
        {/* Packet Size Distribution Bar Chart */}
        <div className="card-section">
          <div className="card-section-header">
            <div className="section-title">
              <BarChart3 style={{ width: 18, height: 18, color: 'var(--cyan)' }} />
              Packet Size Distribution (Byte Buckets)
            </div>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>MTU Footprint</span>
          </div>

          <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
            Bimodal distributions with high frequency in 1025-1500B bucket reflect streaming and bulk transfers; predominance in 64-512B suggests interactive voice or keystroke terminals.
          </p>

          <div className="bar-chart-container">
            {sizeDist.map((bucket, idx) => {
              const pct = Math.round((bucket.count / maxBucketCount) * 100);
              const color = idx === 3 ? 'var(--cyan)' : (idx === 2 ? '#38bdf8' : (idx === 1 ? '#818cf8' : '#a78bfa'));
              return (
                <div key={bucket.range} className="bar-row">
                  <div className="bar-label">{bucket.range}</div>
                  <div className="bar-track">
                    <div
                      className="bar-fill"
                      style={{
                        width: `${pct}%`,
                        background: color
                      }}
                    />
                  </div>
                  <div className="bar-count">
                    {bucket.count.toLocaleString()}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Protocol Composition Breakdown */}
        <div className="card-section">
          <div className="card-section-header">
            <div className="section-title">
              <Activity style={{ width: 18, height: 18, color: 'var(--purple)' }} />
              Protocol Composition Breakdown
            </div>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Wire Frames</span>
          </div>

          <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
            Encrypted ESP payload packets comprise the vast majority of normal tunnel throughput, with IKE management frames exchanged during initial handshake and periodic Child SA rekeys.
          </p>

          <div className="bar-chart-container">
            {Object.entries(protocols).map(([proto, count]) => {
              const pct = Math.round((count / totalPackets) * 100) || 1;
              const color = proto === 'ESP' ? 'var(--emerald)' : (proto === 'IKE' ? 'var(--cyan)' : 'var(--amber)');
              return (
                <div key={proto} className="bar-row">
                  <div className="bar-label" style={{ fontWeight: 700 }}>{proto}</div>
                  <div className="bar-track">
                    <div
                      className="bar-fill"
                      style={{
                        width: `${pct}%`,
                        background: color
                      }}
                    />
                  </div>
                  <div className="bar-count">
                    {count.toLocaleString()} ({pct}%)
                  </div>
                </div>
              );
            })}
          </div>

          {/* Endpoint Communication Metadata */}
          <div style={{ marginTop: '24px', background: 'var(--bg-secondary)', padding: '12px 16px', borderRadius: '8px', fontSize: '12px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)', marginBottom: '4px' }}>
              <span>Tunnel Ingress Peer:</span>
              <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>{traffic.source_ip || '198.51.100.15'}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)' }}>
              <span>Tunnel Egress Peer:</span>
              <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>{traffic.dest_ip || '203.0.113.88'}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
