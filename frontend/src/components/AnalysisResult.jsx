import React from 'react';
import { Cpu, CheckCircle2, HelpCircle, Shield, Eye, Lock, ArrowRight, Activity } from 'lucide-react';

export default function AnalysisResult({ analysisData }) {
  if (!analysisData) return null;

  const ai = analysisData.ai_classification || {};
  const classifications = ai.classifications || [];
  const sa = analysisData.security_association || {};
  const meta = analysisData.security_assessment?.metadata_exposure || {};

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* AI-Assisted Protocol Classification Card */}
      <div className="card-section">
        <div className="card-section-header">
          <div className="section-title">
            <Cpu style={{ width: 18, height: 18, color: 'var(--cyan)' }} />
            AI-Assisted Protocol Classification Engine
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
              Overall Model Confidence:
            </span>
            <span style={{
              fontSize: '15px',
              fontFamily: 'var(--font-mono)',
              fontWeight: 700,
              color: 'var(--cyan)',
              background: 'rgba(6, 182, 212, 0.1)',
              padding: '2px 10px',
              borderRadius: '6px',
              border: '1px solid var(--cyan)'
            }}>
              {ai.overall_confidence}%
            </span>
          </div>
        </div>

        <div style={{
          background: 'rgba(6, 182, 212, 0.05)',
          border: '1px solid rgba(6, 182, 212, 0.2)',
          borderRadius: '8px',
          padding: '12px 16px',
          marginBottom: '20px',
          fontSize: '13px',
          color: 'var(--text-secondary)'
        }}>
          <strong>Classification Philosophy: </strong>
          To avoid security hallucinations, IPsecGuard AI rigorously bifurcates characteristics into{' '}
          <span className="badge badge-mitigated" style={{ margin: '0 4px' }}>DETECTED</span> (empirically derived from frame headers, ISAKMP records, and explicit policy) and{' '}
          <span className="badge badge-info" style={{ margin: '0 4px' }}>INFERRED</span> (derived via heuristic entropy analysis and inter-arrival timing).
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="cyber-table">
            <thead>
              <tr>
                <th>Analyzed Characteristic</th>
                <th>Resolved Value</th>
                <th>Classification Mode</th>
                <th>AI Confidence</th>
                <th>Empirical Evidence / Heuristic Rationale</th>
              </tr>
            </thead>
            <tbody>
              {classifications.map((item, idx) => (
                <tr key={idx}>
                  <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                    {item.parameter}
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--cyan)' }}>
                    {item.value}
                  </td>
                  <td>
                    {item.status === 'DETECTED' ? (
                      <span className="badge badge-mitigated">
                        <CheckCircle2 style={{ width: 12, height: 12 }} /> DETECTED
                      </span>
                    ) : (
                      <span className="badge badge-info">
                        <HelpCircle style={{ width: 12, height: 12 }} /> INFERRED
                      </span>
                    )}
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <div style={{ width: '60px', height: '6px', background: 'var(--bg-secondary)', borderRadius: '3px', overflow: 'hidden' }}>
                        <div style={{
                          width: `${item.confidence}%`,
                          height: '100%',
                          background: item.confidence >= 90 ? 'var(--emerald)' : (item.confidence >= 75 ? 'var(--cyan)' : 'var(--amber)')
                        }} />
                      </div>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                        {item.confidence}%
                      </span>
                    </div>
                  </td>
                  <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    {item.evidence}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Security Association (SA) Deep Inspection */}
      <div className="card-section">
        <div className="card-section-header">
          <div className="section-title">
            <Lock style={{ width: 18, height: 18, color: 'var(--purple)' }} />
            Security Association (SA) Parameter Registry
          </div>
          <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Unidirectional Security Attributes (RFC 4301)
          </span>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="cyber-table">
            <thead>
              <tr>
                <th>SA Attribute</th>
                <th>Negotiated Value</th>
                <th>Cryptographic Standard</th>
                <th>Defensive Status</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Inbound SPI (Security Parameter Index)</td>
                <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--cyan)', fontWeight: 600 }}>{sa.inbound_spi}</td>
                <td>RFC 4303 ESP Identifier</td>
                <td><span className="badge badge-mitigated">Active Index</span></td>
              </tr>
              <tr>
                <td>Outbound SPI (Security Parameter Index)</td>
                <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--cyan)', fontWeight: 600 }}>{sa.outbound_spi}</td>
                <td>RFC 4303 ESP Identifier</td>
                <td><span className="badge badge-mitigated">Active Index</span></td>
              </tr>
              <tr>
                <td>Encapsulation Mode</td>
                <td style={{ fontFamily: 'var(--font-mono)' }}>{sa.mode} Mode</td>
                <td>{sa.mode === 'Tunnel' ? 'Gateway-to-Gateway (Tunnel)' : 'Host-to-Host (Transport)'}</td>
                <td>
                  <span className={`badge ${sa.mode === 'Tunnel' ? 'badge-mitigated' : 'badge-medium'}`}>
                    {sa.mode === 'Tunnel' ? 'Protected Endpoints' : 'Exposed Header'}
                  </span>
                </td>
              </tr>
              <tr>
                <td>Confidentiality Cipher</td>
                <td style={{ fontFamily: 'var(--font-mono)' }}>{sa.encryption}</td>
                <td>NIST SP 800-38A / SP 800-38D</td>
                <td>
                  <span className={`badge ${sa.encryption.includes('256') || sa.encryption.includes('GCM') ? 'badge-mitigated' : 'badge-medium'}`}>
                    {sa.encryption.includes('256') || sa.encryption.includes('GCM') ? 'CNSA Compliant' : 'Marginal Depth'}
                  </span>
                </td>
              </tr>
              <tr>
                <td>Integrity / HMAC Algorithm</td>
                <td style={{ fontFamily: 'var(--font-mono)' }}>{sa.authentication}</td>
                <td>RFC 4868 / FIPS 180-4</td>
                <td>
                  <span className={`badge ${sa.authentication.includes('SHA1') ? 'badge-high' : 'badge-mitigated'}`}>
                    {sa.authentication.includes('SHA1') ? 'Collision Warning' : 'Secure SHA-2'}
                  </span>
                </td>
              </tr>
              <tr>
                <td>Key Exchange Group</td>
                <td style={{ fontFamily: 'var(--font-mono)' }}>{sa.dh_group}</td>
                <td>RFC 7296 / RFC 5114</td>
                <td>
                  <span className={`badge ${sa.dh_group.includes('Group 2') ? 'badge-high' : 'badge-mitigated'}`}>
                    {sa.dh_group.includes('Group 2') ? 'Logjam Vulnerable' : 'Resilient'}
                  </span>
                </td>
              </tr>
              <tr>
                <td>Anti-Replay Window Mechanism</td>
                <td style={{ fontFamily: 'var(--font-mono)' }}>{sa.replay_protection}</td>
                <td>RFC 4303 Section 3.4.3</td>
                <td>
                  <span className={`badge ${sa.replay_protection.includes('Enabled') ? 'badge-mitigated' : 'badge-high'}`}>
                    {sa.replay_protection.includes('Enabled') ? 'Replay Protected' : 'Replay Risk'}
                  </span>
                </td>
              </tr>
              <tr>
                <td>Cryptoperiod (Key Lifetime)</td>
                <td style={{ fontFamily: 'var(--font-mono)' }}>{sa.key_lifetime}</td>
                <td>NIST SP 800-57 Key Management</td>
                <td>
                  <span className={`badge ${sa.key_lifetime.includes('172800') ? 'badge-high' : 'badge-mitigated'}`}>
                    {sa.key_lifetime.includes('172800') ? 'Excessive Window' : 'Safe Interval'}
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Metadata Exposure Assessment Section */}
      <div className="card-section">
        <div className="card-section-header">
          <div className="section-title">
            <Eye style={{ width: 18, height: 18, color: meta.level === 'LOW' ? 'var(--emerald)' : 'var(--amber)' }} />
            Metadata Exposure Analysis (Eavesdropper Visibility Vectors)
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Exposure Level:</span>
            <span className={`badge ${meta.level === 'LOW' ? 'badge-mitigated' : (meta.level === 'MEDIUM' ? 'badge-medium' : 'badge-high')}`}>
              {meta.level} EXPOSURE
            </span>
          </div>
        </div>

        <p style={{ color: 'var(--text-secondary)', fontSize: '13px', lineHeight: '1.6', marginBottom: '16px' }}>
          {meta.summary}
        </p>

        <div style={{ overflowX: 'auto' }}>
          <table className="cyber-table">
            <thead>
              <tr>
                <th>Observable Traffic Vector</th>
                <th>Visibility State Across Wire</th>
                <th>Defensive Risk Tier</th>
                <th>Traffic Analysis Countermeasures</th>
              </tr>
            </thead>
            <tbody>
              {meta.exposed_fields?.map((ef, idx) => (
                <tr key={idx}>
                  <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{ef.field}</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>{ef.status}</td>
                  <td>
                    <span className={`badge ${ef.risk === 'None' ? 'badge-mitigated' : (ef.risk === 'Low' ? 'badge-info' : 'badge-medium')}`}>
                      {ef.risk} Risk
                    </span>
                  </td>
                  <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    {ef.field.includes('Size') 
                      ? 'Deploy ESP arbitrary padding or constant-rate dummy packets to obfuscate MTU fingerprints.'
                      : (ef.field.includes('Timing') 
                        ? 'Inject synthetic jitter or packet queuing to disrupt keystroke / inter-packet arrival analysis.'
                        : (ef.field.includes('Host') 
                          ? 'Enforce Tunnel Mode so public observers only inspect VPN gateway peer IP addresses.'
                          : 'Standard cryptographic encapsulation protects payload confidentiality.'))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
