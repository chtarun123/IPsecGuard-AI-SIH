import React, { useState } from 'react';
import { ShieldAlert, AlertTriangle, ChevronDown, ChevronUp, CheckCircle2, XCircle, Filter } from 'lucide-react';

export default function RiskMatrix({ analysisData }) {
  const [expandedFindings, setExpandedFindings] = useState({});
  const [threatFilter, setThreatFilter] = useState('ALL');

  if (!analysisData) return null;

  const findings = analysisData.security_assessment?.findings || [];
  const threats = analysisData.security_assessment?.threat_matrix || [];

  const toggleFinding = (idx) => {
    setExpandedFindings(prev => ({
      ...prev,
      [idx]: !prev[idx]
    }));
  };

  const getSeverityBadgeClass = (sev) => {
    switch (sev?.toLowerCase()) {
      case 'critical': return 'badge-critical';
      case 'high': return 'badge-high';
      case 'medium': return 'badge-medium';
      case 'low': return 'badge-low';
      default: return 'badge-info';
    }
  };

  const getStatusBadge = (status) => {
    if (status === 'Mitigated') {
      return <span className="badge badge-mitigated"><CheckCircle2 style={{ width: 12, height: 12 }} /> Mitigated</span>;
    }
    if (status === 'At Risk') {
      return <span className="badge badge-medium"><AlertTriangle style={{ width: 12, height: 12 }} /> At Risk</span>;
    }
    return <span className="badge badge-critical"><XCircle style={{ width: 12, height: 12 }} /> Vulnerable</span>;
  };

  const filteredThreats = threats.filter(t => {
    if (threatFilter === 'ALL') return true;
    if (threatFilter === 'VULNERABLE') return t.status === 'Vulnerable';
    if (threatFilter === 'AT_RISK') return t.status === 'At Risk';
    if (threatFilter === 'MITIGATED') return t.status === 'Mitigated';
    return true;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Categorized Security Findings */}
      <div className="card-section">
        <div className="card-section-header">
          <div className="section-title">
            <ShieldAlert style={{ width: 18, height: 18, color: 'var(--rose)' }} />
            Categorized Security Findings ({findings.length})
          </div>
          <div style={{ display: 'flex', gap: '6px' }}>
            {['Critical', 'High', 'Medium', 'Low', 'Informational'].map(lvl => {
              const count = findings.filter(f => f.severity === lvl).length;
              if (count === 0) return null;
              return (
                <span key={lvl} className={`badge ${getSeverityBadgeClass(lvl)}`}>
                  {count} {lvl}
                </span>
              );
            })}
          </div>
        </div>

        {findings.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '30px', color: 'var(--emerald)' }}>
            <CheckCircle2 style={{ width: 36, height: 36, margin: '0 auto 10px' }} />
            <p>No vulnerabilities or warnings detected in this configuration!</p>
          </div>
        ) : (
          <div>
            {findings.map((finding, idx) => {
              const isExpanded = expandedFindings[idx] ?? (finding.severity === 'Critical' || finding.severity === 'High');
              return (
                <div key={idx} className="finding-card">
                  <div className="finding-header" onClick={() => toggleFinding(idx)}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                      <span className={`badge ${getSeverityBadgeClass(finding.severity)}`}>
                        {finding.severity}
                      </span>
                      <strong style={{ color: 'var(--text-primary)', fontSize: '14px' }}>
                        {finding.finding}
                      </strong>
                    </div>
                    {isExpanded ? <ChevronUp style={{ width: 18, height: 18, color: 'var(--text-muted)' }} /> : <ChevronDown style={{ width: 18, height: 18, color: 'var(--text-muted)' }} />}
                  </div>

                  {isExpanded && (
                    <div className="finding-body">
                      <div>
                        <strong style={{ color: 'var(--text-secondary)' }}>Technical Explanation:</strong>
                        <p style={{ color: 'var(--text-muted)', marginTop: '4px', lineHeight: '1.5' }}>
                          {finding.explanation}
                        </p>
                      </div>
                      <div>
                        <strong style={{ color: 'var(--rose)' }}>Security Impact:</strong>
                        <p style={{ color: '#fca5a5', marginTop: '4px', lineHeight: '1.5' }}>
                          {finding.impact}
                        </p>
                      </div>
                      <div>
                        <strong style={{ color: 'var(--emerald)' }}>Recommended Remediation:</strong>
                        <p style={{ color: '#6ee7b7', marginTop: '4px', lineHeight: '1.5' }}>
                          {finding.recommendation}
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Interactive Threat Matrix */}
      <div className="card-section">
        <div className="card-section-header">
          <div className="section-title">
            <AlertTriangle style={{ width: 18, height: 18, color: 'var(--amber)' }} />
            Threat Matrix &amp; Attack Vectors
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Filter style={{ width: 14, height: 14, color: 'var(--text-muted)' }} />
            <select
              className="form-select"
              value={threatFilter}
              onChange={(e) => setThreatFilter(e.target.value)}
              style={{ padding: '4px 10px', fontSize: '12px' }}
            >
              <option value="ALL">All Threats</option>
              <option value="VULNERABLE">Vulnerable Only</option>
              <option value="AT_RISK">At Risk Only</option>
              <option value="MITIGATED">Mitigated Only</option>
            </select>
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="cyber-table">
            <thead>
              <tr>
                <th>Threat Vector</th>
                <th>Severity</th>
                <th>Likelihood</th>
                <th>Impact</th>
                <th>Mitigation Status</th>
                <th>Defensive Recommendation</th>
              </tr>
            </thead>
            <tbody>
              {filteredThreats.map((t, idx) => (
                <tr key={idx}>
                  <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                    {t.threat}
                  </td>
                  <td>
                    <span className={`badge ${getSeverityBadgeClass(t.severity)}`}>
                      {t.severity}
                    </span>
                  </td>
                  <td style={{ color: 'var(--text-muted)', fontSize: '12px' }}>
                    {t.likelihood}
                  </td>
                  <td style={{ color: 'var(--text-muted)', fontSize: '12px' }}>
                    {t.impact}
                  </td>
                  <td>
                    {getStatusBadge(t.status)}
                  </td>
                  <td style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                    {t.recommendation}
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
