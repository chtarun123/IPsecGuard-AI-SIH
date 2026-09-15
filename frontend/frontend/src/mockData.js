/**
 * Client-side Ground-Truth Demo Data & Scoring Fallback
 * Allows the frontend to run 100% standalone on GitHub Pages (static hosting).
 */

export const MOCK_SAMPLES = [
  {
    id: "strong-enterprise",
    name: "Strong Enterprise VPN",
    tag: "Enterprise / High Security",
    description: "Enterprise-grade site-to-site IPsec tunnel conforming to CNSA & NIST SP 800-77 Rev. 1 guidelines. Features modern IKEv2, AES-256 encryption, SHA-256 HMAC integrity, and DH Group 20 with PFS enabled.",
    config: {
      ike_version: "IKEv2",
      mode: "Tunnel",
      encryption: "AES-256",
      authentication: "HMAC-SHA256",
      dh_group: "Group 20",
      pfs: true,
      ip_version: "IPv4",
      traffic_type: "Web Browsing",
      replay_protection: true,
      key_lifetime: 28800
    },
    traffic_metrics: {
      packet_count: 14250,
      avg_packet_size: 842,
      encrypted_ratio: 99.4,
      esp_detected: true,
      ah_detected: false,
      ike_detected: true,
      inbound_spi: "0x8F3C92A1",
      outbound_spi: "0x4E12B07D",
      source_ip: "198.51.100.15",
      dest_ip: "203.0.113.88",
      protocol_breakdown: { ESP: 13950, IKE: 260, "NAT-T": 40 },
      size_distribution: [
        { range: "64-128 B", count: 1200 },
        { range: "129-512 B", count: 3400 },
        { range: "513-1024 B", count: 6850 },
        { range: "1025-1500 B", count: 2800 }
      ]
    },
    score: 100,
    risk_level: "LOW"
  },
  {
    id: "legacy-vpn",
    name: "Legacy VPN",
    tag: "Legacy / Deprecated",
    description: "Outdated legacy site-to-site tunnel using deprecated IKEv1 Main Mode, AES-128-CBC, SHA-1 authentication, and DH Group 2 (1024-bit MODP) with Perfect Forward Secrecy disabled. Vulnerable to cryptoanalysis and key compromise.",
    config: {
      ike_version: "IKEv1",
      mode: "Tunnel",
      encryption: "AES-128",
      authentication: "HMAC-SHA1",
      dh_group: "Group 2",
      pfs: false,
      ip_version: "IPv4",
      traffic_type: "Email",
      replay_protection: false,
      key_lifetime: 86400
    },
    traffic_metrics: {
      packet_count: 8920,
      avg_packet_size: 612,
      encrypted_ratio: 98.1,
      esp_detected: true,
      ah_detected: false,
      ike_detected: true,
      inbound_spi: "0x1A2B3C4D",
      outbound_spi: "0x5E6F7A8B",
      source_ip: "192.0.2.45",
      dest_ip: "198.51.100.22",
      protocol_breakdown: { ESP: 8600, IKE: 300, "NAT-T": 20 },
      size_distribution: [
        { range: "64-128 B", count: 2100 },
        { range: "129-512 B", count: 4300 },
        { range: "513-1024 B", count: 1820 },
        { range: "1025-1500 B", count: 700 }
      ]
    },
    score: 5,
    risk_level: "CRITICAL"
  },
  {
    id: "modern-vpn",
    name: "Modern High-Security VPN (IPv6 + AES-GCM)",
    tag: "Next-Gen / Zero-Trust",
    description: "State-of-the-art authenticated encryption (AEAD) using AES-GCM with SHA-384 and DH Group 20 (384-bit ECP) operating over IPv6. Highest cryptographic robustness and minimal metadata leakage.",
    config: {
      ike_version: "IKEv2",
      mode: "Tunnel",
      encryption: "AES-GCM",
      authentication: "HMAC-SHA384",
      dh_group: "Group 20",
      pfs: true,
      ip_version: "IPv6",
      traffic_type: "Video Streaming",
      replay_protection: true,
      key_lifetime: 14400
    },
    traffic_metrics: {
      packet_count: 25400,
      avg_packet_size: 1180,
      encrypted_ratio: 99.8,
      esp_detected: true,
      ah_detected: false,
      ike_detected: true,
      inbound_spi: "0xFEEDC0DE",
      outbound_spi: "0xCAFEBABE",
      source_ip: "2001:db8:85a3::8a2e:370:7334",
      dest_ip: "2001:db8:85a3::8a2e:370:7335",
      protocol_breakdown: { ESP: 25150, IKE: 210, "NAT-T": 40 },
      size_distribution: [
        { range: "64-128 B", count: 950 },
        { range: "129-512 B", count: 2250 },
        { range: "513-1024 B", count: 8200 },
        { range: "1025-1500 B", count: 14000 }
      ]
    },
    score: 100,
    risk_level: "LOW"
  },
  {
    id: "transport-mode",
    name: "Host-to-Host Transport Mode",
    tag: "Transport / Host-to-Host",
    description: "Host-to-host direct endpoint encryption using Transport Mode. The original IP headers are retained, exposing communication endpoints to intermediate observers.",
    config: {
      ike_version: "IKEv2",
      mode: "Transport",
      encryption: "AES-256",
      authentication: "HMAC-SHA256",
      dh_group: "Group 14",
      pfs: true,
      ip_version: "IPv4",
      traffic_type: "VoIP",
      replay_protection: true,
      key_lifetime: 28800
    },
    traffic_metrics: {
      packet_count: 11600,
      avg_packet_size: 320,
      encrypted_ratio: 98.9,
      esp_detected: true,
      ah_detected: false,
      ike_detected: true,
      inbound_spi: "0x33445566",
      outbound_spi: "0x77889900",
      source_ip: "10.0.1.50",
      dest_ip: "10.0.2.100",
      protocol_breakdown: { ESP: 11350, IKE: 180, "NAT-T": 70 },
      size_distribution: [
        { range: "64-128 B", count: 4800 },
        { range: "129-512 B", count: 5200 },
        { range: "513-1024 B", count: 1200 },
        { range: "1025-1500 B", count: 400 }
      ]
    },
    score: 95,
    risk_level: "LOW"
  },
  {
    id: "misconfigured-vpn",
    name: "Misconfigured High-Risk VPN",
    tag: "Critical / High Risk",
    description: "Dangerously misconfigured VPN with IKEv1, AES-128-CBC, weak SHA-1, DH Group 2, PFS disabled, Replay Protection disabled, and an excessively long key lifetime of 48 hours.",
    config: {
      ike_version: "IKEv1",
      mode: "Transport",
      encryption: "AES-128",
      authentication: "HMAC-SHA1",
      dh_group: "Group 2",
      pfs: false,
      ip_version: "IPv4",
      traffic_type: "Web Browsing",
      replay_protection: false,
      key_lifetime: 172800
    },
    traffic_metrics: {
      packet_count: 6400,
      avg_packet_size: 580,
      encrypted_ratio: 97.4,
      esp_detected: true,
      ah_detected: false,
      ike_detected: true,
      inbound_spi: "0xBAD0CAFE",
      outbound_spi: "0xDEADBEEF",
      source_ip: "172.16.0.4",
      dest_ip: "172.16.10.88",
      protocol_breakdown: { ESP: 6120, IKE: 240, "NAT-T": 40 },
      size_distribution: [
        { range: "64-128 B", count: 1800 },
        { range: "129-512 B", count: 3100 },
        { range: "513-1024 B", count: 1100 },
        { range: "1025-1500 B", count: 400 }
      ]
    },
    score: 5,
    risk_level: "CRITICAL"
  }
];

export function clientSideAnalyze(config) {
  let score = 100;
  const findings = [];
  const threats = [];
  const strengths = [];
  const weaknesses = [];

  const ike = String(config.ike_version || 'IKEv2').toUpperCase();
  const enc = String(config.encryption || 'AES-256').toUpperCase();
  const auth = String(config.authentication || 'HMAC-SHA256').toUpperCase();
  const dh = String(config.dh_group || 'Group 14');
  const pfs = Boolean(config.pfs);
  const replay = Boolean(config.replay_protection);
  const mode = String(config.mode || 'Tunnel');

  if (enc.includes('GCM') || enc.includes('256')) {
    strengths.push(`${enc} provides strong modern 256-bit symmetric security.`);
    threats.push({ threat: 'Brute-force Key Recovery', severity: 'Low', likelihood: 'Low', impact: 'Low', status: 'Mitigated', recommendation: 'Current key length is resistant to attacks.' });
  } else if (enc.includes('128')) {
    score -= 8;
    weaknesses.push('AES-128 provides baseline security with smaller safety margin.');
    findings.push({ finding: 'Sub-Optimal Key Length (AES-128)', severity: 'Low', explanation: 'AES-128 offers smaller security margin than AES-256.', impact: 'Reduced lifespan against advances.', recommendation: 'Upgrade to AES-256 or AES-GCM.' });
  } else if (enc.includes('3DES')) {
    score -= 35;
    weaknesses.push('3DES is deprecated and vulnerable to Sweet32 64-bit collision attacks.');
    findings.push({ finding: 'Deprecated Cipher (3DES)', severity: 'Critical', explanation: 'Sweet32 collision attack (CVE-2016-2183).', impact: 'Plaintext recovery risk.', recommendation: 'Mandate AES-256.' });
  }

  if (auth.includes('SHA1')) {
    score -= 18;
    weaknesses.push('HMAC-SHA1 relies on weakened hash function with collision risks.');
    findings.push({ finding: 'Deprecated Integrity (HMAC-SHA1)', severity: 'High', explanation: 'SHA-1 collision attacks (SHAttered).', impact: 'Integrity tampering risk.', recommendation: 'Upgrade to HMAC-SHA256.' });
    threats.push({ threat: 'Hash Collision (SHA-1)', severity: 'High', likelihood: 'Medium', impact: 'High', status: 'Vulnerable', recommendation: 'Upgrade to SHA-256.' });
  } else {
    strengths.push(`${auth} delivers robust collision resistance.`);
    threats.push({ threat: 'Integrity Tampering', severity: 'Low', likelihood: 'Low', impact: 'Low', status: 'Mitigated', recommendation: 'Maintained with SHA-2 family.' });
  }

  if (dh.includes('Group 2') || dh.includes('1024')) {
    score -= 22;
    weaknesses.push(`${dh} (1024-bit MODP) is vulnerable to Logjam precomputations.`);
    findings.push({ finding: `Weak Diffie-Hellman (${dh})`, severity: 'High', explanation: 'Discrete logarithm precomputation vulnerabilities.', impact: 'Session key eavesdropping.', recommendation: 'Upgrade to DH Group 14 or Group 20.' });
    threats.push({ threat: 'Diffie-Hellman Precomputation (Logjam)', severity: 'High', likelihood: 'High', impact: 'Critical', status: 'Vulnerable', recommendation: 'Mandate DH Group >= 14 or Group 20.' });
  } else {
    strengths.push(`${dh} provides modern key agreement.`);
    threats.push({ threat: 'Key Exchange Eavesdropping', severity: 'Low', likelihood: 'Low', impact: 'Low', status: 'Mitigated', recommendation: 'Satisfies current NIST guidelines.' });
  }

  if (!pfs) {
    score -= 16;
    weaknesses.push('PFS is disabled; compromise of long-term credentials exposes past traffic.');
    findings.push({ finding: 'Perfect Forward Secrecy (PFS) Disabled', severity: 'Medium', explanation: 'Child SAs do not execute independent DH exchange.', impact: 'Retroactive decryption risk.', recommendation: 'Enable PFS in Phase 2 proposals.' });
    threats.push({ threat: 'Retroactive Decryption via Key Leak', severity: 'Medium', likelihood: 'Medium', impact: 'Critical', status: 'At Risk', recommendation: 'Enable PFS immediately.' });
  } else {
    strengths.push('PFS enabled; session keys isolated per renegotiation.');
  }

  if (ike === 'IKEV1') {
    score -= 14;
    weaknesses.push('IKEv1 is legacy; susceptible to Aggressive Mode PSK dictionary attacks.');
    findings.push({ finding: 'Legacy IKE Protocol (IKEv1)', severity: 'High', explanation: 'Lacks modern anti-DoS cookies and resilient state machine.', impact: 'Credential harvesting risk.', recommendation: 'Migrate to IKEv2.' });
    threats.push({ threat: 'IKEv1 Aggressive Mode PSK Cracking', severity: 'High', likelihood: 'Medium', impact: 'High', status: 'Vulnerable', recommendation: 'Migrate to IKEv2.' });
  }

  if (!replay) {
    score -= 15;
    weaknesses.push('Anti-replay protection is disabled; vulnerable to packet duplication.');
    findings.push({ finding: 'Anti-Replay Window Disabled', severity: 'High', explanation: 'ESP sequence counter validation turned off.', impact: 'Susceptible to replay attacks.', recommendation: 'Enable Anti-Replay window.' });
    threats.push({ threat: 'Packet Replay & Sequence Injection', severity: 'High', likelihood: 'High', impact: 'High', status: 'Vulnerable', recommendation: 'Enable Anti-Replay window.' });
  }

  score = Math.max(5, Math.min(100, score));
  let riskLevel = 'LOW';
  if (score < 45) riskLevel = 'CRITICAL';
  else if (score < 70) riskLevel = 'HIGH';
  else if (score < 85) riskLevel = 'MEDIUM';

  return {
    analysis_id: `IPSEC-${Math.random().toString(16).substring(2, 10).toUpperCase()}`,
    timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC',
    config,
    security_assessment: {
      score,
      risk_level: riskLevel,
      risk_summary: score >= 85 ? 'Conforms to CNSA & NIST SP 800-77 enterprise guidelines.' : 'Significant vulnerabilities detected requiring immediate remediation.',
      findings,
      threat_matrix: threats,
      strengths,
      weaknesses,
      recommendations: findings.map(f => `${f.finding}: ${f.recommendation}`),
      metadata_exposure: {
        level: mode === 'Transport' ? 'MEDIUM' : 'LOW',
        summary: mode === 'Transport' ? 'Transport mode exposes original IP header endpoints.' : 'Tunnel mode encapsulates original headers inside gateway IP wrapper.',
        exposed_fields: [
          { field: 'Origin Host IP', status: mode === 'Transport' ? 'EXPOSED' : 'PROTECTED', risk: mode === 'Transport' ? 'Medium' : 'None' },
          { field: 'Destination Host IP', status: mode === 'Transport' ? 'EXPOSED' : 'PROTECTED', risk: mode === 'Transport' ? 'Medium' : 'None' },
          { field: 'Payload Data', status: 'ENCRYPTED', risk: 'None' }
        ]
      }
    },
    ai_classification: {
      overall_confidence: 94.6,
      detected_count: 5,
      inferred_count: 3,
      classifications: [
        { parameter: 'Protocol Identification', value: 'IPsec (ESP/IKE)', confidence: 99.4, status: 'DETECTED', evidence: 'RFC 4301 specification match.' },
        { parameter: 'IKE Protocol Version', value: config.ike_version, confidence: 96.0, status: 'DETECTED', evidence: `Declared protocol suite (${config.ike_version}).` },
        { parameter: 'VPN Mode', value: `${config.mode} Mode`, confidence: 94.0, status: 'DETECTED', evidence: 'Encapsulation framing.' },
        { parameter: 'Confidentiality Cipher', value: config.encryption, confidence: 98.2, status: 'DETECTED', evidence: 'ESP transform proposal.' },
        { parameter: 'Integrity Algorithm', value: config.authentication, confidence: 97.0, status: 'DETECTED', evidence: 'Hash integrity check.' },
        { parameter: 'Key Exchange (DH)', value: config.dh_group, confidence: 96.0, status: 'DETECTED', evidence: 'Phase 1 KE exchange.' },
        { parameter: 'PFS Status', value: config.pfs ? 'Enabled' : 'Disabled', confidence: 92.0, status: 'DETECTED', evidence: 'Child SA policy.' },
        { parameter: 'Traffic Classification', value: config.traffic_type, confidence: 78.5, status: 'INFERRED', evidence: 'MTU distribution heuristics.' }
      ]
    },
    security_association: {
      inbound_spi: '0x8F3C92A1',
      outbound_spi: '0x4E12B07D',
      source_gateway: '198.51.100.15',
      destination_gateway: '203.0.113.88',
      mode: config.mode,
      encryption: config.encryption,
      authentication: config.authentication,
      dh_group: config.dh_group,
      pfs_status: config.pfs ? 'Enabled' : 'Disabled',
      replay_protection: config.replay_protection ? 'Enabled (Window: 64)' : 'Disabled',
      key_lifetime: `${config.key_lifetime} seconds`
    },
    traffic_metrics: {
      packet_count: 14250,
      avg_packet_size: 842,
      encrypted_ratio: 99.4,
      esp_detected: true,
      ah_detected: false,
      ike_detected: true,
      source_ip: '198.51.100.15',
      dest_ip: '203.0.113.88',
      protocol_breakdown: { ESP: 13950, IKE: 260, 'NAT-T': 40 },
      size_distribution: [
        { range: '64-128 B', count: 1200 },
        { range: '129-512 B', count: 3400 },
        { range: '513-1024 B', count: 6850 },
        { range: '1025-1500 B', count: 2800 }
      ]
    },
    reports: {
      executive_report: {
        analysis_id: `IPSEC-${Math.random().toString(16).substring(2, 10).toUpperCase()}`,
        timestamp: new Date().toISOString().substring(0, 10),
        security_score: score,
        risk_level: riskLevel,
        risk_summary: score >= 85 ? 'Conforms to CNSA & NIST SP 800-77 enterprise guidelines.' : 'Significant vulnerabilities detected requiring immediate remediation.',
        protocol_summary: `${config.ike_version} ${config.mode} (${config.encryption} / ${config.authentication})`,
        strengths,
        weaknesses,
        actionable_recommendations: findings.map(f => `${f.finding}: ${f.recommendation}`)
      },
      technical_report: {
        cryptographic_breakdown: {
          ike_version: config.ike_version,
          encryption: config.encryption,
          authentication: config.authentication,
          dh_group: config.dh_group,
          pfs_enabled: config.pfs,
          replay_protection: config.replay_protection,
          key_lifetime_seconds: config.key_lifetime
        }
      }
    }
  };
}
