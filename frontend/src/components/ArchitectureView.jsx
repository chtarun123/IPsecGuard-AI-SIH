import React from 'react';
import { Layers, ArrowDown, Cpu, Shield, FileText, Database, Radio, Activity, Lock, Eye } from 'lucide-react';

export default function ArchitectureView() {
  const steps = [
    {
      step: 1,
      title: "PCAP Ingestion & Live Packet Capture",
      icon: <Radio style={{ width: 20, height: 20, color: 'var(--cyan)' }} />,
      desc: "Ingests standard Libpcap binary files (.pcap, .pcapng) or declared IPsec tunnel parameters without requiring external proprietary software or administrative network drivers."
    },
    {
      step: 2,
      title: "Deep Packet Header Analysis",
      icon: <Activity style={{ width: 20, height: 20, color: 'var(--purple)' }} />,
      desc: "Extracts Link Layer, IPv4/IPv6 headers, UDP 500 (ISAKMP), UDP 4500 (NAT-Traversal), ESP (Protocol 50), and AH (Protocol 51). Identifies Security Parameter Indexes (SPIs) and sequence counters."
    },
    {
      step: 3,
      title: "Protocol Identification & State Machine",
      icon: <Lock style={{ width: 20, height: 20, color: 'var(--emerald)' }} />,
      desc: "Verifies whether packets conform to RFC 4301 and RFC 7296. Differentiates IKEv1 Aggressive/Main mode handshakes from IKEv2 four-message initial exchanges."
    },
    {
      step: 4,
      title: "AI-Assisted Protocol Classification Engine",
      icon: <Cpu style={{ width: 20, height: 20, color: 'var(--cyan)' }} />,
      desc: "Computes calibrated confidence metrics across 8 protocol attributes. Rigorously segregates empirically 'DETECTED' parameters from heuristic 'INFERRED' traffic attributes to prevent hallucinated deductions."
    },
    {
      step: 5,
      title: "Security Assessment & Deduction Engine",
      icon: <Shield style={{ width: 20, height: 20, color: 'var(--amber)' }} />,
      desc: "Applies mathematically structured deductions starting from 100 baseline points based on NIST SP 800-77, Sweet32 block vulnerabilities, Logjam DH weak prime risks, and PFS forward confidentiality rules."
    },
    {
      step: 6,
      title: "Explainable Risk Scoring & Tiering",
      icon: <Layers style={{ width: 20, height: 20, color: 'var(--rose)' }} />,
      desc: "Categorizes overall security posture into LOW (>=80), MEDIUM (60-79), HIGH (40-59), or CRITICAL (<40), producing an audit log of positive strengths and prioritized weaknesses."
    },
    {
      step: 7,
      title: "Dynamic Threat Matrix Generation",
      icon: <Eye style={{ width: 20, height: 20, color: 'var(--purple)' }} />,
      desc: "Cross-references detected vulnerabilities against known attack vectors (e.g., PSK offline dictionary attacks, bit-flipping on CBC, session replay, metadata topology leaks) and flags mitigation statuses."
    },
    {
      step: 8,
      title: "Executive & Technical Report Generation",
      icon: <FileText style={{ width: 20, height: 20, color: 'var(--cyan)' }} />,
      desc: "Compiles self-contained compliance reports for CISO executive reviews and network engineering audits with one-click HTML/PDF download capabilities."
    },
    {
      step: 9,
      title: "SOC Defensive Dashboard UI",
      icon: <Database style={{ width: 20, height: 20, color: 'var(--emerald)' }} />,
      desc: "Visualizes the complete assessment in real-time with dark SOC telemetry styling, configuration policy diff tools, and interactive MTU packet distribution charts."
    }
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <div className="card-section">
        <div className="card-section-header">
          <div className="section-title">
            <Layers style={{ width: 18, height: 18, color: 'var(--cyan)' }} />
            IPsecGuard AI Architectural Pipeline
          </div>
          <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            System Dataflow &amp; Processing Hierarchy
          </span>
        </div>
        <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: '1.6' }}>
          IPsecGuard AI is architected as an end-to-end defensive intelligence pipeline that translates raw wire captures or security association proposals into quantifiable security posture scores and prioritized remediation roadmaps.
        </p>
      </div>

      <div className="flow-container">
        {steps.map((s, idx) => (
          <React.Fragment key={s.step}>
            <div className="flow-step">
              <div className="step-num">{s.step}</div>
              <div style={{ flexGrow: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px' }}>
                  {s.icon}
                  <strong style={{ color: 'var(--text-primary)', fontSize: '15px' }}>{s.title}</strong>
                </div>
                <p style={{ color: 'var(--text-secondary)', fontSize: '13px', lineHeight: '1.5' }}>
                  {s.desc}
                </p>
              </div>
            </div>
            {idx < steps.length - 1 && (
              <div style={{ display: 'flex', justifyContent: 'center', margin: '-6px 0' }}>
                <ArrowDown style={{ width: 18, height: 18, color: 'var(--cyan)' }} />
              </div>
            )}
          </React.Fragment>
        ))}
      </div>
    </div>
  );
}
