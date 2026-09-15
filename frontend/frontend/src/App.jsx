import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  LayoutDashboard, 
  Sliders, 
  Activity, 
  ShieldAlert, 
  AlertTriangle, 
  FileText, 
  Layers, 
  GitCompare, 
  Info, 
  Upload,
  RefreshCw,
  CheckCircle2,
  XCircle,
  ExternalLink
} from 'lucide-react';

import Dashboard from './components/Dashboard';
import ConfigurationPanel from './components/ConfigurationPanel';
import AnalysisResult from './components/AnalysisResult';
import RiskMatrix from './components/RiskMatrix';
import TrafficAnalysis from './components/TrafficAnalysis';
import ReportPanel from './components/ReportPanel';
import ComparePanel from './components/ComparePanel';
import ArchitectureView from './components/ArchitectureView';

import { checkHealth, fetchSampleConfigurations, analyzeConfiguration, uploadPCAPFile } from './api';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [backendOnline, setBackendOnline] = useState(false);
  const [sampleConfigs, setSampleConfigs] = useState([]);
  const [activePresetId, setActivePresetId] = useState('strong-enterprise');
  
  const [config, setConfig] = useState({
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
  });

  const [analysisData, setAnalysisData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [notification, setNotification] = useState(null);

  const showNotification = (msg, type = 'info') => {
    setNotification({ msg, type });
    setTimeout(() => setNotification(null), 4000);
  };

  // Initial load: Verify health, load demo datasets, and run baseline analysis
  useEffect(() => {
    const initApp = async () => {
      try {
        const health = await checkHealth();
        if (health.status === 'online') {
          setBackendOnline(true);
        }

        const samplesRes = await fetchSampleConfigurations();
        if (samplesRes && samplesRes.samples) {
          setSampleConfigs(samplesRes.samples);
          const strong = samplesRes.samples.find(s => s.id === 'strong-enterprise');
          if (strong) {
            setConfig(strong.config);
          }
        }

        // Run initial analysis
        const initialRes = await analyzeConfiguration(config);
        setAnalysisData(initialRes);
      } catch (err) {
        console.error('App init error:', err);
        setBackendOnline(false);
      }
    };

    initApp();
  }, []);

  const handleConfigChange = (field, value) => {
    setConfig(prev => ({
      ...prev,
      [field]: value
    }));
    setActivePresetId(null);
  };

  const handleSelectPreset = async (presetId) => {
    setActivePresetId(presetId);
    const matched = sampleConfigs.find(s => s.id === presetId);
    if (!matched) return;

    setConfig(matched.config);
    setLoading(true);
    try {
      const res = await analyzeConfiguration(matched.config);
      setAnalysisData(res);
      showNotification(`Loaded and analyzed: ${matched.name}`, 'success');
    } catch (err) {
      showNotification(`Analysis error: ${err.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleRunAnalysis = async () => {
    setLoading(true);
    try {
      const res = await analyzeConfiguration(config);
      setAnalysisData(res);
      showNotification('Analysis complete. Dashboard metrics updated.', 'success');
    } catch (err) {
      showNotification(`Analysis failed: ${err.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleUploadPCAP = async (file) => {
    setUploading(true);
    try {
      const res = await uploadPCAPFile(file);
      setAnalysisData(res);
      if (res.config) {
        setConfig(res.config);
      }
      setActivePresetId(null);
      showNotification(`PCAP analyzed: ${file.name} (${res.traffic_metrics?.packet_count || 0} packets)`, 'success');
      setActiveTab('traffic');
    } catch (err) {
      showNotification(`Upload failed: ${err.message}`, 'error');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="app-container">
      {/* Sidebar Navigation */}
      <aside className="sidebar">
        <div className="brand-section">
          <div className="brand-logo">
            <Shield style={{ width: 22, height: 22 }} />
          </div>
          <div>
            <div className="brand-title">IPsecGuard AI</div>
            <div className="brand-subtitle">Protocol Analyzer</div>
          </div>
        </div>

        <nav className="nav-links">
          <div 
            className={`nav-item ${activeTab === 'dashboard' ? 'active' : ''}`}
            onClick={() => setActiveTab('dashboard')}
          >
            <LayoutDashboard style={{ width: 16, height: 16 }} />
            Dashboard
          </div>

          <div 
            className={`nav-item ${activeTab === 'analyzer' ? 'active' : ''}`}
            onClick={() => setActiveTab('analyzer')}
          >
            <Sliders style={{ width: 16, height: 16 }} />
            VPN Analyzer
          </div>

          <div 
            className={`nav-item ${activeTab === 'traffic' ? 'active' : ''}`}
            onClick={() => setActiveTab('traffic')}
          >
            <Activity style={{ width: 16, height: 16 }} />
            Traffic Analysis
          </div>

          <div 
            className={`nav-item ${activeTab === 'assessment' ? 'active' : ''}`}
            onClick={() => setActiveTab('assessment')}
          >
            <ShieldAlert style={{ width: 16, height: 16 }} />
            Security Assessment
          </div>

          <div 
            className={`nav-item ${activeTab === 'analysis' ? 'active' : ''}`}
            onClick={() => setActiveTab('analysis')}
          >
            <Shield style={{ width: 16, height: 16 }} />
            Protocol &amp; SA Inspection
          </div>

          <div 
            className={`nav-item ${activeTab === 'threats' ? 'active' : ''}`}
            onClick={() => setActiveTab('threats')}
          >
            <AlertTriangle style={{ width: 16, height: 16 }} />
            Threat Matrix
          </div>

          <div 
            className={`nav-item ${activeTab === 'compare' ? 'active' : ''}`}
            onClick={() => setActiveTab('compare')}
          >
            <GitCompare style={{ width: 16, height: 16 }} />
            Compare Configurations
          </div>

          <div 
            className={`nav-item ${activeTab === 'reports' ? 'active' : ''}`}
            onClick={() => setActiveTab('reports')}
          >
            <FileText style={{ width: 16, height: 16 }} />
            Reports &amp; Export
          </div>

          <div 
            className={`nav-item ${activeTab === 'architecture' ? 'active' : ''}`}
            onClick={() => setActiveTab('architecture')}
          >
            <Layers style={{ width: 16, height: 16 }} />
            Architecture
          </div>

          <div 
            className={`nav-item ${activeTab === 'about' ? 'active' : ''}`}
            onClick={() => setActiveTab('about')}
          >
            <Info style={{ width: 16, height: 16 }} />
            About &amp; SIH Guide
          </div>
        </nav>

        <div className="sidebar-footer">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
            <span>Backend Engine:</span>
            <span className="soc-badge" style={{
              color: backendOnline ? 'var(--emerald)' : 'var(--rose)',
              borderColor: backendOnline ? 'rgba(16, 185, 129, 0.4)' : 'rgba(239, 68, 68, 0.4)',
              background: backendOnline ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)'
            }}>
              <span className="pulse-dot" style={{ background: backendOnline ? 'var(--emerald)' : 'var(--rose)' }} />
              {backendOnline ? 'ONLINE' : 'OFFLINE'}
            </span>
          </div>
          <div>Smart India Hackathon Prototype &bull; v1.0.0</div>
        </div>
      </aside>

      {/* Main App Body */}
      <div className="main-wrapper">
        {/* Top Header */}
        <header className="topbar">
          <div className="topbar-left">
            <div>
              <div className="topbar-title">IPsecGuard AI</div>
              <div className="topbar-tagline">
                AI-Powered IPsec VPN Protocol Analyzer &amp; Security Assessment Framework
              </div>
            </div>
          </div>

          <div className="topbar-right">
            <button
              className="btn btn-secondary"
              onClick={handleRunAnalysis}
              disabled={loading}
              title="Refresh analysis"
            >
              <RefreshCw style={{ width: 14, height: 14, animation: loading ? 'spin 1s linear infinite' : 'none' }} />
              Refresh
            </button>

            <button
              className="btn btn-outline-cyan"
              onClick={() => setActiveTab('analyzer')}
            >
              <Upload style={{ width: 14, height: 14 }} />
              Upload PCAP
            </button>

            <button
              className="btn btn-primary"
              onClick={() => setActiveTab('reports')}
            >
              <FileText style={{ width: 14, height: 14 }} />
              Security Report
            </button>
          </div>
        </header>

        {/* Global Notification Toast */}
        {notification && (
          <div style={{
            position: 'fixed',
            top: 74,
            right: 24,
            zIndex: 9999,
            background: notification.type === 'error' ? 'rgba(239, 68, 68, 0.9)' : 'rgba(6, 182, 212, 0.9)',
            color: '#fff',
            padding: '10px 18px',
            borderRadius: '8px',
            fontSize: '13px',
            fontWeight: 600,
            boxShadow: '0 8px 20px rgba(0, 0, 0, 0.4)',
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }}>
            {notification.type === 'error' ? <XCircle style={{ width: 16, height: 16 }} /> : <CheckCircle2 style={{ width: 16, height: 16 }} />}
            {notification.msg}
          </div>
        )}

        {/* Active Tab View */}
        <main className="content-area">
          {activeTab === 'dashboard' && (
            <Dashboard
              analysisData={analysisData}
              sampleConfigs={sampleConfigs}
              activePresetId={activePresetId}
              onSelectPreset={handleSelectPreset}
              onAnalyze={handleRunAnalysis}
              loading={loading}
              setActiveTab={setActiveTab}
            />
          )}

          {activeTab === 'analyzer' && (
            <ConfigurationPanel
              config={config}
              onChangeConfig={handleConfigChange}
              onAnalyze={handleRunAnalysis}
              loading={loading}
              sampleConfigs={sampleConfigs}
              activePresetId={activePresetId}
              onSelectPreset={handleSelectPreset}
              onUploadPCAP={handleUploadPCAP}
              uploading={uploading}
            />
          )}

          {activeTab === 'traffic' && (
            <TrafficAnalysis analysisData={analysisData} />
          )}

          {activeTab === 'assessment' && (
            <RiskMatrix analysisData={analysisData} />
          )}

          {activeTab === 'analysis' && (
            <AnalysisResult analysisData={analysisData} />
          )}

          {activeTab === 'threats' && (
            <RiskMatrix analysisData={analysisData} />
          )}

          {activeTab === 'compare' && (
            <ComparePanel sampleConfigs={sampleConfigs} />
          )}

          {activeTab === 'reports' && (
            <ReportPanel analysisData={analysisData} />
          )}

          {activeTab === 'architecture' && (
            <ArchitectureView />
          )}

          {activeTab === 'about' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
              <div className="card-section">
                <div className="card-section-header">
                  <div className="section-title">
                    <Info style={{ width: 18, height: 18, color: 'var(--cyan)' }} />
                    Smart India Hackathon Project Blueprint
                  </div>
                </div>
                <div style={{ fontSize: '14px', lineHeight: '1.6', color: 'var(--text-secondary)' }}>
                  <h3 style={{ color: 'var(--text-primary)', marginBottom: '8px' }}>
                    Title: AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework
                  </h3>
                  <p style={{ marginBottom: '14px' }}>
                    <strong>IPsecGuard AI</strong> delivers deep protocol introspection, cryptographic assurance, and automated risk scoring for defensible IPsec tunnel architectures. Designed specifically for cybersecurity operations centers (SOC) and enterprise network compliance teams.
                  </p>

                  <h4 style={{ color: 'var(--cyan)', marginTop: '16px', marginBottom: '8px' }}>
                    Key SIH Evaluation Criteria Met:
                  </h4>
                  <ul style={{ paddingLeft: '20px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <li><strong>Fully Functional Local Prototype:</strong> Operates natively on a student laptop with standard Python 3.10+ and Vite/React.</li>
                    <li><strong>Zero Paid Dependencies:</strong> Runs 100% offline without cloud API tokens or external subscription costs.</li>
                    <li><strong>Dual Analysis Modes:</strong> Instant 5-preset Demo Dataset evaluation + Real binary PCAP / PCAPNG packet capture upload.</li>
                    <li><strong>Explainable AI Classification:</strong> Calibrated confidence metrics with explicit segregation of Detected vs Inferred fields.</li>
                    <li><strong>Mathematical Security Scoring:</strong> 100-point deduction model grounded in RFC 4301, RFC 7296, RFC 8221, and NIST SP 800-77.</li>
                    <li><strong>Full Executive &amp; Technical Reporting:</strong> Instant downloadable HTML audit certificates with complete threat matrices.</li>
                  </ul>
                </div>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
