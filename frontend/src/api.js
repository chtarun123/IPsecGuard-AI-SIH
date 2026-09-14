/**
 * IPsecGuard AI - Frontend API Service Client
 * Connects React components with FastAPI backend endpoints.
 */

const API_BASE = '/api';

export async function checkHealth() {
  try {
    const res = await fetch(`${API_BASE}/health`);
    if (!res.ok) throw new Error('Backend offline');
    return await res.json();
  } catch (err) {
    console.error('Health check failed:', err);
    return { status: 'offline', error: err.message };
  }
}

export async function fetchSampleConfigurations() {
  const res = await fetch(`${API_BASE}/sample-configurations`);
  if (!res.ok) throw new Error('Failed to load demo datasets');
  return await res.json();
}

export async function analyzeConfiguration(config) {
  const res = await fetch(`${API_BASE}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config)
  });
  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    throw new Error(errData.detail || 'Analysis request failed');
  }
  return await res.json();
}

export async function uploadPCAPFile(file) {
  const formData = new FormData();
  formData.append('file', file);

  const res = await fetch(`${API_BASE}/upload-pcap`, {
    method: 'POST',
    body: formData
  });
  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    throw new Error(errData.detail || 'PCAP upload failed');
  }
  return await res.json();
}

export async function fetchReport(analysisId, format = 'json') {
  const res = await fetch(`${API_BASE}/report/${analysisId}?format=${format}`);
  if (!res.ok) throw new Error('Failed to fetch report');
  if (format === 'html') {
    return await res.text();
  }
  return await res.json();
}

export async function compareConfigs(configA, configB, labelA = 'Configuration A', labelB = 'Configuration B') {
  const res = await fetch(`${API_BASE}/compare`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      config_a: configA,
      config_b: configB,
      label_a: labelA,
      label_b: labelB
    })
  });
  if (!res.ok) throw new Error('Failed to compare configurations');
  return await res.json();
}
