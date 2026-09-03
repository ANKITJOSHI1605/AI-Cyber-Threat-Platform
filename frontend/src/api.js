export const API_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

export async function analyzeUrl(url) {
  const response = await fetch(`${API_URL}/api/v1/analyze-url`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });

  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.detail || 'The URL could not be analyzed.');
  }
  return data;
}

async function getJson(path) {
  const response = await fetch(`${API_URL}${path}`);
  if (!response.ok) throw new Error('The security service is unavailable.');
  return response.json();
}

export const getRecentScans = () => getJson('/api/v1/scans?limit=20');
export const getSummary = () => getJson('/api/v1/summary');

async function postJson(path, payload, method = 'POST') {
  const response = await fetch(`${API_URL}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.detail || 'The request could not be completed.');
  return data;
}

export const analyzeEmail = payload => postJson('/api/v1/analyze-email', payload);
export const analyzeNetwork = payload => postJson('/api/v1/analyze-network', payload);
export const getIncidents = () => getJson('/api/v1/incidents');
export const createIncident = payload => postJson('/api/v1/incidents', payload);
export const setIncidentStatus = (id, status) => postJson(`/api/v1/incidents/${id}`, { status }, 'PATCH');
