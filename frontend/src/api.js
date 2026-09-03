export const API_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';
const tokenKey = 'sentinel_access_token';
export const getToken = () => localStorage.getItem(tokenKey);
export const clearToken = () => localStorage.removeItem(tokenKey);
const authHeaders = () => getToken() ? { Authorization: `Bearer ${getToken()}` } : {};

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

async function getJson(path, authenticated = false) {
  const response = await fetch(`${API_URL}${path}`, { headers: authenticated ? authHeaders() : {} });
  if (!response.ok) throw new Error('The security service is unavailable.');
  return response.json();
}

export const getRecentScans = () => getJson('/api/v1/scans?limit=20');
export const getSummary = () => getJson('/api/v1/summary');

async function postJson(path, payload, method = 'POST', authenticated = false) {
  const response = await fetch(`${API_URL}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...(authenticated ? authHeaders() : {}) },
    body: JSON.stringify(payload),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.detail || 'The request could not be completed.');
  return data;
}

export const analyzeEmail = payload => postJson('/api/v1/analyze-email', payload);
export const analyzeNetwork = payload => postJson('/api/v1/analyze-network', payload);
export const getIncidents = () => getJson('/api/v1/incidents');
export const getAnalytics = () => getJson('/api/v1/analytics');
export const createIncident = payload => postJson('/api/v1/incidents', payload, 'POST', true);
export const setIncidentStatus = (id, status) => postJson(`/api/v1/incidents/${id}`, { status }, 'PATCH', true);
export const login = async payload => { const data = await postJson('/api/v1/auth/login', payload); localStorage.setItem(tokenKey, data.access_token); return data.user; };
export const register = async payload => { const data = await postJson('/api/v1/auth/register', payload); localStorage.setItem(tokenKey, data.access_token); return data.user; };
export const getMe = () => getJson('/api/v1/auth/me', true);
export const getUsers = () => getJson('/api/v1/users', true);
export const getAuditLogs = () => getJson('/api/v1/audit-logs?limit=50', true);
export const setUserRole = (id, role) => postJson(`/api/v1/users/${id}/role`, { role }, 'PATCH', true);
export async function downloadIncidentReport() {
  const response = await fetch(`${API_URL}/api/v1/reports/incidents.csv`, { headers: authHeaders() });
  if (!response.ok) { const data = await response.json(); throw new Error(data.detail || 'Report export failed.'); }
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement('a'); link.href = url; link.download = 'sentinel-incidents.csv'; link.click(); URL.revokeObjectURL(url);
}
