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
