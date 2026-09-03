import React, { useEffect, useState } from 'react';
import { analyzeEmail, analyzeNetwork, analyzeUrl, API_URL, createIncident, getIncidents, getRecentScans, getSummary, setIncidentStatus } from './api';

const examples = ['https://example.com', 'http://192.168.1.10/login/verify', 'https://secure-account-login.example.com/update'];
const modules = [['url', '⌁', 'URL scanner'], ['email', '✉', 'Email analyzer'], ['network', '⌗', 'Network anomaly'], ['incidents', '◴', 'Incidents']];

function Signals({ result }) {
  if (!result) return <section className="panel empty-result"><span>⌁</span><h2>Ready to investigate</h2><p>Run an analysis to see a risk score and explainable security signals.</p></section>;
  return <section className="result-grid" id="signals">
    <article className={`score-card panel ${result.verdict}`}><p className="eyebrow">RISK ASSESSMENT</p><div className="score-ring" style={{ '--score': `${result.risk_score * 3.6}deg` }}><strong>{result.risk_score}</strong><span>/ 100</span></div><h2>{result.verdict.replace('_', ' ')}</h2><p>{result.summary || result.normalized_url}</p></article>
    <article className="panel signals-card"><div className="panel-heading"><h2>Detected signals</h2><span>{result.signals.length} found</span></div>{result.signals.length ? result.signals.map(signal => <div className="signal" key={signal.name}><span className="signal-icon">!</span><div><strong>{signal.name.replaceAll('_', ' ')}</strong><p>{signal.description}</p></div><b>+{signal.weight}</b></div>) : <div className="empty-state"><span>✓</span><p>No major risk signals were detected.</p></div>}</article>
  </section>;
}

export default function App() {
  const [active, setActive] = useState('url');
  const [url, setUrl] = useState('');
  const [email, setEmail] = useState({ sender: '', text: '' });
  const [network, setNetwork] = useState({ failed_login_count: 0, requests_per_minute: 1, bytes_out: 0, hour: 12, is_new_country: false, privileged_action: false });
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [totals, setTotals] = useState({ scanned: 0, threats: 0, safe: 0 });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => { Promise.all([getRecentScans(), getSummary(), getIncidents()]).then(([scans, summary, cases]) => { setHistory(scans); setTotals(summary); setIncidents(cases); }).catch(() => setError('The API is starting or unavailable. Retry shortly.')); }, []);

  async function run(event, analyzer, payload) {
    event.preventDefault(); setLoading(true); setError('');
    try {
      const analysis = await analyzer(payload); setResult(analysis);
      if (analysis.normalized_url) {
        setHistory(current => [analysis, ...current].slice(0, 20));
        setTotals(current => ({ scanned: current.scanned + 1, threats: current.threats + (analysis.verdict === 'low_risk' ? 0 : 1), safe: current.safe + (analysis.verdict === 'low_risk' ? 1 : 0) }));
      }
    } catch (requestError) { setError(requestError.message); } finally { setLoading(false); }
  }

  async function escalate() {
    if (!result) return;
    const incident = await createIncident({ title: `${result.analysis_type || 'URL'} analysis: ${result.verdict.replace('_', ' ')}`, description: result.summary || result.normalized_url, severity: result.risk_score >= 70 ? 'critical' : result.risk_score >= 45 ? 'high' : 'medium', source: result.analysis_type || 'url-scanner' });
    setIncidents(current => [incident, ...current]); setActive('incidents');
  }

  async function changeStatus(id, status) { const updated = await setIncidentStatus(id, status); setIncidents(current => current.map(item => item.id === id ? updated : item)); }
  const switchModule = id => { setActive(id); setResult(null); setError(''); };

  return <div className="app-shell">
    <aside className="sidebar"><a className="brand" href="#top"><span className="shield">S</span><span>Sentinel<strong>AI</strong></span></a><nav>{modules.map(([id, icon, label]) => <button key={id} className={`nav-item ${active === id ? 'active' : ''}`} onClick={() => switchModule(id)}><span>{icon}</span>{label}</button>)}</nav><div className="system-card"><div><span className="status-dot" />Analysis engine</div><strong>Operational</strong><small>Multi-signal security engine v0.2</small></div></aside>
    <main id="top"><header className="topbar"><div><p className="eyebrow">THREAT INTELLIGENCE CONSOLE</p><h1>{modules.find(item => item[0] === active)[2]}</h1></div><a className="docs-link" href={`${API_URL}/docs`} target="_blank" rel="noreferrer">API docs ↗</a></header>
      <section className="stats"><article><span>URLs scanned</span><strong>{totals.scanned}</strong><small>Persisted analyses</small></article><article><span>Threats detected</span><strong className="danger-text">{totals.threats}</strong><small>Suspicious or malicious</small></article><article><span>Open incidents</span><strong className="safe-text">{incidents.filter(item => item.status !== 'resolved').length}</strong><small>Requires attention</small></article></section>

      {active === 'url' && <><section className="scanner panel"><div className="panel-heading"><div><p className="eyebrow">LIVE ANALYSIS</p><h2>Inspect a suspicious URL</h2></div><span className="engine-badge">● Engine ready</span></div><form onSubmit={e => run(e, analyzeUrl, url)}><label htmlFor="url">URL or domain</label><div className="scan-row"><input id="url" value={url} onChange={e => setUrl(e.target.value)} placeholder="https://example.com/login" required /><button disabled={loading}>{loading ? 'Analyzing…' : 'Analyze URL →'}</button></div><div className="examples"><span>Try:</span>{examples.map(item => <button type="button" key={item} onClick={() => setUrl(item)}>{item}</button>)}</div></form></section><Signals result={result} />{result && result.risk_score >= 30 && <button className="escalate" onClick={escalate}>Create security incident</button>}<section className="panel history"><div className="panel-heading"><h2>Recent URL scans</h2><span>{history.length} records</span></div>{history.map(item => <button key={item.id} onClick={() => setResult(item)}><span className={`verdict-dot ${item.verdict}`} /><span>{item.normalized_url}</span><b>{item.risk_score}</b><em>{item.verdict.replace('_', ' ')}</em></button>)}</section></>}

      {active === 'email' && <><section className="panel scanner"><div className="panel-heading"><div><p className="eyebrow">PHISHING DETECTION</p><h2>Analyze suspicious email content</h2></div><span className="engine-badge">● Logistic baseline</span></div><form onSubmit={e => run(e, analyzeEmail, email)}><label>Sender address</label><input value={email.sender} onChange={e => setEmail({ ...email, sender: e.target.value })} placeholder="security@example.com" /><label>Email message</label><textarea value={email.text} onChange={e => setEmail({ ...email, text: e.target.value })} placeholder="Paste the suspicious email text here…" required minLength="10" /><button disabled={loading}>Analyze email →</button></form></section><Signals result={result} />{result && result.risk_score >= 30 && <button className="escalate" onClick={escalate}>Create security incident</button>}</>}

      {active === 'network' && <><section className="panel scanner"><div className="panel-heading"><div><p className="eyebrow">ANOMALY DETECTION</p><h2>Evaluate a network security event</h2></div><span className="engine-badge">● Baseline ready</span></div><form className="network-form" onSubmit={e => run(e, analyzeNetwork, network)}><label>Failed logins<input type="number" min="0" value={network.failed_login_count} onChange={e => setNetwork({ ...network, failed_login_count: Number(e.target.value) })} /></label><label>Requests/minute<input type="number" min="0" value={network.requests_per_minute} onChange={e => setNetwork({ ...network, requests_per_minute: Number(e.target.value) })} /></label><label>Outbound bytes<input type="number" min="0" value={network.bytes_out} onChange={e => setNetwork({ ...network, bytes_out: Number(e.target.value) })} /></label><label>Hour (0–23)<input type="number" min="0" max="23" value={network.hour} onChange={e => setNetwork({ ...network, hour: Number(e.target.value) })} /></label><label className="check"><input type="checkbox" checked={network.is_new_country} onChange={e => setNetwork({ ...network, is_new_country: e.target.checked })} /> New source country</label><label className="check"><input type="checkbox" checked={network.privileged_action} onChange={e => setNetwork({ ...network, privileged_action: e.target.checked })} /> Privileged action</label><button disabled={loading}>Analyze event →</button></form></section><Signals result={result} />{result && result.risk_score >= 30 && <button className="escalate" onClick={escalate}>Create security incident</button>}</>}

      {active === 'incidents' && <section className="panel incident-list"><div className="panel-heading"><div><p className="eyebrow">CASE MANAGEMENT</p><h2>Security incidents</h2></div><span>{incidents.length} cases</span></div>{incidents.length ? incidents.map(item => <article key={item.id}><span className={`severity ${item.severity}`}>{item.severity}</span><div><h3>{item.title}</h3><p>{item.description}</p><small>{item.source} · {item.created_at}</small></div><select value={item.status} onChange={e => changeStatus(item.id, e.target.value)}><option value="open">Open</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option></select></article>) : <div className="empty-state"><p>No incidents have been created.</p></div>}</section>}
      {error && <p className="error" role="alert">{error}</p>}
    </main>
  </div>;
}
