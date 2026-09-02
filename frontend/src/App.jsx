import { useMemo, useState } from 'react';
import { analyzeUrl, API_URL } from './api';

const examples = [
  'https://example.com',
  'http://192.168.1.10/login/verify',
  'https://secure-account-login.example.com/update',
];

function ShieldIcon() {
  return <span className="shield" aria-hidden="true">S</span>;
}

function App() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const totals = useMemo(() => ({
    scanned: history.length,
    threats: history.filter(item => item.verdict !== 'low_risk').length,
    safe: history.filter(item => item.verdict === 'low_risk').length,
  }), [history]);

  async function submit(event) {
    event.preventDefault();
    if (!url.trim()) return;
    setLoading(true);
    setError('');
    try {
      const analysis = await analyzeUrl(url);
      setResult(analysis);
      setHistory(current => [analysis, ...current.filter(item => item.normalized_url !== analysis.normalized_url)].slice(0, 6));
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#top"><ShieldIcon /><span>Sentinel<strong>AI</strong></span></a>
        <nav aria-label="Primary navigation">
          <a className="nav-item active" href="#scanner"><span>⌁</span>URL scanner</a>
          <a className="nav-item" href="#history"><span>◴</span>Recent scans</a>
          <a className="nav-item" href="#signals"><span>⌗</span>Risk signals</a>
        </nav>
        <div className="system-card">
          <div><span className="status-dot" />Analysis engine</div>
          <strong>Operational</strong>
          <small>Explainable rule engine v0.1</small>
        </div>
      </aside>

      <main id="top">
        <header className="topbar">
          <div>
            <p className="eyebrow">THREAT INTELLIGENCE CONSOLE</p>
            <h1>URL risk analysis</h1>
          </div>
          <a className="docs-link" href={`${API_URL}/docs`} target="_blank" rel="noreferrer">API docs ↗</a>
        </header>

        <section className="stats" aria-label="Session statistics">
          <article><span>URLs scanned</span><strong>{totals.scanned}</strong><small>This session</small></article>
          <article><span>Threats detected</span><strong className="danger-text">{totals.threats}</strong><small>Suspicious or malicious</small></article>
          <article><span>Low-risk results</span><strong className="safe-text">{totals.safe}</strong><small>No major signals</small></article>
        </section>

        <section className="scanner panel" id="scanner">
          <div className="panel-heading">
            <div><p className="eyebrow">LIVE ANALYSIS</p><h2>Inspect a suspicious URL</h2></div>
            <span className="engine-badge">● Engine ready</span>
          </div>
          <form onSubmit={submit}>
            <label htmlFor="url">URL or domain</label>
            <div className="scan-row">
              <input id="url" value={url} onChange={event => setUrl(event.target.value)} placeholder="https://example.com/login" autoComplete="url" />
              <button disabled={loading}>{loading ? 'Analyzing…' : 'Analyze URL →'}</button>
            </div>
            <div className="examples">
              <span>Try:</span>{examples.map(example => <button type="button" key={example} onClick={() => setUrl(example)}>{example}</button>)}
            </div>
          </form>
          {error && <p className="error" role="alert">{error}</p>}
        </section>

        {result ? (
          <section className="result-grid" id="signals">
            <article className={`score-card panel ${result.verdict}`}>
              <p className="eyebrow">RISK ASSESSMENT</p>
              <div className="score-ring" style={{ '--score': `${result.risk_score * 3.6}deg` }}><strong>{result.risk_score}</strong><span>/ 100</span></div>
              <h2>{result.verdict.replace('_', ' ')}</h2>
              <p className="analyzed-url">{result.normalized_url}</p>
            </article>
            <article className="panel signals-card">
              <div className="panel-heading"><h2>Detected signals</h2><span>{result.signals.length} found</span></div>
              {result.signals.length ? result.signals.map(signal => (
                <div className="signal" key={signal.name}>
                  <span className="signal-icon">!</span>
                  <div><strong>{signal.name.replaceAll('_', ' ')}</strong><p>{signal.description}</p></div>
                  <b>+{signal.weight}</b>
                </div>
              )) : <div className="empty-state"><span>✓</span><p>No major risk signals were detected.</p></div>}
            </article>
          </section>
        ) : (
          <section className="panel empty-result"><span>⌁</span><h2>Ready to investigate</h2><p>Submit a URL to see its risk score, extracted features, and explainable security signals.</p></section>
        )}

        <section className="panel history" id="history">
          <div className="panel-heading"><div><p className="eyebrow">SESSION LOG</p><h2>Recent scans</h2></div><span>{history.length} records</span></div>
          {history.length ? history.map(item => (
            <button key={item.normalized_url} onClick={() => setResult(item)}>
              <span className={`verdict-dot ${item.verdict}`} /><span>{item.normalized_url}</span><b>{item.risk_score}</b><em>{item.verdict.replace('_', ' ')}</em>
            </button>
          )) : <p className="empty-history">Your analyzed URLs will appear here.</p>}
        </section>
      </main>
    </div>
  );
}

export default App;
