import { useCallback, useEffect, useState } from "react";
import { getMessageHistory, scanMessage } from "../api.js";
import RiskBadge from "../components/RiskBadge.jsx";
import "./MessagesPage.css";

const MAX_CHARS = 2000;

// One entry per backend verdict (app/routes/message.py). Unknown verdicts are errors.
const VERDICTS = {
  smishing_registry_match: {
    title: "Known smishing — registry match",
    text: "This exact message (after canonicalization) is registered as a known threat.",
  },
  likely_smishing: {
    title: "Likely smishing (model prediction)",
    text: "The model predicts a phishing (smishing) message. Predictions can be wrong.",
  },
  generic_spam: {
    title: "Generic spam (model prediction)",
    text: "The model predicts unsolicited spam. This is not the same as smishing.",
  },
  likely_legitimate: {
    title: "Likely legitimate (model prediction)",
    text: "The model predicts a legitimate message. This is not proof that it is safe.",
  },
  unavailable: {
    title: "Detection unavailable",
    text: "The message model could not run. No verdict is available — this is not a safety result.",
  },
};

const REGISTRY = {
  match_threat: "Message hash found in the threat registry.",
  match_non_threat: "Message hash is registered without a threat verdict.",
  no_match: "Registry checked: hash not found. Absence does not mean the message is safe.",
  unavailable: "Threat registry unavailable during this scan.",
};

const percent = (value) => (typeof value === "number" ? `${Math.round(value * 100)}%` : "—");

function MessageResult({ result }) {
  const verdict = VERDICTS[result.verdict];
  const p = result.model?.probabilities;
  return (
    <div className="card message-result" role="status">
      <div className="message-result-header">
        <RiskBadge level={result.risk_level} />
        <h2 className="message-result-title">{verdict.title}</h2>
      </div>
      <p>{verdict.text}</p>

      <section aria-label="Model output" className="message-section">
        <h3>Model</h3>
        {result.model.status === "ok" && p ? (
          <>
            <ul className="message-scores">
              <li>Smishing: {percent(p.smishing)}</li>
              <li>Generic spam: {percent(p.generic_spam)}</li>
              <li>Legitimate: {percent(p.legitimate)}</li>
            </ul>
            <p className="message-note">
              Model scores, not calibrated real-world probabilities. Version: {result.model.model_version}
            </p>
          </>
        ) : (
          <p className="message-note">Model unavailable: {result.model.error || "unknown error"}</p>
        )}
      </section>

      <section aria-label="Threat registry" className="message-section">
        <h3>Threat registry</h3>
        <p>{REGISTRY[result.registry.status] || REGISTRY.unavailable}</p>
      </section>

      {result.findings.length > 0 && (
        <section aria-label="Warning signs" className="message-section">
          <h3>Warning signs (simple checks)</h3>
          <ul>{result.findings.map((f) => <li key={f}>{f}</li>)}</ul>
        </section>
      )}

      <details className="message-section">
        <summary>Limitations</summary>
        <ul>{result.limitations.map((l) => <li key={l}>{l}</li>)}</ul>
      </details>

      {!result.persisted && <p className="message-note">This result was not saved to history.</p>}
    </div>
  );
}

function validResponse(data) {
  return data && VERDICTS[data.verdict] && data.model && data.registry &&
    Array.isArray(data.findings) && Array.isArray(data.limitations);
}

export default function MessagesPage() {
  const [text, setText] = useState("");
  const [validation, setValidation] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState(null);
  const [historyError, setHistoryError] = useState(null);

  const loadHistory = useCallback(async () => {
    setHistoryError(null);
    try {
      const data = await getMessageHistory();
      if (!Array.isArray(data)) throw { message: "Unexpected response from /message/history." };
      setHistory(data);
    } catch (err) {
      setHistoryError(err);
      setHistory([]);
    }
  }, []);

  useEffect(() => { loadHistory(); }, [loadHistory]);

  async function handleSubmit(e) {
    e.preventDefault();
    if (!text.trim()) return setValidation("Please paste a message to scan.");
    if (text.length > MAX_CHARS) return setValidation(`Messages are limited to ${MAX_CHARS} characters.`);
    setValidation("");
    setResult(null);
    setError(null);
    setLoading(true);
    try {
      const data = await scanMessage(text);
      if (!validResponse(data)) throw { type: "parse", message: "Unexpected response from the server. No result is available." };
      setResult(data);
      loadHistory();
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="messages-page">
      <h1 className="section-title" style={{ marginBottom: 0 }}>Message Scanner</h1>
      <p className="section-subtitle">
        Paste an SMS or text message to check it for smishing. The text is sent only when you press
        Scan, is not stored, and only a hash is used for the registry lookup.
      </p>

      <form onSubmit={handleSubmit} noValidate className="messages-form">
        <label htmlFor="message-input" className="sr-only">Message to scan</label>
        <textarea
          id="message-input"
          className={`input messages-input${validation ? " input-error" : ""}`}
          rows={5}
          maxLength={MAX_CHARS}
          value={text}
          onChange={(e) => { setText(e.target.value); if (validation) setValidation(""); }}
          disabled={loading}
          placeholder="Paste a text message here"
          spellCheck="false"
        />
        <div className="messages-actions">
          <span className="message-note">{text.length}/{MAX_CHARS}</span>
          <button type="submit" className="btn btn-primary" disabled={loading}>
            {loading ? "Scanning…" : "Scan message"}
          </button>
        </div>
        {validation && <p className="scanner-validation-error" role="alert">{validation}</p>}
      </form>

      {loading && <div className="card" aria-busy="true">Scanning…</div>}
      {!loading && error && (
        <div className="error-box" role="alert">
          <strong>Scan failed:</strong> {error.message || "Unknown error"}. No result is available.
        </div>
      )}
      {!loading && result && <MessageResult result={result} />}

      <h2 className="section-title messages-history-title">Message scan history</h2>
      <p className="section-subtitle">Metadata only. Message text is never stored.</p>
      {historyError && <div className="error-box" role="alert">Could not load history: {historyError.message}</div>}
      {history === null ? (
        <div className="card" aria-busy="true">Loading…</div>
      ) : history.length === 0 ? (
        !historyError && <div className="empty-state">No message scans yet.</div>
      ) : (
        <table className="messages-table">
          <thead>
            <tr><th>#</th><th>When</th><th>Verdict</th><th>Risk</th><th>Smishing score</th><th>Registry</th><th>Length</th></tr>
          </thead>
          <tbody>
            {history.map((item) => (
              <tr key={item.id}>
                <td>{item.id}</td>
                <td>{item.created_at ? new Date(item.created_at).toLocaleString() : "—"}</td>
                <td>{VERDICTS[item.verdict]?.title || item.verdict}</td>
                <td><RiskBadge level={item.risk_level} /></td>
                <td>{percent(item.probability_smishing)}</td>
                <td>{item.registry_status}</td>
                <td>{item.message_length}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
