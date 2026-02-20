import { useState, useEffect, useCallback, useRef } from "react";

// Crypto helpers (all client-side, zero-knowledge)
async function deriveMasterKey(password, saltB64) {
  const enc = new TextEncoder();
  const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey", "deriveBits"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 310000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function deriveAuthHash(password, saltB64) {
  const enc = new TextEncoder();
  const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial, 256
  );
  return btoa(String.fromCharCode(...new Uint8Array(bits)));
}

async function encryptVault(masterKey, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, masterKey, enc.encode(plaintext));
  return {
    encrypted_data: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
    iv: btoa(String.fromCharCode(...iv)),
  };
}

async function decryptVault(masterKey, encryptedData, ivB64) {
  const ciphertext = Uint8Array.from(atob(encryptedData), c => c.charCodeAt(0));
  const iv = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, masterKey, ciphertext);
  return new TextDecoder().decode(plaintext);
}

function generateSalt() {
  return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
}

function generatePassword(opts = {}) {
  const { length = 20, upper = true, lower = true, numbers = true, symbols = true } = opts;
  let chars = "";
  if (upper) chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  if (lower) chars += "abcdefghijklmnopqrstuvwxyz";
  if (numbers) chars += "0123456789";
  if (symbols) chars += "!@#$%^&*()_+-=[]{}|;:,.<>?";
  const arr = new Uint32Array(length);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(n => chars[n % chars.length]).join("");
}

// API client
const API = "http://localhost:8000/api/v1";

async function apiFetch(path, opts = {}, token = null) {
  const headers = { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) };
  const res = await fetch(`${API}${path}`, { headers, ...opts, body: opts.body ? JSON.stringify(opts.body) : undefined });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "Request failed");
  }
  if (res.status === 204) return null;
  return res.json();
}

// Components
const styles = `
  @import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  html, body, #root { width: 100%; height: 100%; }

  :root {
    --bg: #0a0a0f;
    --surface: #111118;
    --surface2: #18181f;
    --border: #252530;
    --accent: #7c6dfa;
    --accent2: #e84393;
    --text: #e8e8f0;
    --muted: #6b6b80;
    --success: #22c55e;
    --danger: #ef4444;
    --warn: #f59e0b;
    --radius: 12px;
    --mono: 'JetBrains Mono', monospace;
    --sans: 'Syne', sans-serif;
  }

  body { background: var(--bg); color: var(--text); font-family: var(--sans); min-height: 100vh; overflow-x: hidden; }

  .app { min-height: 100vh; display: flex; flex-direction: column; }

  /* Grain overlay */
  .app::before {
    content: '';
    position: fixed; inset: 0; z-index: 0; pointer-events: none;
    background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.04'/%3E%3C/svg%3E");
    opacity: 0.4;
  }

  /* Auth screen */
  .auth-wrap { min-height: 100vh; display: grid; place-items: center; padding: 24px; position: relative; }
  .auth-glow {
    position: fixed; width: 600px; height: 600px; border-radius: 50%;
    background: radial-gradient(ellipse, rgba(124,109,250,0.12) 0%, transparent 70%);
    top: -100px; left: 50%; transform: translateX(-50%); pointer-events: none;
  }
  .auth-card {
    background: var(--surface); border: 1px solid var(--border); border-radius: 20px;
    padding: 48px 40px; width: 100%; max-width: 420px; position: relative; z-index: 1;
    box-shadow: 0 0 0 1px rgba(124,109,250,0.08), 0 32px 80px rgba(0,0,0,0.5);
  }
  .auth-logo { font-size: 28px; font-weight: 800; letter-spacing: -1px; margin-bottom: 8px; }
  .auth-logo span { color: var(--accent); }
  .auth-tagline { color: var(--muted); font-size: 13px; margin-bottom: 32px; letter-spacing: 0.02em; }
  .auth-tabs { display: flex; gap: 4px; margin-bottom: 28px; background: var(--bg); border-radius: 10px; padding: 4px; }
  .tab-btn {
    flex: 1; padding: 9px; border: none; border-radius: 8px; cursor: pointer;
    font-family: var(--sans); font-size: 14px; font-weight: 600; transition: all 0.2s;
    background: transparent; color: var(--muted);
  }
  .tab-btn.active { background: var(--accent); color: #fff; }
  .field { margin-bottom: 16px; }
  .field label { display: block; font-size: 12px; font-weight: 600; color: var(--muted); margin-bottom: 6px; letter-spacing: 0.08em; text-transform: uppercase; }
  .field input {
    width: 100%; background: var(--bg); border: 1px solid var(--border); border-radius: 10px;
    padding: 12px 14px; color: var(--text); font-family: var(--mono); font-size: 14px;
    outline: none; transition: border-color 0.2s;
  }
  .field input:focus { border-color: var(--accent); }
  .zk-note {
    background: rgba(124,109,250,0.08); border: 1px solid rgba(124,109,250,0.2);
    border-radius: 10px; padding: 12px 14px; font-size: 12px; color: var(--accent);
    margin-bottom: 20px; display: flex; gap: 8px; align-items: flex-start; line-height: 1.5;
  }
  .btn {
    width: 100%; padding: 14px; border: none; border-radius: 12px; cursor: pointer;
    font-family: var(--sans); font-size: 15px; font-weight: 700; transition: all 0.2s;
    background: var(--accent); color: #fff;
  }
  .btn:hover { opacity: 0.9; transform: translateY(-1px); }
  .btn:active { transform: translateY(0); }
  .btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
  .btn.danger { background: var(--danger); }
  .btn.ghost { background: transparent; border: 1px solid var(--border); color: var(--muted); }
  .btn.sm { width: auto; padding: 8px 14px; font-size: 13px; }
  .error { color: var(--danger); font-size: 13px; margin-top: 12px; text-align: center; }
  .success-msg { color: var(--success); font-size: 13px; margin-top: 12px; text-align: center; }

  /* Main layout */
  .main-layout { display: flex; flex-direction: column; flex: 1; position: relative; z-index: 1; }
  .topbar {
    border-bottom: 1px solid var(--border); background: rgba(10,10,15,0.8);
    backdrop-filter: blur(12px); position: sticky; top: 0; z-index: 100;
  }
  .topbar-inner {
    display: flex; align-items: center; justify-content: space-between;
    padding: 16px 28px; max-width: 900px; margin: 0 auto; width: 100%;
  }
  .topbar-logo { font-size: 20px; font-weight: 800; letter-spacing: -0.5px; }
  .topbar-logo span { color: var(--accent); }
  .topbar-right { display: flex; align-items: center; gap: 16px; }
  .user-badge {
    display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--muted);
    background: var(--surface); border: 1px solid var(--border); border-radius: 20px; padding: 6px 12px;
  }
  .user-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--success); }
  .logout-btn {
    background: transparent; border: 1px solid var(--border); border-radius: 8px;
    padding: 7px 14px; color: var(--muted); font-size: 13px; cursor: pointer;
    font-family: var(--sans); transition: all 0.2s;
  }
  .logout-btn:hover { border-color: var(--danger); color: var(--danger); }

  /* Content */
  .content { flex: 1; padding: 32px 28px; max-width: 900px; margin: 0 auto; width: 100%; }

  /* Password list */
  .pw-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px; }
  .pw-title { font-size: 22px; font-weight: 800; }
  .pw-count { background: var(--surface2); border: 1px solid var(--border); border-radius: 20px; padding: 4px 12px; font-size: 12px; color: var(--muted); margin-left: 10px; }
  .search-bar {
    width: 100%; background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
    padding: 12px 16px; color: var(--text); font-family: var(--sans); font-size: 14px;
    outline: none; margin-bottom: 20px; transition: border-color 0.2s;
  }
  .search-bar:focus { border-color: var(--accent); }
  .search-bar::placeholder { color: var(--muted); }

  .pw-grid { display: grid; gap: 12px; }
  .pw-card {
    background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
    padding: 20px; transition: all 0.2s; cursor: default;
    display: flex; align-items: center; gap: 16px;
  }
  .pw-card:hover { border-color: rgba(124,109,250,0.4); box-shadow: 0 4px 20px rgba(124,109,250,0.08); }
  .pw-icon {
    width: 44px; height: 44px; border-radius: 10px; display: grid; place-items: center;
    font-size: 20px; flex-shrink: 0; font-weight: 700;
    background: linear-gradient(135deg, var(--accent), var(--accent2));
    color: #fff; font-style: normal;
  }
  .pw-info { flex: 1; min-width: 0; }
  .pw-site { font-weight: 700; font-size: 15px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .pw-user { font-size: 13px; color: var(--muted); margin-top: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .pw-actions { display: flex; gap: 8px; flex-shrink: 0; }
  .icon-btn {
    background: var(--surface2); border: 1px solid var(--border); border-radius: 8px;
    width: 36px; height: 36px; display: grid; place-items: center; cursor: pointer;
    color: var(--muted); font-size: 16px; transition: all 0.2s;
  }
  .icon-btn:hover { border-color: var(--accent); color: var(--accent); }
  .icon-btn.red:hover { border-color: var(--danger); color: var(--danger); }
  .icon-btn.green:hover { border-color: var(--success); color: var(--success); }

  .empty-state {
    text-align: center; padding: 80px 20px; color: var(--muted);
  }
  .empty-state .icon { font-size: 48px; margin-bottom: 16px; }
  .empty-state h3 { font-size: 18px; font-weight: 700; margin-bottom: 8px; color: var(--text); }
  .empty-state p { font-size: 14px; line-height: 1.6; }

  /* Modal */
  .modal-overlay {
    position: fixed; inset: 0; background: rgba(0,0,0,0.7); backdrop-filter: blur(4px);
    display: grid; place-items: center; z-index: 200; padding: 20px;
  }
  .modal {
    background: var(--surface); border: 1px solid var(--border); border-radius: 20px;
    padding: 36px; width: 100%; max-width: 480px;
    box-shadow: 0 32px 80px rgba(0,0,0,0.6);
    animation: slideUp 0.2s ease;
  }
  @keyframes slideUp { from { opacity: 0; transform: translateY(16px); } to { opacity: 1; transform: translateY(0); } }
  .modal-title { font-size: 20px; font-weight: 800; margin-bottom: 24px; }
  .modal-actions { display: flex; gap: 10px; margin-top: 24px; }

  /* Password generator in modal */
  .pw-preview {
    font-family: var(--mono); font-size: 15px; background: var(--bg); border: 1px solid var(--border);
    border-radius: 10px; padding: 12px 14px; word-break: break-all; letter-spacing: 0.05em;
    color: var(--accent); display: flex; align-items: center; justify-content: space-between; gap: 8px;
    margin-bottom: 12px; cursor: pointer;
  }
  .pw-preview:hover { border-color: var(--accent); }
  .gen-opts { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }
  .opt-chip {
    background: var(--bg); border: 1px solid var(--border); border-radius: 8px;
    padding: 6px 12px; font-size: 12px; cursor: pointer; transition: all 0.15s;
    font-family: var(--sans); color: var(--muted);
  }
  .opt-chip.on { background: rgba(124,109,250,0.15); border-color: var(--accent); color: var(--accent); }

  /* Toast */
  .toast {
    position: fixed; bottom: 24px; right: 24px; z-index: 999;
    background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
    padding: 14px 20px; font-size: 14px; animation: toastIn 0.2s ease;
    display: flex; align-items: center; gap: 10px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.4);
  }
  @keyframes toastIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
  .toast.ok { border-color: var(--success); }
  .toast.err { border-color: var(--danger); }

  /* Spinner */
  .spinner { width: 20px; height: 20px; border: 2px solid rgba(255,255,255,0.2); border-top-color: #fff; border-radius: 50%; animation: spin 0.6s linear infinite; display: inline-block; }
  @keyframes spin { to { transform: rotate(360deg); } }

  .strength-bar { height: 4px; border-radius: 2px; margin-top: 6px; transition: all 0.3s; background: var(--border); }
  .strength-bar div { height: 100%; border-radius: 2px; transition: all 0.3s; }

  .saved-badge { font-size: 11px; color: var(--success); font-weight: 600; letter-spacing: 0.05em; display: flex; align-items: center; gap: 4px; }
`;

function Toast({ msg, type, onDone }) {
  useEffect(() => { const t = setTimeout(onDone, 2500); return () => clearTimeout(t); }, [onDone]);
  return (
    <div className={`toast ${type}`}>
      <span>{type === "ok" ? "✓" : "✕"}</span>
      {msg}
    </div>
  );
}

function StrengthBar({ password }) {
  const score = !password ? 0 : Math.min(4, [password.length >= 12, /[A-Z]/.test(password), /[0-9]/.test(password), /[^A-Za-z0-9]/.test(password)].filter(Boolean).length);
  const colors = ["#ef4444","#f59e0b","#f59e0b","#22c55e","#22c55e"];
  const labels = ["","Weak","Fair","Good","Strong"];
  return (
    <div>
      <div className="strength-bar"><div style={{ width: `${score * 25}%`, background: colors[score] }} /></div>
      {password && <span style={{ fontSize: 11, color: colors[score], fontWeight: 600 }}>{labels[score]}</span>}
    </div>
  );
}

function GenOptions({ opts, setOpts }) {
  const toggles = [
    { key: "upper", label: "A-Z" }, { key: "lower", label: "a-z" },
    { key: "numbers", label: "0-9" }, { key: "symbols", label: "!@#" },
  ];
  return (
    <div className="gen-opts">
      {toggles.map(t => (
        <button key={t.key} className={`opt-chip ${opts[t.key] ? "on" : ""}`} onClick={() => setOpts(o => ({ ...o, [t.key]: !o[t.key] }))}>
          {t.label}
        </button>
      ))}
      {[16, 20, 24, 32].map(l => (
        <button key={l} className={`opt-chip ${opts.length === l ? "on" : ""}`} onClick={() => setOpts(o => ({ ...o, length: l }))}>
          {l}
        </button>
      ))}
    </div>
  );
}

function EntryModal({ entry, onSave, onClose }) {
  const [form, setForm] = useState({ site: "", username: "", password: "", url: "", notes: "", ...entry });
  const [showPw, setShowPw] = useState(false);
  const [genOpts, setGenOpts] = useState({ length: 20, upper: true, lower: true, numbers: true, symbols: true });
  const [generated, setGenerated] = useState("");

  const gen = () => setGenerated(generatePassword(genOpts));
  useEffect(() => { gen(); }, [genOpts]);
  const useGenerated = () => setForm(f => ({ ...f, password: generated }));

  const siteIcon = form.site ? form.site[0].toUpperCase() : "?";

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal">
        <div className="modal-title">{entry ? "Edit Entry" : "New Entry"}</div>
        {["site", "username", "url"].map(k => (
          <div className="field" key={k}>
            <label>{k.charAt(0).toUpperCase() + k.slice(1)}</label>
            <input value={form[k]} onChange={e => setForm(f => ({ ...f, [k]: e.target.value }))} placeholder={k === "url" ? "https://..." : ""}/>
          </div>
        ))}
        <div className="field">
          <label>Password</label>
          <div style={{ position: "relative" }}>
            <input
              type={showPw ? "text" : "password"}
              value={form.password}
              onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
              style={{ paddingRight: 44 }}
            />
            <button
              onClick={() => setShowPw(s => !s)}
              style={{ position: "absolute", right: 10, top: "50%", transform: "translateY(-50%)", background: "none", border: "none", color: "var(--muted)", cursor: "pointer", fontSize: 16 }}
            >{showPw ? "🙈" : "👁"}</button>
          </div>
          <StrengthBar password={form.password} />
        </div>
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: "var(--muted)", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.08em" }}>Generate</div>
          <GenOptions opts={genOpts} setOpts={setGenOpts} />
          <div className="pw-preview" onClick={() => { navigator.clipboard.writeText(generated); useGenerated(); }}>
            <span style={{ flex: 1, overflow: "hidden", whiteSpace: "nowrap", textOverflow: "ellipsis" }}>{generated}</span>
            <span style={{ fontSize: 12, color: "var(--muted)", flexShrink: 0 }}>click to use</span>
          </div>
        </div>
        <div className="field">
          <label>Notes</label>
          <input value={form.notes} onChange={e => setForm(f => ({ ...f, notes: e.target.value }))} placeholder="Optional notes"/>
        </div>
        <div className="modal-actions">
          <button className="btn ghost sm" onClick={onClose} style={{ flex: 1 }}>Cancel</button>
          <button className="btn sm" onClick={() => onSave(form)} style={{ flex: 2 }} disabled={!form.site || !form.password}>
            {entry ? "Update" : "Add Entry"}
          </button>
        </div>
      </div>
    </div>
  );
}

// Main App
export default function App() {
  const [tab, setTab] = useState("login");
  const [token, setToken] = useState(null);
  const [email, setEmail] = useState("");
  const [masterKey, setMasterKey] = useState(null);
  const [entries, setEntries] = useState([]);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [toast, setToast] = useState(null);
  const [modal, setModal] = useState(null); // null | "add" | { entry, index }
  const [saving, setSaving] = useState(false);
  const [vaultExists, setVaultExists] = useState(false);

  // Auth form state
  const [authEmail, setAuthEmail] = useState("");
  const [authPw, setAuthPw] = useState("");
  const [authPw2, setAuthPw2] = useState("");

  const showToast = (msg, type = "ok") => setToast({ msg, type });

  // Load vault after login
  const loadVault = useCallback(async (key, tok) => {
    try {
      const vault = await apiFetch("/vault/", {}, tok);
      setVaultExists(true);
      const plain = await decryptVault(key, vault.encrypted_data, vault.iv);
      setEntries(JSON.parse(plain));
    } catch (e) {
      if (e.message.includes("404")) {
        setVaultExists(false);
        setEntries([]);
      }
    }
  }, []);

  // Save vault
  const saveVault = useCallback(async (newEntries, key, tok) => {
    setSaving(true);
    try {
      const plain = JSON.stringify(newEntries);
      const { encrypted_data, iv } = await encryptVault(key, plain);
      if (vaultExists) {
        await apiFetch("/vault/", { method: "PUT", body: { encrypted_data, iv } }, tok);
      } else {
        await apiFetch("/vault/", { method: "POST", body: { encrypted_data, iv } }, tok);
        setVaultExists(true);
      }
      showToast("Vault saved");
    } catch (e) {
      showToast(e.message, "err");
    } finally {
      setSaving(false);
    }
  }, [vaultExists, token, masterKey]);

  // Register
  const handleRegister = async () => {
    setErr(""); setLoading(true);
    try {
      if (authPw !== authPw2) throw new Error("Passwords don't match");
      if (authPw.length < 8) throw new Error("Master password must be at least 8 characters");
      const salt = generateSalt();
      const authHash = await deriveAuthHash(authPw, salt);
      await apiFetch("/auth/register", { method: "POST", body: { email: authEmail, auth_key_hash: authHash, salt } });
      showToast("Account created! Please log in.");
      setTab("login");
    } catch (e) {
      setErr(e.message);
    } finally {
      setLoading(false);
    }
  };

  // Login
  const handleLogin = async () => {
    setErr(""); setLoading(true);
    try {
      const saltRes = await apiFetch("/auth/salt", { method: "POST", body: { email: authEmail } });
      const authHash = await deriveAuthHash(authPw, saltRes.salt);
      const data = await apiFetch("/auth/login", { method: "POST", body: { email: authEmail, auth_key_hash: authHash } });
      // Derive the separate encryption key (different from auth hash)
      const encKey = await deriveMasterKey(authPw + ":enc", saltRes.salt);
      setToken(data.access_token);
      setEmail(authEmail);
      setMasterKey(encKey);
      await loadVault(encKey, data.access_token);
    } catch (e) {
      setErr(e.message);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => { setToken(null); setMasterKey(null); setEntries([]); setEmail(""); };

  // Entry CRUD
  const addEntry = async (form) => {
    const newEntries = [...entries, { ...form, id: crypto.randomUUID(), created: Date.now() }];
    setEntries(newEntries);
    setModal(null);
    await saveVault(newEntries, masterKey, token);
  };

  const updateEntry = async (form, index) => {
    const newEntries = entries.map((e, i) => i === index ? { ...e, ...form } : e);
    setEntries(newEntries);
    setModal(null);
    await saveVault(newEntries, masterKey, token);
  };

  const deleteEntry = async (index) => {
    if (!confirm("Delete this entry?")) return;
    const newEntries = entries.filter((_, i) => i !== index);
    setEntries(newEntries);
    await saveVault(newEntries, masterKey, token);
  };

  const copyPassword = (pw) => {
    navigator.clipboard.writeText(pw);
    showToast("Password copied!");
  };

  // Filter entries
  const filtered = entries.filter(e =>
    !search || e.site?.toLowerCase().includes(search.toLowerCase()) || e.username?.toLowerCase().includes(search.toLowerCase())
  );

  // Auth screen
  if (!token) {
    return (
      <div className="app">
        <style>{styles}</style>
        <div className="auth-wrap">
          <div className="auth-glow" />
          <div className="auth-card">
            <div className="auth-logo">Pass<span>key</span></div>
            <div className="auth-tagline">Zero-knowledge password manager — your vault never leaves your device unencrypted</div>
            <div className="auth-tabs">
              <button className={`tab-btn ${tab === "login" ? "active" : ""}`} onClick={() => { setTab("login"); setErr(""); }}>Sign In</button>
              <button className={`tab-btn ${tab === "register" ? "active" : ""}`} onClick={() => { setTab("register"); setErr(""); }}>Register</button>
            </div>
            <div className="zk-note">
              <span>🔒</span>
              <span>Your master password <strong>never leaves your browser</strong>. All encryption uses AES-256-GCM with PBKDF2 key derivation.</span>
            </div>
            <div className="field">
              <label>Email</label>
              <input type="email" value={authEmail} onChange={e => setAuthEmail(e.target.value)} onKeyDown={e => e.key === "Enter" && (tab === "login" ? handleLogin() : handleRegister())} />
            </div>
            <div className="field">
              <label>Master Password</label>
              <input type="password" value={authPw} onChange={e => setAuthPw(e.target.value)} onKeyDown={e => e.key === "Enter" && (tab === "login" ? handleLogin() : handleRegister())} />
              {tab === "register" && <StrengthBar password={authPw} />}
            </div>
            {tab === "register" && (
              <div className="field">
                <label>Confirm Password</label>
                <input type="password" value={authPw2} onChange={e => setAuthPw2(e.target.value)} />
              </div>
            )}
            {err && <div className="error">{err}</div>}
            <button className="btn" style={{ marginTop: 20 }} onClick={tab === "login" ? handleLogin : handleRegister} disabled={loading || !authEmail || !authPw}>
              {loading ? <span className="spinner" /> : tab === "login" ? "Unlock Vault" : "Create Account"}
            </button>
          </div>
        </div>
        {toast && <Toast msg={toast.msg} type={toast.type} onDone={() => setToast(null)} />}
      </div>
    );
  }

  // Main vault screen
  return (
    <div className="app">
      <style>{styles}</style>
      <div className="main-layout">
        <header className="topbar">
          <div className="topbar-inner">
            <div className="topbar-logo">Pass<span>keyed</span></div>
            <div className="topbar-right">
              <div className="user-badge"><div className="user-dot" />{email}</div>
              {saving && <span style={{ color: "var(--muted)", fontSize: 13, display: "flex", alignItems: "center", gap: 6 }}><span className="spinner" />Saving…</span>}
              <button className="logout-btn" onClick={handleLogout}>Lock</button>
            </div>
          </div>
        </header>
        <main className="content">
          <div className="pw-header">
            <div style={{ display: "flex", alignItems: "center" }}>
              <h1 className="pw-title">My Vault</h1>
              <span className="pw-count">{entries.length}</span>
            </div>
            <button className="btn sm" onClick={() => setModal("add")}>+ New Entry</button>
          </div>
          <input className="search-bar" placeholder="Search sites, usernames…" value={search} onChange={e => setSearch(e.target.value)} />
          {filtered.length === 0 ? (
            <div className="empty-state">
              <div className="icon">🔐</div>
              <h3>{entries.length === 0 ? "Your vault is empty" : "No results"}</h3>
              <p>{entries.length === 0 ? "Add your first password entry to get started." : "Try a different search term."}</p>
            </div>
          ) : (
            <div className="pw-grid">
              {filtered.map((entry, i) => {
                const realIndex = entries.indexOf(entry);
                return (
                  <div className="pw-card" key={entry.id || i}>
                    <div className="pw-icon">{entry.site?.[0]?.toUpperCase() || "?"}</div>
                    <div className="pw-info">
                      <div className="pw-site">{entry.site}</div>
                      <div className="pw-user">{entry.username}{entry.url && ` · ${entry.url}`}</div>
                    </div>
                    <div className="pw-actions">
                      <button className="icon-btn green" title="Copy password" onClick={() => copyPassword(entry.password)}>⎘</button>
                      <button className="icon-btn" title="Edit" onClick={() => setModal({ entry, index: realIndex })}>✎</button>
                      <button className="icon-btn red" title="Delete" onClick={() => deleteEntry(realIndex)}>✕</button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </main>
      </div>

      {modal === "add" && (
        <EntryModal onSave={addEntry} onClose={() => setModal(null)} />
      )}
      {modal && modal !== "add" && (
        <EntryModal entry={modal.entry} onSave={(form) => updateEntry(form, modal.index)} onClose={() => setModal(null)} />
      )}
      {toast && <Toast msg={toast.msg} type={toast.type} onDone={() => setToast(null)} />}
    </div>
  );
}
