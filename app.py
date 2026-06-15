#!/usr/bin/env python3
"""
Web interface for Password Strength Analyzer using Flask.
Run: python app.py  →  open http://127.0.0.1:5000
"""

from flask import Flask, request, jsonify, render_template_string
from password_analyzer import analyze_password, generate_strong_password, generate_passphrase, check_reuse, record_password

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Password Strength Analyzer</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Courier New', monospace;
    background: #0d0f14;
    color: #c9d1d9;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
  }
  .container {
    width: 100%;
    max-width: 640px;
  }
  header {
    text-align: center;
    margin-bottom: 32px;
  }
  header h1 {
    font-size: 1.8rem;
    color: #58a6ff;
    letter-spacing: 2px;
    text-transform: uppercase;
  }
  header p { color: #6e7681; margin-top: 6px; font-size: 0.9rem; }

  .card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 28px;
    margin-bottom: 20px;
  }

  label {
    display: block;
    font-size: 0.82rem;
    color: #8b949e;
    margin-bottom: 8px;
    letter-spacing: 1px;
    text-transform: uppercase;
  }

  .input-row {
    display: flex;
    gap: 10px;
  }
  input[type="text"], input[type="password"] {
    flex: 1;
    background: #0d1117;
    border: 1px solid #30363d;
    color: #e6edf3;
    padding: 12px 16px;
    border-radius: 6px;
    font-family: 'Courier New', monospace;
    font-size: 1rem;
    outline: none;
    transition: border-color 0.2s;
  }
  input:focus { border-color: #58a6ff; }

  button {
    background: #1f6feb;
    color: #fff;
    border: none;
    padding: 12px 20px;
    border-radius: 6px;
    cursor: pointer;
    font-size: 0.9rem;
    font-family: 'Courier New', monospace;
    transition: background 0.2s;
    white-space: nowrap;
  }
  button:hover { background: #388bfd; }
  button.secondary {
    background: #21262d;
    border: 1px solid #30363d;
    color: #c9d1d9;
  }
  button.secondary:hover { background: #30363d; }

  .toggle-btn {
    background: #21262d;
    border: 1px solid #30363d;
    color: #8b949e;
    padding: 12px 14px;
    border-radius: 6px;
    cursor: pointer;
    font-size: 1rem;
  }

  .meter-container {
    margin: 20px 0 12px;
  }
  .meter-label {
    display: flex;
    justify-content: space-between;
    margin-bottom: 6px;
    font-size: 0.85rem;
  }
  .meter-bar {
    height: 8px;
    background: #21262d;
    border-radius: 4px;
    overflow: hidden;
  }
  .meter-fill {
    height: 100%;
    border-radius: 4px;
    transition: width 0.4s ease, background 0.4s ease;
    width: 0%;
  }

  .stats-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
    margin: 16px 0;
  }
  .stat-box {
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 6px;
    padding: 12px 16px;
  }
  .stat-box .val { font-size: 1.3rem; font-weight: bold; color: #e6edf3; }
  .stat-box .key { font-size: 0.75rem; color: #6e7681; text-transform: uppercase; letter-spacing: 1px; }

  .checks-list { list-style: none; margin: 16px 0; }
  .checks-list li {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 5px 0;
    font-size: 0.9rem;
  }
  .check-icon { font-size: 1rem; }

  .issues-box, .suggestions-box {
    border-radius: 6px;
    padding: 14px 16px;
    margin-top: 12px;
    font-size: 0.88rem;
  }
  .issues-box {
    background: rgba(248,81,73,0.1);
    border: 1px solid rgba(248,81,73,0.3);
  }
  .issues-box .title { color: #f85149; font-weight: bold; margin-bottom: 6px; }
  .suggestions-box {
    background: rgba(88,166,255,0.08);
    border: 1px solid rgba(88,166,255,0.25);
  }
  .suggestions-box .title { color: #58a6ff; font-weight: bold; margin-bottom: 6px; }
  .suggestions-box li, .issues-box li { margin-left: 16px; margin-top: 4px; }

  .gen-buttons { display: flex; gap: 10px; flex-wrap: wrap; }

  .gen-result {
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 14px 16px;
    margin-top: 14px;
    display: none;
  }
  .gen-result .pwd-text {
    font-size: 1.05rem;
    color: #3fb950;
    word-break: break-all;
    letter-spacing: 1px;
  }
  .copy-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
  }
  .copy-row small { color: #6e7681; font-size: 0.78rem; }

  .reuse-warning {
    background: rgba(248,81,73,0.1);
    border: 1px solid rgba(248,81,73,0.3);
    color: #f85149;
    border-radius: 6px;
    padding: 10px 14px;
    font-size: 0.88rem;
    margin-top: 10px;
    display: none;
  }

  #result { display: none; }
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>🔐 Password Analyzer</h1>
    <p>Evaluate strength · Generate secure passwords · Track history</p>
  </header>

  <!-- Analyze Section -->
  <div class="card">
    <label>Analyze Your Password</label>
    <div class="input-row">
      <input type="password" id="pwdInput" placeholder="Enter your password…" oninput="analyzeRealtime()">
      <button class="toggle-btn" onclick="toggleVisibility()" id="eyeBtn">👁</button>
      <button onclick="analyzePassword()">Analyze</button>
    </div>

    <div id="result">
      <div class="meter-container">
        <div class="meter-label">
          <span id="strengthLabel">—</span>
          <span id="scoreLabel">—</span>
        </div>
        <div class="meter-bar"><div class="meter-fill" id="meterFill"></div></div>
      </div>

      <div class="stats-grid">
        <div class="stat-box">
          <div class="val" id="statLength">—</div>
          <div class="key">Length</div>
        </div>
        <div class="stat-box">
          <div class="val" id="statEntropy">—</div>
          <div class="key">Entropy (bits)</div>
        </div>
      </div>

      <ul class="checks-list" id="checksList"></ul>

      <div class="reuse-warning" id="reuseWarning">⚠ This password was used before!</div>
      <div class="issues-box" id="issuesBox" style="display:none">
        <div class="title">⚠ Issues Detected</div>
        <ul id="issuesList"></ul>
      </div>
      <div class="suggestions-box" id="suggestionsBox" style="display:none">
        <div class="title">💡 Suggestions</div>
        <ul id="suggestionsList"></ul>
      </div>
    </div>
  </div>

  <!-- Generate Section -->
  <div class="card">
    <label>Generate Strong Password</label>
    <div class="gen-buttons">
      <button class="secondary" onclick="generatePassword()">⚙ Random Password</button>
      <button class="secondary" onclick="generatePassphrase()">📖 Passphrase</button>
    </div>
    <div class="gen-result" id="genResult">
      <div class="copy-row">
        <small>Generated password</small>
        <button class="secondary" style="padding:6px 12px;font-size:0.8rem" onclick="copyGenerated()">Copy</button>
      </div>
      <div class="pwd-text" id="genText"></div>
    </div>
  </div>
</div>

<script>
  let debounceTimer;
  const STRENGTH_COLORS = {
    'Very Weak': '#f85149',
    'Weak':      '#e3b341',
    'Fair':      '#d29922',
    'Strong':    '#58a6ff',
    'Very Strong': '#3fb950'
  };

  function toggleVisibility() {
    const inp = document.getElementById('pwdInput');
    const btn = document.getElementById('eyeBtn');
    if (inp.type === 'password') { inp.type = 'text'; btn.textContent = '🙈'; }
    else { inp.type = 'password'; btn.textContent = '👁'; }
  }

  function analyzeRealtime() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(analyzePassword, 300);
  }

  async function analyzePassword() {
    const pwd = document.getElementById('pwdInput').value;
    if (!pwd) { document.getElementById('result').style.display = 'none'; return; }

    const resp = await fetch('/analyze', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ password: pwd })
    });
    const data = await resp.json();
    renderResult(data);
  }

  function renderResult(data) {
    document.getElementById('result').style.display = 'block';

    const color = STRENGTH_COLORS[data.strength] || '#8b949e';
    document.getElementById('strengthLabel').textContent = data.strength;
    document.getElementById('strengthLabel').style.color = color;
    document.getElementById('scoreLabel').textContent = data.score + '%';
    document.getElementById('scoreLabel').style.color = color;

    const fill = document.getElementById('meterFill');
    fill.style.width = data.score + '%';
    fill.style.background = color;

    document.getElementById('statLength').textContent = data.length;
    document.getElementById('statEntropy').textContent = data.entropy;

    const checkDefs = [
      ['has_lowercase',  'Lowercase letters'],
      ['has_uppercase',  'Uppercase letters'],
      ['has_digit',      'Numbers'],
      ['has_special',    'Special characters'],
      ['length_ok',      'Minimum length (8+)'],
      ['length_good',    'Recommended length (12+)'],
    ];
    const cl = document.getElementById('checksList');
    cl.innerHTML = checkDefs.map(([k, label]) =>
      `<li><span class="check-icon">${data.checks[k] ? '✅' : '❌'}</span>${label}</li>`
    ).join('');

    // Reuse warning
    const rw = document.getElementById('reuseWarning');
    rw.style.display = data.reused ? 'block' : 'none';

    // Issues
    const ib = document.getElementById('issuesBox');
    if (data.issues.length) {
      ib.style.display = 'block';
      document.getElementById('issuesList').innerHTML = data.issues.map(i => `<li>${i}</li>`).join('');
    } else { ib.style.display = 'none'; }

    // Suggestions
    const sb = document.getElementById('suggestionsBox');
    if (data.suggestions.length) {
      sb.style.display = 'block';
      document.getElementById('suggestionsList').innerHTML = data.suggestions.map(s => `<li>${s}</li>`).join('');
    } else { sb.style.display = 'none'; }
  }

  async function generatePassword() {
    const resp = await fetch('/generate', { method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ type: 'random' })
    });
    const data = await resp.json();
    document.getElementById('genText').textContent = data.password;
    document.getElementById('genResult').style.display = 'block';
  }

  async function generatePassphrase() {
    const resp = await fetch('/generate', { method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ type: 'passphrase' })
    });
    const data = await resp.json();
    document.getElementById('genText').textContent = data.password;
    document.getElementById('genResult').style.display = 'block';
  }

  function copyGenerated() {
    const text = document.getElementById('genText').textContent;
    navigator.clipboard.writeText(text).then(() => alert('Copied to clipboard!'));
  }
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    pwd = data.get("password", "")
    result = analyze_password(pwd)
    result["reused"] = check_reuse(pwd)
    record_password(pwd)
    return jsonify(result)

@app.route("/generate", methods=["POST"])
def generate():
    data = request.get_json()
    if data.get("type") == "passphrase":
        pwd = generate_passphrase()
    else:
        pwd = generate_strong_password(16, True)
    return jsonify({"password": pwd})

if __name__ == "__main__":
    print("  🔐 Password Analyzer Web UI")
    print("  → Open http://127.0.0.1:5000 in your browser")
    app.run(debug=True)
