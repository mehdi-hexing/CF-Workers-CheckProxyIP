import { connect } from "cloudflare:sockets";

let temporaryTOKEN, permanentTOKEN;

// --- Helper Functions (Server-Side) ---

async function doubleHash(text) {
  const encoder = new TextEncoder();
  const firstHashBuffer = await crypto.subtle.digest('MD5', encoder.encode(text));
  const firstHashArray = Array.from(new Uint8Array(firstHashBuffer));
  const firstHex = firstHashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
  const secondHashBuffer = await crypto.subtle.digest('MD5', encoder.encode(firstHex.slice(7, 27)));
  const secondHashArray = Array.from(new Uint8Array(secondHashBuffer));
  const secondHex = secondHashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
  return secondHex.toLowerCase();
}

async function resolveDomain(domain) {
  domain = domain.includes(':') ? domain.split(':')[0] : domain;
  try {
    const [ipv4Response, ipv6Response] = await Promise.all([
      fetch(`https://1.1.1.1/dns-query?name=${domain}&type=A`, { headers: { 'Accept': 'application/dns-json' } }),
      fetch(`https://1.1.1.1/dns-query?name=${domain}&type=AAAA`, { headers: { 'Accept': 'application/dns-json' } })
    ]);
    const [ipv4Data, ipv6Data] = await Promise.all([ipv4Response.json(), ipv6Response.json()]);
    const ips = [];
    if (ipv4Data.Answer) {
      ips.push(...ipv4Data.Answer.filter(r => r.type === 1).map(r => r.data));
    }
    if (ipv6Data.Answer) {
      ips.push(...ipv6Data.Answer.filter(r => r.type === 28).map(r => `[${r.data}]`));
    }
    if (ips.length === 0) throw new Error('No A or AAAA records found for this domain.');
    return ips;
  } catch (error) {
    throw new Error(`DNS resolution failed: ${error.message}`);
  }
}

async function checkProxyIP(proxyIPWithPort) {
  let portRemote = 443;
  let hostToCheck = proxyIPWithPort;

  if (proxyIPWithPort.includes('.tp')) {
    const portMatch = proxyIPWithPort.match(/\.tp(\d+)\./);
    if (portMatch) portRemote = parseInt(portMatch[1]);
    hostToCheck = proxyIPWithPort.split('.tp')[0];
  } else if (proxyIPWithPort.includes('[') && proxyIPWithPort.includes(']:')) {
    portRemote = parseInt(proxyIPWithPort.split(']:')[1]);
    hostToCheck = proxyIPWithPort.split(']:')[0] + ']';
  } else if (proxyIPWithPort.includes(':') && !proxyIPWithPort.startsWith('[')) {
    const parts = proxyIPWithPort.split(':');
    if (parts.length === 2 && parts[0].includes('.')) {
      hostToCheck = parts[0];
      portRemote = parseInt(parts[1]) || 443;
    }
  }

  try {
    const tcpSocket = connect({ hostname: hostToCheck, port: portRemote });
    const writer = tcpSocket.writable.getWriter();
    const httpRequest = `GET /cdn-cgi/trace HTTP/1.1\r\nHost: speed.cloudflare.com\r\nUser-Agent: CheckProxyIP/CloudflareWorker\r\nConnection: close\r\n\r\n`;
    await writer.write(new TextEncoder().encode(httpRequest));
    writer.releaseLock();

    const reader = tcpSocket.readable.getReader();
    let responseData = new Uint8Array(0);
    const timeoutPromise = new Promise(resolve => setTimeout(() => resolve({ done: true, timeout: true }), 5000));

    while (true) {
      const result = await Promise.race([reader.read(), timeoutPromise]);
      if (result.done) break;
      if (result.value) {
        const newData = new Uint8Array(responseData.length + result.value.length);
        newData.set(responseData);
        newData.set(result.value, responseData.length);
        responseData = newData;
        const responseText = new TextDecoder().decode(responseData);
        if (responseText.includes("\r\n\r\n") && (responseText.toLowerCase().includes("connection: close") || responseText.includes("content-length"))) {
          break;
        }
      }
    }
    reader.releaseLock();

    const responseText = new TextDecoder().decode(responseData);
    const statusMatch = responseText.match(/^HTTP\/\d\.\d\s+(\d+)/i);
    const statusCode = statusMatch ? parseInt(statusMatch[1]) : null;
    const looksLikeCloudflare = responseText.toLowerCase().includes("cloudflare");
    const isExpectedError = responseText.includes("plain HTTP request") || responseText.includes("400 Bad Request");
    const hasSufficientBody = responseData.length > 50;
    const isSuccessful = statusCode !== null && looksLikeCloudflare && isExpectedError && hasSufficientBody;

    await tcpSocket.close();
    return { success: isSuccessful, proxyIP: hostToCheck, portRemote, statusCode, responseSize: responseData.length, timestamp: new Date().toISOString() };
  } catch (error) {
    return { success: false, proxyIP: hostToCheck, portRemote, timestamp: new Date().toISOString(), error: error.message || error.toString() };
  }
}

// --- Main Fetch Handler ---

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const userAgent = request.headers.get('User-Agent') || 'null';
    const path = url.pathname;
    const hostname = url.hostname;

    const timestampForToken = Math.ceil(new Date().getTime() / (1000 * 60 * 31));
    temporaryTOKEN = await doubleHash(hostname + timestampForToken + userAgent);
    permanentTOKEN = env.TOKEN || temporaryTOKEN;
    
    if (path.toLowerCase().startsWith('/api/')) {
        const isTokenValid = () => {
            if (!env.TOKEN) return true;
            const providedToken = url.searchParams.get('token');
            return providedToken === permanentTOKEN || providedToken === temporaryTOKEN;
        };
        
        if (path.toLowerCase() === '/api/get-token') {
            return new Response(JSON.stringify({ token: temporaryTOKEN }), { headers: { "Content-Type": "application/json" } });
        }

        if (!isTokenValid()) {
            return new Response(JSON.stringify({ status: "error", message: "Invalid TOKEN" }), {
                status: 403, headers: { "Content-Type": "application/json" }
            });
        }

        if (path.toLowerCase() === '/api/check') {
            if (!url.searchParams.has('proxyip')) return new Response('Missing proxyip parameter', { status: 400 });
            const proxyIPInput = url.searchParams.get('proxyip');
            const result = await checkProxyIP(proxyIPInput);
            return new Response(JSON.stringify(result), {
                status: result.success ? 200 : 502, headers: { "Content-Type": "application/json" }
            });
        }
        
        if (path.toLowerCase() === '/api/resolve') {
            if (!url.searchParams.has('domain')) return new Response('Missing domain parameter', { status: 400 });
            const domain = url.searchParams.get('domain');
            try {
                const ips = await resolveDomain(domain);
                return new Response(JSON.stringify({ success: true, domain, ips }), { headers: { "Content-Type": "application/json" } });
            } catch (error) {
                return new Response(JSON.stringify({ success: false, error: error.message }), { status: 500, headers: { "Content-Type": "application/json" } });
            }
        }

        if (path.toLowerCase() === '/api/ip-info') {
            let ip = url.searchParams.get('ip') || request.headers.get('CF-Connecting-IP');
            if (!ip) return new Response('IP parameter not provided', { status: 400 });
            if (ip.includes('[')) ip = ip.replace(/\[|\]/g, '');
            const response = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,query,country,countryCode,as&lang=en`);
            const data = await response.json();
            return new Response(JSON.stringify(data), { headers: { "Content-Type": "application/json" } });
        }
        
        return new Response('API route not found', { status: 404 });
    }
    
    const faviconURL = env.ICO || 'https://cf-assets.www.cloudflare.com/dzlvafdwdttg/19kSkLSfWtDcspvQI5pit4/c5630cf25d589a0de91978ca29486259/performance-acceleration-bolt.svg';

    if (path.toLowerCase() === '/favicon.ico') {
        return Response.redirect(faviconURL, 302);
    }
    
    return new Response(generateMainHTML(faviconURL), {
      headers: { "content-type": "text/html;charset=UTF-8" }
    });
  }
};

// --- HTML Generation ---

function generateMainHTML(faviconURL) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Proxy IP Checker</title>
  <link rel="icon" href="${faviconURL}" type="image/x-icon">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      --bg-primary: #ffffff;
      --bg-secondary: #f8f9fa;
      --text-primary: #2c3e50;
      --text-light: #adb5bd;
      --border-color: #dee2e6;
      --primary-color: #3498db; 
      --success-color: #2ecc71;
      --error-color: #e74c3c; 
      --result-success-bg: #d4edda;
      --result-success-text: #155724;
      --result-error-bg: #f8d7da;
      --result-error-text: #721c24;
      --result-warning-bg: #fff3cd;
      --result-warning-text: #856404;
      --border-radius: 12px; 
      --border-radius-sm: 8px;
    }
    body.dark-mode {
      --bg-gradient: linear-gradient(135deg, #232526 0%, #414345 100%);
      --bg-primary: #2c3e50;
      --bg-secondary: #34495e;
      --text-primary: #ecf0f1;
      --text-light: #95a5a6;
      --border-color: #465b71;
      --result-success-bg: #2c5a3d;
      --result-success-text: #ffffff;
      --result-error-bg: #5a2c2c;
      --result-error-text: #ffffff;
      --result-warning-bg: #5a4b1e;
      --result-warning-text: #fff8dd;
    }
    html {
      height: 100%;
    }
    body { 
      font-family: 'Inter', sans-serif; 
      background: var(--bg-gradient);
      background-attachment: fixed;
      color: var(--text-primary);
      line-height: 1.6; margin:0; padding:0; min-height: 100%; 
      display: flex; flex-direction: column; align-items: center;
      transition: background 0.3s ease, color 0.3s ease;
    }
    .container { 
        max-width: 800px; 
        width: 100%;
        padding: 20px;
        box-sizing: border-box;
    }
    .header { text-align: center; margin-bottom: 30px; }
    .main-title { font-size: 2.2rem; font-weight: 700; color: #fff; text-shadow: 1px 1px 3px rgba(0,0,0,0.2); }
    .card { background: var(--bg-primary); border-radius: var(--border-radius); padding: 25px; box-shadow: 0 8px 20px rgba(0,0,0,0.1); margin-bottom: 25px; transition: background 0.3s ease; }
    .form-section { display: flex; flex-direction: column; align-items: center; }
    .form-label { display: block; font-weight: 500; margin-bottom: 8px; color: var(--text-primary); width: 100%; max-width: 450px; text-align: left;}
    .input-wrapper { width: 100%; max-width: 450px; margin-bottom: 15px; }
    .form-input { width: 100%; padding: 12px; border: 1px solid var(--border-color); border-radius: var(--border-radius-sm); font-size: 0.95rem; box-sizing: border-box; background-color: var(--bg-secondary); color: var(--text-primary); transition: border-color 0.3s ease, background-color 0.3s ease; }
    textarea.form-input { min-height: 60px; resize: vertical; }
    .btn-primary { background: linear-gradient(135deg, var(--primary-color), #2980b9); color: white; padding: 12px 25px; border: none; border-radius: var(--border-radius-sm); font-size: 1rem; font-weight: 500; cursor: pointer; width: 100%; max-width: 450px; box-sizing: border-box; }
    .btn-primary:disabled { background: #bdc3c7; cursor: not-allowed; }
    .btn-secondary { background-color: var(--bg-secondary); color: var(--text-primary); padding: 8px 15px; border: 1px solid var(--border-color); border-radius: var(--border-radius-sm); font-size: 0.9rem; cursor: pointer; }
    .loading-spinner { width: 16px; height: 16px; border: 2px solid rgba(255,255,255,0.3); border-top-color: white; border-radius: 50%; animation: spin 1s linear infinite; display: none; margin-left: 8px; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .result-section { margin-top: 25px; }
    .result-card { padding: 18px; border-radius: var(--border-radius-sm); margin-bottom: 12px; transition: background-color 0.3s, color 0.3s, border-color 0.3s; }
    .result-success { background-color: var(--result-success-bg); border-left: 4px solid var(--success-color); color: var(--result-success-text); }
    .result-error { background-color: var(--result-error-bg); border-left: 4px solid var(--error-color); color: var(--result-error-text); }
    .result-warning { background-color: var(--result-warning-bg); border-left: 4px solid #f39c12; color: var(--result-warning-text); }
    .copy-btn { background: var(--bg-secondary); border: 1px solid var(--border-color); padding: 4px 8px; border-radius: 4px; font-size: 0.85em; cursor: pointer; margin-left: 8px;}
    .toast { position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%); background: #333; color: white; padding: 12px 20px; border-radius:var(--border-radius-sm); z-index:1001; opacity:0; transition: opacity 0.3s, transform 0.3s; }
    .toast.show { opacity:1; }
    #successfulRangeIPsList, .domain-ip-list { border: 1px solid var(--border-color); padding: 10px; border-radius: var(--border-radius-sm); max-height: 250px; overflow-y: auto;}
    .ip-item { padding:8px 5px; border-bottom:1px solid var(--border-color); display:flex; justify-content:space-between; align-items:center; }
    #successfulRangeIPsList .ip-item:last-child, .domain-ip-list .ip-item:last-child { border-bottom: none; }
    .api-docs { margin-top: 30px; padding: 25px; background: var(--bg-primary); border-radius: var(--border-radius); transition: background 0.3s ease; }
    .api-docs p { background-color: var(--bg-secondary); border: 1px solid var(--border-color); padding: 10px; border-radius: 4px; margin-bottom: 10px; word-break: break-all; transition: background 0.3s ease, border-color 0.3s ease;}
    .api-docs p code { background: none; padding: 0;}
    .footer { text-align: center; padding: 20px; margin-top: 30px; color: rgba(255,255,255,0.8); font-size: 0.85em; border-top: 1px solid rgba(255,255,255,0.1); }
    .github-corner svg { fill: var(--primary-color); color: #fff; position: fixed; top: 0; border: 0; right: 0; z-index: 1000;}
    body.dark-mode .github-corner svg { fill: #fff; color: #151513; }
    .octo-arm{transform-origin:130px 106px}
    .github-corner:hover .octo-arm{animation:octocat-wave 560ms ease-in-out}
    @keyframes octocat-wave{0%,100%{transform:rotate(0)}20%,60%{transform:rotate(-25deg)}40%,80%{transform:rotate(10deg)}}
    
    #theme-toggle {
      position: fixed;
      bottom: 25px;
      right: 25px;
      z-index: 1002;
      background: var(--bg-primary);
      border: 1px solid var(--border-color);
      width: 48px;
      height: 48px;
      border-radius: 50%;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 0;
      box-shadow: 0 4px 8px rgba(0,0,0,0.15);
      transition: background-color 0.3s, border-color 0.3s;
    }
    #theme-toggle svg {
      width: 24px;
      height: 24px;
      stroke: var(--text-primary);
      transition: all 0.3s ease;
    }
    body:not(.dark-mode) #theme-toggle .sun-icon { display: block; fill: none;}
    body:not(.dark-mode) #theme-toggle .moon-icon { display: none; }
    body.dark-mode #theme-toggle .sun-icon { display: none; }
    body.dark-mode #theme-toggle .moon-icon { display: block; fill: var(--text-primary); stroke: var(--text-primary); }
  </style>
</head>
<body>
  <a href="https://github.com/mehdi-hexing/CF-Workers-CheckProxyIP" target="_blank" class="github-corner" aria-label="View source on Github"><svg width="80" height="80" viewBox="0 0 250 250" style="position: absolute; top: 0; border: 0; right: 0;" aria-hidden="true"><path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path><path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" fill="currentColor" style="transform-origin: 130px 106px;" class="octo-arm"></path><path d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z" fill="currentColor" class="octo-body"></path></svg></a>
  <div class="container">
    <header class="header">
      <h1 class="main-title">Proxy IP Checker</h1>
    </header>
    <div class="card">
      <div class="form-section">
        <label for="proxyip" class="form-label">Enter Single Proxy IP or Domain:</label>
        <div class="input-wrapper">
          <input type="text" id="proxyip" class="form-input" placeholder="127.0.0.1 or nima.nscl.ir" autocomplete="off">
        </div>
        <label for="proxyipRangeRows" class="form-label">Enter IP Range(s) (one per line):</label>
        <div class="input-wrapper">
          <textarea id="proxyipRangeRows" class="form-input" rows="3" placeholder="127.0.0.0/24 or 127.0.0.0-255" autocomplete="off"></textarea>
        </div>
        <button id="checkBtn" class="btn-primary">
          <span style="display: flex; align-items: center; justify-content: center;">
            <span class="btn-text">Check</span>
            <span class="loading-spinner"></span>
          </span>
        </button>
      </div>
      <div id="result" class="result-section"></div>
      <div id="rangeResultCard" class="result-card result-section" style="display:none;">
         <h4>Successful IPs in Range:</h4>
         <div id="rangeResultSummary" style="margin-bottom: 15px;"></div>
         <div id="successfulRangeIPsList" style="margin-bottom: 15px; max-height: 200px; overflow-y: auto;"></div>
         <button class="btn-secondary" id="copyRangeBtn" style="display:none;">Copy Successful IPs</button>
      </div>
    </div>
    <div class="api-docs">
       <h3 style="margin-bottom:15px; text-align:center;">API Documentation</h3>
       <p><code>GET /api/check?proxyip=YOUR_IP&token=YOUR_TOKEN</code></p>
       <p><code>GET /api/resolve?domain=YOUR_DOMAIN&token=YOUR_TOKEN</code></p>
       <p><code>GET /api/ip-info?ip=TARGET_IP&token=YOUR_TOKEN</code></p>
    </div>
    <footer class="footer">
      <p>© ${new Date().getFullYear()} Proxy IP Checker - By <strong>mehdi-hexing</strong></p>
    </footer>
  </div>
  <div id="toast" class="toast"></div>
  <button id="theme-toggle" aria-label="Toggle Theme">
    <svg class="sun-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="12" cy="12" r="5"></circle>
      <line x1="12" y1="1" x2="12" y2="3"></line>
      <line x1="12" y1="21" x2="12" y2="23"></line>
      <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
      <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
      <line x1="1" y1="12" x2="3" y2="12"></line>
      <line x1="21" y1="12" x2="23" y2="12"></line>
      <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
      <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
    </svg>
    <svg class="moon-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="0.5" stroke-linecap="round" stroke-linejoin="round">
      <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
    </svg>
  </button>
  <script>
    let isChecking = false;
    let TEMP_TOKEN = '';
    let currentSuccessfulRangeIPs = [];
    let ipCheckResults = new Map();

    document.addEventListener('DOMContentLoaded', () => {
        fetch('/api/get-token').then(res => res.json()).then(data => { TEMP_TOKEN = data.token; });
        
        document.getElementById('checkBtn').addEventListener('click', checkInputs);
        
        document.getElementById('copyRangeBtn').addEventListener('click', () => {
            if (currentSuccessfulRangeIPs.length > 0) {
                const textToCopy = currentSuccessfulRangeIPs.map(item => item.ip).join('\\n');
                copyToClipboard(textToCopy, null, "All successful IPs copied!");
            }
        });

        document.body.addEventListener('click', event => {
            if (event.target.classList.contains('copy-btn')) {
                const text = event.target.getAttribute('data-copy');
                if (text) copyToClipboard(text, event.target, "Copied!");
            }
        });

        const themeToggleBtn = document.getElementById('theme-toggle');
        const body = document.body;
        
        const applyTheme = (theme) => {
            if (theme === 'dark') {
                body.classList.add('dark-mode');
            } else {
                body.classList.remove('dark-mode');
            }
        };

        const savedTheme = localStorage.getItem('theme');
        if (savedTheme) {
            applyTheme(savedTheme);
        } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
            applyTheme('dark');
        }

        themeToggleBtn.addEventListener('click', () => {
            body.classList.toggle('dark-mode');
            localStorage.setItem('theme', body.classList.contains('dark-mode') ? 'dark' : 'light');
        });
    });

    function showToast(message, duration = 3000) {
        const toast = document.getElementById('toast');
        toast.textContent = message;
        toast.classList.add('show');
        setTimeout(() => toast.classList.remove('show'), duration);
    }

    function copyToClipboard(text, element, successMessage = "Copied!") {
        navigator.clipboard.writeText(text).then(() => {
            const originalText = element ? element.textContent : '';
            if (element) element.textContent = 'Copied ✓';
            showToast(successMessage);
            if (element) setTimeout(() => { element.textContent = originalText; }, 2000);
        }).catch(err => showToast('Copy failed. Please copy manually.'));
    }
    
    function createCopyButton(text) {
        return '<span class="copy-btn" data-copy="' + text + '">' + text + '</span>';
    }

    function toggleCheckButton(checking) {
        isChecking = checking;
        const checkBtn = document.getElementById('checkBtn');
        checkBtn.disabled = checking;
        checkBtn.querySelector('.btn-text').style.display = checking ? 'none' : 'inline-block';
        checkBtn.querySelector('.loading-spinner').style.display = checking ? 'inline-block' : 'none';
    }

    async function fetchAPI(path, params) {
        if (!TEMP_TOKEN) {
             showToast("Session not ready. Retrying...");
             await new Promise(resolve => setTimeout(resolve, 500));
             if (!TEMP_TOKEN) {
                await fetch('/api/get-token').then(res => res.json()).then(data => { TEMP_TOKEN = data.token; });
             }
             if (!TEMP_TOKEN) throw new Error("Could not retrieve session token.");
        }
        params.append('token', TEMP_TOKEN);
        const response = await fetch(path + '?' + params.toString());
        const data = await response.json();
        if (!response.ok && typeof data.success === 'undefined') {
            throw new Error('API Error: ' + (data.message || response.statusText));
        }
        return data;
    }

    function isIPAddress(input) {
      const ipv4Pattern = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";
      const ipv6Pattern = "^\\\\[?([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\\\\]?$";
      return new RegExp(ipv4Pattern).test(input) || new RegExp(ipv6Pattern).test(input);
    }
    
    async function checkInputs() {
        if (isChecking) return;
        
        const singleIpInputEl = document.getElementById('proxyip');
        const rangeIpTextareaEl = document.getElementById('proxyipRangeRows');
        const singleIpToTest = singleIpInputEl.value.trim();
        const individualRangeQueries = rangeIpTextareaEl.value.split('\\n').map(s => s.trim()).filter(s => s);

        if (!singleIpToTest && individualRangeQueries.length === 0) {
            showToast('Please enter a single IP/Domain or at least one IP Range.');
            return;
        }

        toggleCheckButton(true);
        
        document.getElementById('result').innerHTML = '';
        const rangeResultCard = document.getElementById('rangeResultCard');
        const rangeResultSummary = document.getElementById('rangeResultSummary');
        const successfulIPsListDiv = document.getElementById('successfulRangeIPsList');
        const copyRangeBtn = document.getElementById('copyRangeBtn');
        
        rangeResultCard.style.display = 'none';
        currentSuccessfulRangeIPs = [];
        let totalChecked = 0, totalSuccess = 0;

        try {
            if (singleIpToTest) {
                if (isIPAddress(singleIpToTest.split(':')[0].replace(/[\\[\\]]/g, ''))) {
                    await checkAndDisplaySingleIP(singleIpToTest);
                } else {
                    await checkAndDisplayDomain(singleIpToTest);
                }
            }

            if (individualRangeQueries.length > 0) {
                rangeResultCard.style.display = 'block';
                successfulIPsListDiv.innerHTML = '<p style="text-align:center; color: var(--text-light);">Processing...</p>';
                rangeResultSummary.innerHTML = 'Total Tested: 0 | Total Successful: 0';
                
                for (const rangeQuery of individualRangeQueries) {
                    const ipsInRange = parseIPRange(rangeQuery);
                    if (ipsInRange.length === 0) {
                        showToast('Invalid format for range: "' + rangeQuery + '". Skipping.');
                        continue;
                    }
                    
                    const batchSize = 10;
                    for (let i = 0; i < ipsInRange.length; i += batchSize) {
                        const batch = ipsInRange.slice(i, i + batchSize);
                        const promises = batch.map(async (ip) => {
                            try {
                                const data = await fetchAPI('/api/check', new URLSearchParams({ proxyip: ip + ':443' }));
                                totalChecked++;
                                if (data && data.success) {
                                    totalSuccess++;
                                    const ipInfo = await fetchAPI('/api/ip-info', new URLSearchParams({ ip: data.proxyIP }));
                                    currentSuccessfulRangeIPs.push({ ip: data.proxyIP, countryCode: ipInfo.countryCode || 'N/A' });
                                }
                            } catch (e) {
                                totalChecked++;
                                console.error('Error checking ' + ip + ':', e);
                            }
                        });
                        await Promise.all(promises);
                        rangeResultSummary.innerHTML = 'Total Tested: ' + totalChecked + ' | Total Successful: ' + totalSuccess;
                        updateSuccessfulRangeIPsDisplay();
                    }
                }
                if(currentSuccessfulRangeIPs.length > 0) {
                    copyRangeBtn.style.display = 'inline-block';
                }
            }
        } catch (error) {
            showToast(error.message);
            console.error("Check failed:", error);
        } finally {
            toggleCheckButton(false);
        }
    }
    
    function updateSuccessfulRangeIPsDisplay() {
        const listDiv = document.getElementById('successfulRangeIPsList');
        if (currentSuccessfulRangeIPs.length === 0) {
            listDiv.innerHTML = '<p style="text-align:center; color: var(--text-light);">No successful IPs found.</p>';
            return;
        }
        let html = '<div class="ip-grid">';
        currentSuccessfulRangeIPs.forEach(item => {
            html += '<div class="ip-item"><span>' + item.ip + '</span><span style="font-weight: 500;">' + item.countryCode + '</span></div>';
        });
        html += '</div>';
        listDiv.innerHTML = html;
    }

    function formatIPInfo(ipInfo, isShort = false) {
      if (!ipInfo || ipInfo.status !== 'success') { return ''; }
      const country = ipInfo.country || 'N/A';
      const as = ipInfo.as || 'N/A';
      if (isShort) return ' (' + country + ' - ' + as.substring(0, 15) + '...)';
      return '<span style="font-size:0.85em; color: var(--text-light);">' + country + ' - ' + as + '</span>';
    }

    async function getIPInfoWithIndex(ip, index) {
      try {
        const ipInfo = await fetchAPI('/api/ip-info', new URLSearchParams({ ip: ip.split(':')[0].replace(/[\\[\\]]/g, '') }));
        const infoElement = document.getElementById('domain-ip-info-' + index);
        if (infoElement) infoElement.innerHTML = formatIPInfo(ipInfo, true);
      } catch (error) { console.warn("Could not get IP info for " + ip, error); }
    }

    async function checkDomainIPWithIndex(ip, port, index) {
      try {
        const ipToTest = ip.includes(':') || ip.includes(']:') ? ip : (ip + ':' + port);
        const result = await fetchAPI('/api/check', new URLSearchParams({ proxyip: ipToTest }));
        ipCheckResults.set(ipToTest, result);
        
        const statusIcon = document.getElementById('domain-ip-status-' + index);
        if (statusIcon) statusIcon.textContent = result.success ? '✅' : '❌';
      } catch (error) {
        const statusIcon = document.getElementById('domain-ip-status-' + index);
        if (statusIcon) statusIcon.textContent = '⚠️';
        ipCheckResults.set(ip, { success: false, error: error.message });
      }
    }

    async function checkAndDisplaySingleIP(proxyip) {
        const resultDiv = document.getElementById('result');
        resultDiv.innerHTML = '<p style="text-align:center; color: var(--text-light);">Checking...</p>';
        try {
            const data = await fetchAPI('/api/check', new URLSearchParams({ proxyip: proxyip }));
            let ipInfoHTML = '';
            if (data && data.success) {
                const ipInfo = await fetchAPI('/api/ip-info', new URLSearchParams({ ip: data.proxyIP }));
                const country = ipInfo.country || 'N/A';
                const as = ipInfo.as || 'N/A';
                ipInfoHTML = '<p><strong>🌍 Country:</strong> ' + country + '</p>' +
                             '<p><strong>🌐 AS:</strong> ' + as + '</p>';
                resultDiv.innerHTML =
                    '<div class="result-card result-success">' +
                        '<h3>✅ ProxyIP Valid</h3>' +
                        '<p><strong>📍 IP Address:</strong> ' + createCopyButton(data.proxyIP) + '</p>' +
                        ipInfoHTML +
                        '<p><strong>🔌 Port:</strong> ' + data.portRemote + '</p>' +
                        '<p><strong>🕒 Check Time:</strong> ' + new Date(data.timestamp).toLocaleString() + '</p>' +
                    '</div>';
            } else {
                 resultDiv.innerHTML =
                    '<div class="result-card result-error">' +
                        '<h3>❌ ProxyIP Invalid</h3>' +
                        '<p><strong>📍 IP Address:</strong> ' + createCopyButton(proxyip) + '</p>' +
                        '<p><strong>Error:</strong> ' + (data.error || 'Check failed.') + '</p>' +
                        '<p><strong>🕒 Check Time:</strong> ' + new Date(data.timestamp).toLocaleString() + '</p>' +
                    '</div>';
            }
        } catch (error) {
            resultDiv.innerHTML = '<div class="result-card result-error"><h3>❌ Error</h3><p>' + error.message + '</p></div>';
        }
    }

    async function checkAndDisplayDomain(domain) {
        const resultDiv = document.getElementById('result');
        ipCheckResults.clear();
        resultDiv.innerHTML = '<p style="text-align:center; color: var(--text-light);">Resolving domain...</p>';
        try {
            let port = 443;
            let cleanDomain = domain;
            if (domain.includes(':') && !domain.startsWith('[')) {
                const parts = domain.split(':');
                if(parts.length === 2) {
                   cleanDomain = parts[0];
                   const parsedPort = parseInt(parts[1]);
                   if(!isNaN(parsedPort)) port = parsedPort;
                }
            }

            const resolveData = await fetchAPI('/api/resolve', new URLSearchParams({ domain: cleanDomain }));
            if (!resolveData.success || !resolveData.ips || resolveData.ips.length === 0) {
                throw new Error(resolveData.error || 'Could not resolve domain to any IPs.');
            }
            const ips = resolveData.ips;
            
            let html = '<div class="result-card result-warning">' +
                '<h3 id="domain-result-header">🔍 Resolving & Checking Domain...</h3>' +
                '<p><strong>🌐 Domain:</strong> ' + createCopyButton(domain) + '</p>' +
                '<p><strong>🔌 Default Port for Test:</strong> ' + port + '</p>' +
                '<p><strong>📋 IPs Found:</strong> ' + ips.length + '</p>' +
                '<div class="domain-ip-list">';
            ips.forEach((ip, index) => {
                html += '<div class="ip-item" id="domain-ip-item-' + index + '">' +
                        '<div>' + createCopyButton(ip) + '<span id="domain-ip-info-' + index + '"></span></div>' +
                        '<span id="domain-ip-status-' + index + '">🔄</span>' +
                        '</div>';
            });
            html += '</div></div>';
            resultDiv.innerHTML = html;

            const checkPromises = ips.map((ip, index) => checkDomainIPWithIndex(ip, port, index));
            const ipInfoPromises = ips.map((ip, index) => getIPInfoWithIndex(ip, index));
            
            await Promise.all([...checkPromises, ...ipInfoPromises]);

            const successCount = Array.from(ipCheckResults.values()).filter(r => r.success).length;
            const resultCardHeader = document.getElementById('domain-result-header');

            if (successCount === ips.length) {
                resultCardHeader.textContent = '✅ All Domain IPs Valid';
            } else if (successCount === 0) {
                resultCardHeader.textContent = '❌ All Domain IPs Invalid';
            } else {
                resultCardHeader.textContent = '⚠️ Some Domain IPs Valid (' + successCount + '/' + ips.length + ')';
            }

        } catch (error) {
            resultDiv.innerHTML = '<div class="result-card result-error"><h3>❌ Error</h3><p>' + error.message + '</p></div>';
        }
    }
    
    function parseIPRange(rangeInput) {
        const ips = [];
        const cidrPattern = new RegExp(/^(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\/24$/);
        const simpleRangePattern = new RegExp(/^(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.)(\\d{1,3})-(\\d{1,3})$/);

        if (cidrPattern.test(rangeInput)) {
            const baseIp = rangeInput.split('/')[0];
            const baseParts = baseIp.split('.');
            for (let i = 1; i <= 255; i++) {
                ips.push(baseParts[0] + '.' + baseParts[1] + '.' + baseParts[2] + '.' + i);
            }
        } else if (simpleRangePattern.test(rangeInput)) {
            const match = rangeInput.match(simpleRangePattern);
            const prefix = match[1];
            const startOctet = parseInt(match[2]);
            const endOctet = parseInt(match[3]);
            if (!isNaN(startOctet) && !isNaN(endOctet) && startOctet <= endOctet && startOctet >=0 && endOctet <= 255) {
                for (let i = startOctet; i <= endOctet; i++) {
                    ips.push(prefix + i);
                }
            }
        }
        return ips;
    }
  </script>
</body>
</html>`;
}
