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

const isIp = (input) => {
  const ipv4Pattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipv6Pattern = /^(?:\[)?((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?::[0-9a-fA-F]{1,4}){1,7}|::)(?:\])?$/;
  return ipv4Pattern.test(input) || ipv6Pattern.test(input);
};

const isDomain = (input) => /^(?!-)[A-Za-z0-9-]+([\-\.]{1}[a-z0-9]+)*\.[A-Za-z]{2,6}$/.test(input);

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

    const isTokenValid = () => {
      if (!env.TOKEN) return true;
      const providedToken = url.searchParams.get('token');
      return providedToken === permanentTOKEN || providedToken === temporaryTOKEN;
    };

    if (path.toLowerCase().startsWith('/api/')) {
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

    if (path.toLowerCase() === '/iprange/') {
      const range = url.searchParams.get('range') || '';
      const results = await processAndRender(range, env, ctx);
      return new Response(results, { headers: { "content-type": "text/html;charset=UTF-8" } });
    }

    if (path.toLowerCase() === '/file/') {
      const fileUrl = url.searchParams.get('url');
      if (fileUrl) {
        try {
          const response = await fetch(fileUrl);
          if (!response.ok) throw new Error(`Failed to fetch URL: ${response.statusText}`);
          const contentType = response.headers.get('content-type') || 'text/plain';
          const content = await response.text();
          const results = await processAndRenderFile(content, contentType, env, ctx);
          return new Response(results, { headers: { "content-type": "text/html;charset=UTF-8" } });
        } catch (error) {
          return new Response(generateErrorHTML(error.message), { headers: { "content-type": "text/html;charset=UTF-8" } });
        }
      }

      const formData = await request.formData();
      const file = formData.get('file');
      if (!file) return new Response('No file or URL provided', { status: 400 });
      const contentType = file.type;
      const content = await file.text();
      const results = await processAndRenderFile(content, contentType, env, ctx);
      return new Response(results, { headers: { "content-type": "text/html;charset=UTF-8" } });
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
    html { height: 100%; }
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
    .ip-item { padding: 10px; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center; gap: 12px; }
    .ip-item:last-child { border-bottom: none; }
    .domain-ip-list { border: 1px solid var(--border-color); padding: 10px; border-radius: var(--border-radius-sm); max-height: 250px; overflow-y: auto; }
    .ip-list-container { border: 1px solid var(--border-color); padding: 10px; border-radius: var(--border-radius-sm); max-height: 250px; overflow-y: auto; }
    .ip-item-multi { padding: 8px 5px; border-bottom: 1px solid var(--border-color); display: flex; align-items: center; gap: 12px; }
    .ip-item-multi:last-child { border-bottom: none; }
    .ip-tag { background: var(--bg-secondary); border: 1px solid var(--border-color); padding: 4px 8px; border-radius: 4px; font-size: 0.85em; cursor: pointer; }
    .ip-details { font-size: 0.85em; color: var(--text-light); }
    .toast { position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%); background: #333; color: white; padding: 12px 20px; border-radius: var(--border-radius-sm); z-index: 1001; opacity: 0; transition: opacity 0.3s, transform 0.3s; }
    .toast.show { opacity: 1; }
    #successfulRangeIPsList { border: 1px solid var(--border-color); padding: 10px; border-radius: var(--border-radius-sm); max-height: 250px; overflow-y: auto; }
    #successfulRangeIPsList .ip-item:last-child { border-bottom: none; }
    .api-docs { margin-top: 30px; padding: 25px; background: var(--bg-primary); border-radius: var(--border-radius); transition: background 0.3s ease; }
    .api-docs p { background-color: var(--bg-secondary); border: 1px solid var(--border-color); padding: 10px; border-radius: 4px; margin-bottom: 10px; word-break: break-all; transition: background 0.3s ease, border-color 0.3s ease;}
    .api-docs p code { background: none; padding: 0;}
    .footer { text-align: center; padding: 20px; margin-top: 30px; color: rgba(255,255,255,0.8); font-size: 0.85em; border-top: 1px solid rgba(255,255,255,0.1); }
    .github-corner svg { fill: var(--primary-color); color: #fff; position: fixed; top: 0; border: 0; right: 0; z-index: 1000;}
    body.dark-mode .github-corner svg { fill: #fff; color: #151513; }
    .octo-arm { transform-origin: 130px 106px; }
    .github-corner:hover .octo-arm { animation: octocat-wave 560ms ease-in-out; }
    @keyframes octocat-wave { 0%,100% { transform: rotate(0); } 20%,60% { transform: rotate(-25deg); } 40%,80% { transform: rotate(10deg); } }
    #theme-toggle {
      position: fixed; bottom: 25px; right: 25px; z-index: 1002; background: var(--bg-primary);
      border: 1px solid var(--border-color); width: 48px; height: 48px; border-radius: 50%;
      cursor: pointer; display: flex; align-items: center; justify-content: center; padding: 0;
      box-shadow: 0 4px 8px rgba(0,0,0,0.15); transition: background-color 0.3s, border-color 0.3s;
    }
    #theme-toggle svg { width: 24px; height: 24px; stroke: var(--text-primary); transition: all 0.3s ease; }
    body:not(.dark-mode) #theme-toggle .sun-icon { display: block; fill: none; }
    body:not(.dark-mode) #theme-toggle .moon-icon { display: none; }
    body.dark-mode #theme-toggle .sun-icon { display: none; }
    body.dark-mode #theme-toggle .moon-icon { display: block; fill: var(--text-primary); stroke: var(--text-primary); }
  </style>
</head>
<body>
  <a href="https://github.com/mehdi-hexing/CF-Workers-CheckProxyIP" target="_blank" class="github-corner" aria-label="View source on Github">
    <svg width="80" height="80" viewBox="0 0 250 250" style="position: absolute; top: 0; border: 0; right: 0;" aria-hidden="true">
      <path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path>
      <path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" fill="currentColor" style="transform-origin: 130px 106px;" class="octo-arm"></path>
      <path d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z" fill="currentColor" class="octo-body"></path>
    </svg>
  </a>
  <div class="container">
    <header class="header">
      <h1 class="main-title">Proxy IP Checker</h1>
    </header>
    <div class="card">
      <div class="form-section">
        <label for="mainInput" class="form-label">Enter Single Proxy IP or Domain:</label>
        <div class="input-wrapper">
          <input type="text" id="mainInput" class="form-input" placeholder="127.0.0.1 or nima.nscl.ir" autocomplete="off">
        </div>
        <label for="rangeInput" class="form-label">Enter IP Range(s) (one per line, e.g., 127.0.0.0/24 or 127.0.0.0-255):</label>
        <div class="input-wrapper">
          <textarea id="rangeInput" class="form-input" rows="3" placeholder="127.0.0.0/24 or 127.0.0.0-255" autocomplete="off"></textarea>
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
    <div class="card">
      <div class="form-section">
        <label for="fileInput" class="form-label">Upload IP File (txt or csv) or Enter URL:</label>
        <div class="input-wrapper">
          <input type="file" id="fileInput" class="form-input" accept=".txt,.csv">
          <input type="text" id="urlInput" class="form-input" placeholder="https://example.com/ips.txt" autocomplete="off">
        </div>
        <button id="fileCheckBtn" class="btn-primary">Check File or URL</button>
      </div>
    </div>
    <div class="api-docs">
      <h3 style="margin-bottom:15px; text-align:center;">API Documentation</h3>
      <p><code>GET /api/check?proxyip=YOUR_IP&token=YOUR_TOKEN</code></p>
      <p><code>GET /api/resolve?domain=YOUR_DOMAIN&token=YOUR_TOKEN</code></p>
      <p><code>GET /api/ip-info?ip=TARGET_IP&token=YOUR_TOKEN</code></ elleckAndDisplaySingleIP(ipLines[0], document.getElementById('result'));
      } else if (ipLines.length > 1 && domainLines.length === 0) {
        await checkAndDisplayMultipleIPs(ipLines, document.getElementById('result'));
      } else {
        const checkPromises = lines.map(async (line) => {
          if (isDomain(line)) {
            await checkAndDisplayDomain(line, document.getElementById('result'));
          } else if (isIPAddress(line.split(':')[0].replace(/\[|\]/g, ''))) {
            await checkAndDisplaySingleIP(line, document.getElementById('result'));
          } else {
            const resultCard = document.createElement('div');
            resultCard.classList.add('result-card', 'result-error');
            resultCard.innerHTML = `<h3> ❌ Unrecognized Format</h3><p>Input '${line}' is not a valid IP or domain.</p>`;
            document.getElementById('result').appendChild(resultCard);
          }
        });
        await Promise.all(checkPromises);
      }
    }
    
    async function processRangeInput(lines) {
      if (lines.length === 0) return;
      
      const rangeResultCard = document.getElementById('rangeResultCard');
      const rangeResultSummary = document.getElementById('rangeResultSummary');
      const successfulIPsListDiv = document.getElementById('successfulRangeIPsList');
      const copyRangeBtn = document.getElementById('copyRangeBtn');
      
      rangeResultCard.style.display = 'block';
      rangeSuccessfulIPs = [];
      successfulIPsListDiv.innerHTML = '<p style="text-align:center; color: var(--text-light);">Processing...</p>';
      rangeResultSummary.innerHTML = 'Total Tested: 0 | Total Successful: 0';
      
      let totalChecked = 0, totalSuccess = 0;
      
      for (const range of lines) {
        const ipsInRange = parseIPRange(range);
        if (ipsInRange.length === 0) {
          showToast('Invalid format for range: "' + range + '". Skipping.');
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
                rangeSuccessfulIPs.push({ ip: data.proxyIP, countryCode: ipInfo.countryCode || 'N/A', country: ipInfo.country || 'N/A', as: ipInfo.as || 'N/A' });
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
      
      if (rangeSuccessfulIPs.length > 0) {
        copyRangeBtn.style.display = 'inline-block';
      }
    }

    function updateSuccessfulRangeIPsDisplay() {
      const listDiv = document.getElementById('successfulRangeIPsList');
      if (rangeSuccessfulIPs.length === 0) {
        listDiv.innerHTML = '<p style="text-align:center; color: var(--text-light);">No successful IPs found.</p>';
        return;
      }
      let html = '<div class="ip-grid">';
      rangeSuccessfulIPs.forEach(item => {
        html += `
          <div class="ip-item">
            <span>${createCopyButton(item.ip)}</span>
            <span style="font-weight: 500;">${item.countryCode}</span>
            <span style="font-size: 0.85em; color: var(--text-light);">(${item.country} - ${item.as})</span>
          </div>
        `;
      });
      html += '</div>';
      listDiv.innerHTML = html;
    }

    async function checkAndDisplayMultipleIPs(ips, parentElement) {
      const resultCard = document.createElement('div');
      resultCard.className = 'result-card';
      resultCard.innerHTML = `<h3>🔍 Checking ${ips.length} IPs...</h3><div class="ip-list-container"></div>`;
      parentElement.appendChild(resultCard);
      
      const listContainer = resultCard.querySelector('.ip-list-container');

      const checkPromises = ips.map(async (ip) => {
        try {
          const data = await fetchAPI('/api/check', new URLSearchParams({ proxyip: ip }));
          if (data.success) {
            const ipInfo = await fetchAPI('/api/ip-info', new URLSearchParams({ ip: data.proxyIP }));
            const detailsParts = [];
            if (ipInfo.country) detailsParts.push(ipInfo.country);
            if (ipInfo.as) detailsParts.push(ipInfo.as);
            return {
              ip: data.proxyIP,
              details: detailsParts.length > 0 ? `(${detailsParts.join(' - ')})`
                : ''
            };
          }
        } catch (e) { /* Ignore failed IPs */ }
        return null;
      });

      const results = await Promise.all(checkPromises);
      const successfulIPs = results.filter(Boolean);

      if (successfulIPs.length === 0) {
        resultCard.innerHTML = '<h3>❌ No valid proxies found among the provided IPs.</h3>';
        resultCard.classList.add('result-error');
        return;
      }
      
      const ipListHTML = successfulIPs.map(item => `
        <div class="ip-item-multi">
          <span class="ip-tag" data-copy="${item.ip}">${item.ip}</span>
          <span class="ip-details">${item.details}</span>
        </div>
      `).join('');

      resultCard.innerHTML = `<h3>✅ Found ${successfulIPs.length} valid proxies:</h3><div class="ip-list-container">${ipListHTML}</div>`;
      resultCard.classList.add('result-success');
    }

    async function checkAndDisplaySingleIP(proxyip, parentElement) {
      const resultCard = document.createElement('div');
      resultCard.className = 'result-card result-warning';
      resultCard.innerHTML = `<p style="text-align:center;">Checking ${proxyip}...</p>`;
      parentElement.appendChild(resultCard);

      try {
        const data = await fetchAPI('/api/check', new URLSearchParams({ proxyip }));
        let ipInfoHTML = '';
        if (data.success) {
          const ipInfo = await fetchAPI('/api/ip-info', new URLSearchParams({ ip: data.proxyIP }));
          const country = ipInfo.country || 'N/A';
          const as = ipInfo.as || 'N/A';
          ipInfoHTML = `
            <p><strong>🌍 Country:</strong> ${country}</p>
            <p><strong>🌐 AS:</strong> ${as}</p>
          `;
          resultCard.innerHTML = `
            <div class="result-card result-success">
              <h3>✅ ProxyIP Valid</h3>
              <p><strong>📍 IP Address:</strong> ${createCopyButton(data.proxyIP)}</p>
              ${ipInfoHTML}
              <p><strong>🔌 Port:</strong> ${data.portRemote}</p>
              <p><strong>🕒 Check Time:</strong> ${new Date(data.timestamp).toLocaleString()}</p>
            </div>
          `;
        } else {
          resultCard.innerHTML = `
            <div class="result-card result-error">
              <h3>❌ ProxyIP Invalid</h3>
              <p><strong>📍 IP Address:</strong> ${createCopyButton(proxyip)}</p>
              <p><strong>Error:</strong> ${data.error || 'Check failed.'}</p>
              <p><strong>🕒 Check Time:</strong> ${new Date(data.timestamp).toLocaleString()}</p>
            </div>
          `;
        }
      } catch (error) {
        resultCard.innerHTML = `<div class="result-card result-error"><h3>❌ Error</h3><p>${error.message}</p></div>`;
      }
    }
    
    async function checkAndDisplayDomain(domain, parentElement) {
      domainCheckCounter++;
      const currentDomainId = domainCheckCounter;
      
      const resultCard = document.createElement('div');
      resultCard.className = 'result-card result-warning';
      resultCard.innerHTML = `<p style="text-align:center;">Resolving ${domain}...</p>`;
      parentElement.appendChild(resultCard);

      try {
        let port = 443;
        let cleanDomain = domain;
        if (domain.includes(':') && !domain.startsWith('[')) {
          const parts = domain.split(':');
          if (parts.length === 2) {
            cleanDomain = parts[0];
            const parsedPort = parseInt(parts[1]);
            if (!isNaN(parsedPort)) port = parsedPort;
          }
        }

        const resolveData = await fetchAPI('/api/resolve', new URLSearchParams({ domain: cleanDomain }));
        if (!resolveData.success || !resolveData.ips || resolveData.ips.length === 0) {
          throw new Error(resolveData.error || 'Could not resolve domain to any IPs.');
        }
        const ips = resolveData.ips;
        
        let html = `
          <div class="result-card result-warning">
            <h3 id="domain-result-header-${currentDomainId}">🔍 Resolving & Checking Domain...</h3>
            <p><strong>🌐 Domain:</strong> ${createCopyButton(domain)}</p>
            <p><strong>🔌 Default Port for Test:</strong> ${port}</p>
            <p><strong>📋 IPs Found:</strong> ${ips.length}</p>
            <div class="domain-ip-list">
        `;
        ips.forEach((ip, index) => {
          html += `
            <div class="ip-item" id="domain-ip-item-${currentDomainId}-${index}">
              <div style="display: flex; align-items: center; gap: 12px;">
                ${createCopyButton(ip)}
                <span id="domain-ip-info-${currentDomainId}-${index}"></span>
              </div>
              <span id="domain-ip-status-${currentDomainId}-${index}">🔄</span>
            </div>
          `;
        });
        html += '</div></div>';
        resultCard.innerHTML = html;

        const checkPromises = ips.map((ip, index) => checkDomainIPWithIndex(ip, port, currentDomainId, index));
        const ipInfoPromises = ips.map((ip, index) => getIPInfoWithIndex(ip, currentDomainId, index));
        
        await Promise.all([...checkPromises, ...ipInfoPromises]);

        const successCount = Array.from(ipCheckResults.values()).filter(r => r.success).length;
        const resultCardHeader = document.getElementById('domain-result-header-' + currentDomainId);

        if (successCount === ips.length) {
          resultCardHeader.textContent = '✅ All Domain IPs Valid';
          resultCard.classList.remove('result-warning');
          resultCard.classList.add('result-success');
        } else if (successCount === 0) {
          resultCardHeader.textContent = '❌ All Domain IPs Invalid';
          resultCard.classList.remove('result-warning');
          resultCard.classList.add('result-error');
        } else {
          resultCardHeader.textContent = '⚠️ Some Domain IPs Valid (' + successCount + '/' + ips.length + ')';
        }

      } catch (error) {
        resultCard.innerHTML = `<div class="result-card result-error"><h3>❌ Error</h3><p>${error.message}</p></div>`;
      }
    }

    async function checkDomainIPWithIndex(ip, port, domainId, index) {
      try {
        const ipToTest = ip.includes(':') || ip.includes(']:') ? ip : (ip + ':' + port);
        const result = await fetchAPI('/api/check', new URLSearchParams({ proxyip: ipToTest }));
        ipCheckResults.set(ipToTest, result);
        
        const statusIcon = document.getElementById('domain-ip-status-' + domainId + '-' + index);
        if (statusIcon) statusIcon.textContent = result.success ? '✅' : '❌';
      } catch (error) {
        const statusIcon = document.getElementById('domain-ip-status-' + domainId + '-' + index);
        if (statusIcon) statusIcon.textContent = '⚠️';
        ipCheckResults.set(ip, { success: false, error: error.message });
      }
    }

    async function getIPInfoWithIndex(ip, domainId, index) {
      try {
        const ipInfo = await fetchAPI('/api/ip-info', new URLSearchParams({ ip: ip.split(':')[0].replace(/\[|\]/g, '') }));
        const infoElement = document.getElementById('domain-ip-info-' + domainId + '-' + index);
        if (infoElement && ipInfo.status === 'success') {
          const country = ipInfo.country || 'N/A';
          const as = ipInfo.as || 'N/A';
          infoElement.innerHTML = `(${country} - ${as.substring(0, 15)}...) <span>✅</span>`;
        }
      } catch (error) {
        console.warn("Could not get IP info for " + ip, error);
      }
    }

    async function processAndRender(range, env, ctx) {
      const faviconURL = env.ICO || 'https://cf-assets.www.cloudflare.com/dzlvafdwdttg/19kSkLSfWtDcspvQI5pit4/c5630cf25d589a0de91978ca29486259/performance-acceleration-bolt.svg';
      let resultHTML = '';
      const ips = parseIPRange(range);
      if (ips.length === 0) {
        resultHTML = `<div class="result-card result-error"><h3>❌ Invalid Range</h3><p>Range '${range}' is not a valid CIDR or range format.</p></div>`;
      } else {
        const results = await Promise.all(ips.map(async (ip) => {
          try {
            const data = await checkProxyIP(ip + ':443');
            if (data.success) {
              const ipInfo = await fetchAPI('/api/ip-info', new URLSearchParams({ ip: data.proxyIP }));
              return { ...data, countryCode: ipInfo.countryCode || 'N/A', country: ipInfo.country || 'N/A', as: ipInfo.as || 'N/A' };
            }
            return data;
          } catch (e) {
            return { success: false, proxyIP: ip, error: e.message };
          }
        }));

        resultHTML = results.map(data => {
          if (data.success) {
            return `
              <div class="result-card result-success">
                <h3>✅ ProxyIP Valid</h3>
                <p><strong>📍 IP Address:</strong> ${createCopyButton(data.proxyIP)}</p>
                <p><strong>🌍 Country Code:</strong> ${data.countryCode}</p>
                <p><strong>🌍 Country:</strong> ${data.country}</p>
                <p><strong>🌐 AS:</strong> ${data.as}</p>
              </div>
            `;
          } else {
            return `
              <div class="result-card result-error">
                <h3>❌ ProxyIP Invalid</h3>
                <p><strong>📍 IP Address:</strong> ${createCopyButton(data.proxyIP)}</p>
                <p><strong>Error:</strong> ${data.error || 'Check failed.'}</p>
              </div>
            `;
          }
        }).join('');
      }

      return `
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>IP Range Check Results</title>
          <link rel="icon" href="${faviconURL}" type="image/x-icon">
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
            body { 
              font-family: 'Inter', sans-serif; 
              background: var(--bg-gradient);
              background-attachment: fixed;
              color: var(--text-primary);
              line-height: 1.6; margin: 0; padding: 0; min-height: 100vh; 
              display: flex; flex-direction: column; align-items: center;
            }
            .container { 
              max-width: 800px; width: 100%; padding: 20px; box-sizing: border-box;
            }
            .header { text-align: center; margin-bottom: 30px; }
            .main-title { font-size: 2.2rem; font-weight: 700; color: #fff; }
            .result-card { padding: 18px; border-radius: var(--border-radius-sm); margin-bottom: 12px; }
            .result-success { background-color: var(--result-success-bg); border-left: 4px solid var(--success-color); color: var(--result-success-text); }
            .result-error { background-color: var(--result-error-bg); border-left: 4px solid var(--error-color); color: var(--result-error-text); }
            .copy-btn { background: var(--bg-secondary); border: 1px solid var(--border-color); padding: 4px 8px; border-radius: 4px; font-size: 0.85em; cursor: pointer; margin-left: 8px; }
            .toast { position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%); background: #333; color: white; padding: 12px 20px; border-radius: var(--border-radius-sm); z-index: 1001; opacity: 0; transition: opacity 0.3s; }
            .toast.show { opacity: 1; }
            #theme-toggle {
              position: fixed; bottom: 25px; right: 25px; z-index: 1002; background: var(--bg-primary);
              border: 1px solid var(--border-color); width: 48px; height: 48px; border-radius: 50%;
              cursor: pointer; display: flex; align-items: center; justify-content: center; padding: 0;
              box-shadow: 0 4px 8px rgba(0,0,0,0.15);
            }
            #theme-toggle svg { width: 24px; height: 24px; stroke: var(--text-primary); }
            body:not(.dark-mode) #theme-toggle .sun-icon { display: block; fill: none; }
            body:not(.dark-mode) #theme-toggle .moon-icon { display: none; }
            body.dark-mode #theme-toggle .sun-icon { display: none; }
            body.dark-mode #theme-toggle .moon-icon { display: block; fill: var(--text-primary); stroke: var(--text-primary); }
          </style>
        </head>
        <body>
          <div class="container">
            <header class="header">
              <h1 class="main-title">IP Range Check Results</h1>
            </header>
            <div id="result">${resultHTML}</div>
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
            function showToast(message, duration = 3000) {
              const toast = document.getElementById('toast');
              toast.textContent = message;
              toast.classList.add('show');
              setTimeout(() => toast.classList.remove('show'), duration);
            }

            function copyToClipboard(text, element) {
              navigator.clipboard.writeText(text).then(() => {
                showToast('Copied!');
              }).catch(err => showToast('Copy failed.'));
            }

            document.body.addEventListener('click', event => {
              if (event.target.classList.contains('copy-btn')) {
                const text = event.target.getAttribute('data-copy');
                if (text) copyToClipboard(text, event.target);
              }
            });

            const themeToggleBtn = document.getElementById('theme-toggle');
            const body = document.body;
            
            if (localStorage.getItem('theme') === 'dark' || (!('theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
              body.classList.add('dark-mode');
            }

            themeToggleBtn.addEventListener('click', () => {
              body.classList.toggle('dark-mode');
              localStorage.setItem('theme', body.classList.contains('dark-mode') ? 'dark' : 'light');
            });
          </script>
        </body>
        </html>
      `;
    }

    async function processAndRenderFile(content, contentType, env, ctx) {
      const faviconURL = env.ICO || 'https://cf-assets.www.cloudflare.com/dzlvafdwdttg/19kSkLSfWtDcspvQI5pit4/c5630cf25d589a0de91978ca29486259/performance-acceleration-bolt.svg';
      let resultHTML = '';
      const lines = content.split(/[\n,;\s]+/).map(s => s.trim()).filter(Boolean);
      const validIPs = lines.filter(line => isIPAddress(line.split(':')[0].replace(/\[|\]/g, '')));

      if (validIPs.length === 0) {
        resultHTML = `<div class="result-card result-error"><h3>❌ No Valid IPs</h3><p>No valid IP addresses found in the provided content.</p></div>`;
      } else {
        const results = await Promise.all(validIPs.map(async (ip) => {
          try {
            const data = await checkProxyIP(ip + ':443');
            if (data.success) {
              const ipInfo = await fetchAPI('/api/ip-info', new URLSearchParams({ ip: data.proxyIP }));
              return { ...data, countryCode: ipInfo.countryCode || 'N/A', country: ipInfo.country || 'N/A', as: ipInfo.as || 'N/A' };
            }
            return data;
          } catch (e) {
            return { success: false, proxyIP: ip, error: e.message };
          }
        }));

        resultHTML = results.map(data => {
          if (data.success) {
            return `
              <div class="result-card result-success">
                <h3>✅ ProxyIP Valid</h3>
                <p><strong>📍 IP Address:</strong> ${createCopyButton(data.proxyIP)}</p>
                <p><strong>🌍 Country Code:</strong> ${data.countryCode}</p>
                <p><strong>🌍 Country:</strong> ${data.country}</p>
                <p><strong>🌐 AS:</strong> ${data.as}</p>
              </div>
            `;
          } else {
            return `
              <div class="result-card result-error">
                <h3>❌ ProxyIP Invalid</h3>
                <p><strong>📍 IP Address:</strong> ${createCopyButton(data.proxyIP)}</p>
                <p><strong>Error:</strong> ${data.error || 'Check failed.'}</p>
              </div>
            `;
          }
        }).join('');
      }

      return `
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>File IP Check Results</title>
          <link rel="icon" href="${faviconURL}" type="image/x-icon">
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
            body { 
              font-family: 'Inter', sans-serif; 
              background: var(--bg-gradient);
              background-attachment: fixed;
              color: var(--text-primary);
              line-height: 1.6; margin: 0; padding: 0; min-height: 100vh; 
              display: flex; flex-direction: column; align-items: center;
            }
            .container { 
              max-width: 800px; width: 100%; padding: 20px; box-sizing: border-box;
            }
            .header { text-align: center; margin-bottom: 30px; }
            .main-title { font-size: 2.2rem; font-weight: 700; color: #fff; }
            .result-card { padding: 18px; border-radius: var(--border-radius-sm); margin-bottom: 12px; }
            .result-success { background-color: var(--result-success-bg); border-left: 4px solid var(--success-color); color: var(--result-success-text); }
            .result-error { background-color: var(--result-error-bg); border-left: 4px solid var(--error-color); color: var(--result-error-text); }
            .copy-btn { background: var(--bg-secondary); border: 1px solid var(--border-color); padding: 4px 8px; border-radius: 4px; font-size: 0.85em; cursor: pointer; margin-left: 8px; }
            .toast { position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%); background: #333; color: white; padding: 12px 20px; border-radius: var(--border-radius-sm); z-index: 1001; opacity: 0; transition: opacity 0.3s; }
            .toast.show { opacity: 1; }
            #theme-toggle {
              position: fixed; bottom: 25px; right: 25px; z-index: 1002; background: var(--bg-primary);
              border: 1px solid var(--border-color); width: 48px; height: 48px; border-radius: 50%;
              cursor: pointer; display: flex; align-items: center; justify-content: center; padding: 0;
              box-shadow: 0 4px 8px rgba(0,0,0,0.15);
            }
            #theme-toggle svg { width: 24px; height: 24px; stroke: var(--text-primary); }
            body:not(.dark-mode) #theme-toggle .sun-icon { display: block; fill: none; }
            body:not(.dark-mode) #theme-toggle .moon-icon { display: none; }
            body.dark-mode #theme-toggle .sun-icon { display: none; }
            body.dark-mode #theme-toggle .moon-icon { display: block; fill: var(--text-primary); stroke: var(--text-primary); }
          </style>
        </head>
        <body>
          <div class="container">
            <header class="header">
              <h1 class="main-title">File IP Check Results</h1>
            </header>
            <div id="result">${resultHTML}</div>
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
            function showToast(message, duration = 3000) {
              const toast = document.getElementById('toast');
              toast.textContent = message;
              toast.classList.add('show');
              setTimeout(() => toast.classList.remove('show'), duration);
            }

            function copyToClipboard(text, element) {
              navigator.clipboard.writeText(text).then(() => {
                showToast('Copied!');
              }).catch(err => showToast('Copy failed.'));
            }

            document.body.addEventListener('click', event => {
              if (event.target.classList.contains('copy-btn')) {
                const text = event.target.getAttribute('data-copy');
                if (text) copyToClipboard(text, event.target);
              }
            });

            const themeToggleBtn = document.getElementById('theme-toggle');
            const body = document.body;
            
            if (localStorage.getItem('theme') === 'dark' || (!('theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
              body.classList.add('dark-mode');
            }

            themeToggleBtn.addEventListener('click', () => {
              body.classList.toggle('dark-mode');
              localStorage.setItem('theme', body.classList.contains('dark-mode') ? 'dark' : 'light');
            });
          </script>
        </body>
        </html>
      `;
    }

    function generateErrorHTML(message) {
      const faviconURL = 'https://cf-assets.www.cloudflare.com/dzlvafdwdttg/19kSkLSfWtDcspvQI5pit4/c5630cf25d589a0de91978ca29486259/performance-acceleration-bolt.svg';
      return `
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Error</title>
          <link rel="icon" href="${faviconURL}" type="image/x-icon">
          <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
          <style>
            :root {
              --bg-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
              --bg-primary: #ffffff;
              --text-primary: #2c3e50;
              --border-color: #dee2e6;
              --error-color: #e74c3c;
              --result-error-bg: #f8d7da;
              --result-error-text: #721c24;
              --border-radius: 12px;
              --border-radius-sm: 8px;
            }
            body.dark-mode {
              --bg-gradient: linear-gradient(135deg, #232526 0%, #414345 100%);
              --bg-primary: #2c3e50;
              --text-primary: #ecf0f1;
              --border-color: #465b71;
              --result-error-bg: #5a2c2c;
              --result-error-text: #ffffff;
            }
            body { 
              font-family: 'Inter', sans-serif; 
              background: var(--bg-gradient);
              background-attachment: fixed;
              color: var(--text-primary);
              line-height: 1.6; margin: 0; padding: 0; min-height: 100vh; 
              display: flex; flex-direction: column; align-items: center;
            }
            .container { 
              max-width: 800px; width: 100%; padding: 20px; box-sizing: border-box;
            }
            .header { text-align: center; margin-bottom: 30px; }
            .main-title { font-size: 2.2rem; font-weight: 700; color: #fff; }
            .result-card { padding: 18px; border-radius: var(--border-radius-sm); margin-bottom: 12px; }
            .result-error { background-color: var(--result-error-bg); border-left: 4px solid var(--error-color); color: var(--result-error-text); }
          </style>
        </head>
        <body>
          <div class="container">
            <header class="header">
              <h1 class="main-title">Error</h1>
            </header>
            <div id="result">
              <div class="result-card result-error">
                <h3>❌ Error</h3>
                <p>${message}</p>
              </div>
            </div>
          </div>
        </body>
        </html>
      `;
    }
