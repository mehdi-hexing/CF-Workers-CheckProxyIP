import { connect } from "cloudflare:sockets";

let temporaryTOKEN, permanentTOKEN;

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

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const userAgent = request.headers.get('User-Agent') || 'null';
    const path = url.pathname;
    const hostname = url.hostname;

    const timestampForToken = Math.ceil(new Date().getTime() / (1000 * 60 * 31));
    temporaryTOKEN = await doubleHash(hostname + timestampForToken + userAgent);
    permanentTOKEN = env.TOKEN || temporaryTOKEN;
    
    // API Route Handling
    if (path.toLowerCase().startsWith('/api/')) {
      const isTokenValid = () => {
        if (!env.TOKEN) return true; // No token set, public access
        const providedToken = url.searchParams.get('token');
        return providedToken === permanentTOKEN || providedToken === temporaryTOKEN;
      };

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
    
    // UI Handling
    const faviconURL = env.ICO || 'https://cf-assets.www.cloudflare.com/dzlvafdwdttg/19kSkLSfWtDcspvQI5pit4/c5630cf25d589a0de91978ca29486259/performance-acceleration-bolt.svg';

    if (path.toLowerCase() === '/favicon.ico') {
        return Response.redirect(faviconURL, 302);
    }
    
    return new Response(generateMainHTML(temporaryTOKEN, faviconURL), {
      headers: { "content-type": "text/html;charset=UTF-8" }
    });
  }
};

function generateMainHTML(token, faviconURL) {
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
      --primary-color: #3498db; --primary-dark: #2980b9; --success-color: #2ecc71;
      --error-color: #e74c3c; --bg-primary: #ffffff; --bg-secondary: #f8f9fa;
      --text-primary: #2c3e50; --text-light: #adb5bd; --border-color: #dee2e6;
      --border-radius: 12px; --border-radius-sm: 8px;
    }
    body { font-family: 'Inter', sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: var(--text-primary); line-height: 1.6; margin:0; padding:20px; min-height: 100vh; display: flex; flex-direction: column; align-items: center; box-sizing: border-box;}
    .container { max-width: 800px; width: 100%; }
    .card { background: var(--bg-primary); border-radius: var(--border-radius); padding: 25px; box-shadow: 0 8px 20px rgba(0,0,0,0.1); margin-bottom: 25px; }
    .form-section { display: flex; flex-direction: column; align-items: center; }
    .form-label { display: block; font-weight: 500; margin-bottom: 8px; color: var(--text-primary); width: 100%; max-width: 400px; text-align: left;}
    .input-wrapper { width: 100%; max-width: 400px; margin-bottom: 15px; }
    .form-input { width: 100%; padding: 12px; border: 1px solid var(--border-color); border-radius: var(--border-radius-sm); font-size: 0.95rem; box-sizing: border-box; }
    textarea.form-input { min-height: 60px; resize: vertical; }
    .btn-primary { background: linear-gradient(135deg, var(--primary-color), var(--primary-dark)); color: white; padding: 12px 25px; border: none; border-radius: var(--border-radius-sm); font-size: 1rem; font-weight: 500; cursor: pointer; width: 100%; max-width: 400px; box-sizing: border-box; }
    .btn-primary:disabled { background: #bdc3c7; cursor: not-allowed; }
    .loading-spinner { width: 16px; height: 16px; border: 2px solid rgba(255,255,255,0.3); border-top-color: white; border-radius: 50%; animation: spin 1s linear infinite; display: none; margin-left: 8px; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .result-section { margin-top: 25px; }
    .result-card { padding: 18px; border-radius: var(--border-radius-sm); margin-bottom: 12px; }
    .result-success { background-color: #d4edda; border-left: 4px solid var(--success-color); color: #155724; }
    .result-error { background-color: #f8d7da; border-left: 4px solid var(--error-color); color: #721c24; }
    .copy-btn { background: var(--bg-secondary); border: 1px solid var(--border-color); padding: 4px 8px; border-radius: 4px; font-size: 0.85em; cursor: pointer; margin-left: 8px;}
    .toast { position: fixed; bottom: 20px; right: 20px; background: #333; color: white; padding: 12px 20px; border-radius:var(--border-radius-sm); z-index:1000; opacity:0; transition: opacity 0.3s; box-sizing: border-box;}
    .toast.show { opacity:1; }
    #successfulRangeIPsList { border: 1px solid var(--border-color); padding: 10px; border-radius: var(--border-radius-sm); }
    .ip-item { padding:8px 5px; border-bottom:1px solid #f0f0f0; display:flex; justify-content:space-between; align-items:center; }
    #successfulRangeIPsList .ip-item:last-child { border-bottom: none; }
  </style>
</head>
<body>
  <div class="container">
    <header style="text-align: center; margin-bottom: 30px;">
      <h1 style="font-size: 2.5rem; font-weight: 700; background: linear-gradient(135deg, #ffffff 0%, #f0f0f0 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">Proxy IP Checker</h1>
    </header>

    <div class="card">
      <div class="form-section">
        <label for="proxyip" class="form-label">Enter Single Proxy IP or Domain:</label>
        <div class="input-wrapper">
          <input type="text" id="proxyip" class="form-input" placeholder="e.g., 1.2.3.4:443 or example.com" autocomplete="off">
        </div>
        
        <label for="proxyipRangeRows" class="form-label">Enter IP Range(s) (one per line):</label>
        <div class="input-wrapper">
          <textarea id="proxyipRangeRows" class="form-input" rows="3" placeholder="e.g., 1.2.3.0/24\\n1.2.4.1-10" autocomplete="off"></textarea>
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
         <div id="rangeResultSummary" style="margin-bottom: 10px;"></div>
         <div id="successfulRangeIPsList" style="margin-bottom: 10px; max-height: 200px; overflow-y: auto;"></div>
         <button class="btn-secondary" id="copyRangeBtn" style="display:none; margin-top: 15px;">Copy Successful IPs</button>
      </div>
    </div>
  </div>

  <div id="toast" class="toast"></div>

  <script>
    let isChecking = false;
    const TEMP_TOKEN = "${token}";
    let currentSuccessfulRangeIPs = [];

    document.addEventListener('DOMContentLoaded', () => {
        const checkBtn = document.getElementById('checkBtn');
        checkBtn.addEventListener('click', checkInputs);
        
        document.getElementById('copyRangeBtn').addEventListener('click', () => {
            if (currentSuccessfulRangeIPs.length > 0) {
                const textToCopy = currentSuccessfulRangeIPs.map(item => item.ip).join('\\n');
                copyToClipboard(textToCopy, null, "All successful IPs copied!");
            } else {
                showToast("No successful IPs to copy.");
            }
        });

        document.body.addEventListener('click', event => {
            if (event.target.classList.contains('copy-btn')) {
                const text = event.target.getAttribute('data-copy');
                if (text) copyToClipboard(text, event.target, "Copied!");
            }
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

    function toggleCheckButton(checking) {
        isChecking = checking;
        const checkBtn = document.getElementById('checkBtn');
        checkBtn.disabled = checking;
        checkBtn.querySelector('.btn-text').style.display = checking ? 'none' : 'inline-block';
        checkBtn.querySelector('.loading-spinner').style.display = checking ? 'inline-block' : 'none';
    }

    async function fetchAPI(path, params) {
        params.append('token', TEMP_TOKEN);
        const response = await fetch(path + '?' + params.toString());
        if (!response.ok) {
            throw new Error('API Error: ' + await response.text());
        }
        return response.json();
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
                await checkAndDisplaySingleIP(singleIpToTest);
            }

            if (individualRangeQueries.length > 0) {
                rangeResultCard.style.display = 'block';
                successfulIPsListDiv.innerHTML = '<p style="text-align:center; color: var(--text-light);">Processing...</p>';

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
                if(currentSuccessfulRangeIPs.length > 0) copyRangeBtn.style.display = 'block';
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
            listDiv.innerHTML = '<p style="text-align:center; color: var(--text-light);">No successful IPs yet.</p>';
            return;
        }
        let html = '<div class="ip-grid">';
        currentSuccessfulRangeIPs.forEach(item => {
            html += '<div class="ip-item"><span>' + item.ip + '</span><span style="font-weight: 500;">' + item.countryCode + '</span></div>';
        });
        html += '</div>';
        listDiv.innerHTML = html;
    }

    async function checkAndDisplaySingleIP(proxyip) {
        const resultDiv = document.getElementById('result');
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
                        '<p><strong>📍 IP Address:</strong> <span class="copy-btn" data-copy="' + data.proxyIP + '">' + data.proxyIP + '</span></p>' +
                        ipInfoHTML +
                        '<p><strong>🔌 Port:</strong> ' + data.portRemote + '</p>' +
                        '<p><strong>🕒 Check Time:</strong> ' + new Date(data.timestamp).toLocaleString() + '</p>' +
                    '</div>';
            } else {
                 resultDiv.innerHTML =
                    '<div class="result-card result-error">' +
                        '<h3>❌ ProxyIP Invalid</h3>' +
                        '<p><strong>📍 IP Address:</strong> ' + proxyip + '</p>' +
                        '<p><strong>Error:</strong> ' + (data.error || 'Check failed.') + '</p>' +
                    '</div>';
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
            if (!isNaN(startOctet) && !isNaN(endOctet) && startOctet <= endOctet) {
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
