import { connect } from "cloudflare:sockets";

// --- Client-side JavaScript as a String Constant ---
// This script will be served dynamically by the worker at the /client.js path.
const CLIENT_SCRIPT = `
    let isChecking = false;
    let TEMP_TOKEN = '';
    let rangeSuccessfulIPs = [];
    let ipCheckResults = new Map();

    document.addEventListener('DOMContentLoaded', () => {
        fetch('/api/get-token').then(res => res.json()).then(data => { TEMP_TOKEN = data.token; });
        
        const checkBtn = document.getElementById('checkBtn');
        if(checkBtn) {
            checkBtn.addEventListener('click', checkInputs);
        }
        
        const copyRangeBtn = document.getElementById('copyRangeBtn');
        if (copyRangeBtn) {
            copyRangeBtn.addEventListener('click', () => {
                if (rangeSuccessfulIPs.length > 0) {
                    copyToClipboard(rangeSuccessfulIPs.join('\\n'), null, "All successful range IPs copied!");
                }
            });
        }
        
        document.body.addEventListener('click', event => {
            if (event.target.classList.contains('copy-btn')) {
                const text = event.target.getAttribute('data-copy');
                if (text) copyToClipboard(text, event.target, "Copied!");
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
        
        handleHashChange();
        window.addEventListener('hashchange', handleHashChange, false);
    });

    function handleHashChange() {
        if (!location.hash.startsWith('#/action/')) return;
        const parts = location.hash.split('/');
        const type = parts[2];
        const data = decodeURIComponent(parts.slice(3).join('/'));

        if (data && type === 'range') {
            document.getElementById('rangeInput').value = data.replace(/,/g, '\\n');
            setTimeout(() => document.getElementById('checkBtn').click(), 100);
        }
         if (data && type === 'proxyip') {
            document.getElementById('mainInput').value = data.replace(/,/g, '\\n');
            setTimeout(() => document.getElementById('checkBtn').click(), 100);
        }
        history.pushState("", document.title, window.location.pathname + window.location.search);
    }

    function showToast(message, duration = 3000) {
        const toast = document.getElementById('toast');
        toast.textContent = message;
        toast.classList.add('show');
        setTimeout(() => toast.classList.remove('show'), duration);
    }

    function copyToClipboard(text, element, successMessage = "Copied!") {
        navigator.clipboard.writeText(text).then(() => {
            const originalText = element ? element.textContent : '';
            if (element) {
                element.textContent = 'Copied ✓';
                setTimeout(() => { element.textContent = originalText; }, 2000);
            }
            showToast(successMessage);
        }).catch(err => showToast('Copy failed. Please copy manually.'));
    }
    
    function createCopyButton(text) {
        return \`<span class="copy-btn" data-copy="\${text}">\${text}</span>\`;
    }

    function toggleCheckButton(checking) {
        isChecking = checking;
        const checkBtn = document.getElementById('checkBtn');
        if (!checkBtn) return;
        checkBtn.disabled = checking;
        const btnText = checkBtn.querySelector('.btn-text');
        const spinner = checkBtn.querySelector('.loading-spinner');
        if(btnText) btnText.style.display = checking ? 'none' : 'inline-block';
        if(spinner) spinner.style.display = checking ? 'inline-block' : 'none';
    }

    async function fetchAPI(path, params) {
        if (!TEMP_TOKEN) {
             showToast("Session not ready. Retrying...");
             await new Promise(resolve => setTimeout(resolve, 500));
             if (!TEMP_TOKEN) {
                const res = await fetch('/api/get-token');
                const data = await res.json();
                TEMP_TOKEN = data.token;
             }
             if (!TEMP_TOKEN) throw new Error("Could not retrieve session token.");
        }
        params.append('token', TEMP_TOKEN);
        const response = await fetch(path + '?' + params.toString());
        if (!response.ok) {
           const data = await response.json().catch(() => ({}));
           throw new Error('API Error: ' + (data.message || response.statusText));
        }
        return response.json();
    }
    
    const isIPAddress = (input) => /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(input) || /^\\[?([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\\]?$/.test(input);
    const isDomain = (input) => /^(?!-)[A-Za-z0-9-]+([\\-\\.]{1}[a-z0-9]+)*\\.[A-Za-z]{2,6}$/.test(input);
    const isIPRange = (input) => /^(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\/(\\d{1,2})$/.test(input) || /^(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.)(\\d{1,3})-(\\d{1,3})$/.test(input);

    function parseIPRange(rangeInput) {
        const ips = [];
        const cidrMatch = rangeInput.match(/^(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\/(\\d{1,2})$/);
        const rangeMatch = rangeInput.match(/^(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.)(\\d{1,3})-(\\d{1,3})$/);

        if (cidrMatch) {
            const [, baseIp, mask] = cidrMatch;
            if (parseInt(mask) === 24) {
                const prefix = baseIp.substring(0, baseIp.lastIndexOf('.'));
                for (let i = 0; i <= 255; i++) {
                    ips.push(prefix + '.' + i);
                }
            } else {
                 showToast('Only /24 CIDR masks are supported. Skipping ' + rangeInput);
            }
        } else if (rangeMatch) {
            const [, prefix, startOctetStr, endOctetStr] = rangeMatch;
            const startOctet = parseInt(startOctetStr);
            const endOctet = parseInt(endOctetStr);
            if (!isNaN(startOctet) && !isNaN(endOctet) && startOctet <= endOctet && startOctet >= 0 && endOctet <= 255) {
                for (let i = startOctet; i <= endOctet; i++) {
                    ips.push(prefix + '.' + i);
                }
            }
        }
        return ips;
    }

    async function checkInputs() {
        if (isChecking) return;
        toggleCheckButton(true);

        const mainInputValue = document.getElementById('mainInput').value;
        const rangeInputValue = document.getElementById('rangeInput').value;
        const mainLines = mainInputValue.split(/[\\n,;\\s]+/).map(s => s.trim()).filter(Boolean);
        const rangeLines = rangeInputValue.split('\\n').map(s => s.trim()).filter(Boolean);

        if (mainLines.length === 0 && rangeLines.length === 0) {
            showToast('Please enter something to check.');
            toggleCheckButton(false);
            return;
        }

        document.getElementById('result').innerHTML = '';
        document.getElementById('rangeResultCard').style.display = 'none';
        
        const mainPromise = processMainInput(mainLines);
        const rangePromise = processRangeInput(rangeLines);
        
        try {
            await Promise.all([mainPromise, rangePromise]);
        } catch (e) {
            showToast('An error occurred during processing.');
            console.error(e);
        } finally {
            toggleCheckButton(false);
        }
    }

    async function processMainInput(lines) {
        if (lines.length === 0) return;
        const resultDiv = document.getElementById('result');
        const checkPromises = lines.map(async (line) => {
            if (isDomain(line.split(':')[0])) {
                await checkAndDisplayDomain(line, resultDiv);
            } else if (isIPAddress(line.split(':')[0].replace(/\\[|\\]/g, ''))) {
                await checkAndDisplaySingleIP(line, resultDiv);
            } else {
                showToast('Unrecognized format in main box: ' + line);
            }
        });
        await Promise.all(checkPromises);
    }
    
    async function checkAndDisplaySingleIP(proxyip, parentElement) {
        const resultCard = document.createElement('div');
        resultCard.classList.add('result-card');
        resultCard.innerHTML = '<p style="text-align:center; color: var(--text-light);">Checking ' + proxyip + '...</p>';
        parentElement.appendChild(resultCard);
        
        try {
            const data = await fetchAPI('/api/check', new URLSearchParams({ proxyip }));
            if (data.success) {
                const ipInfo = await fetchAPI('/api/ip-info', new URLSearchParams({ ip: data.proxyIP }));
                resultCard.classList.add('result-success');
                resultCard.innerHTML = \`<h3>✅ Valid Proxy IP</h3>
                    <p><strong>📍 IP Address:</strong> \${createCopyButton(data.proxyIP)}</p>
                    <p><strong>🌍 Country:</strong> \${ipInfo.country || 'N/A'}</p>
                    <p><strong>🌐 AS:</strong> \${ipInfo.as || 'N/A'}</p>
                    <p><strong>🔌 Port:</strong> \${data.portRemote}</p>\`;
            } else {
                resultCard.classList.add('result-error');
                resultCard.innerHTML = \`<h3>❌ Invalid Proxy IP</h3>
                    <p><strong>📍 IP Address:</strong> \${createCopyButton(proxyip)}</p>
                    <p><strong>Error:</strong> \${data.error || 'Check failed.'}</p>\`;
            }
        } catch (error) {
            resultCard.classList.add('result-error');
            resultCard.innerHTML = '<h3>❌ Error</h3><p>' + error.message + '</p>';
        }
    }

    async function checkAndDisplayDomain(domain, parentElement) {
        const resultCard = document.createElement('div');
        resultCard.classList.add('result-card', 'result-warning');
        resultCard.innerHTML = '<p style="text-align:center; color: var(--text-light);">Resolving ' + domain + '...</p>';
        parentElement.appendChild(resultCard);

        try {
            const resolveData = await fetchAPI('/api/resolve', new URLSearchParams({ domain }));
            const ips = resolveData.ips;

            resultCard.innerHTML = \`<h3>🔍 Results for \${createCopyButton(domain)} (\${ips.length} IPs found)</h3>
                                    <div class="domain-ip-list"></div>\`;
            const ipListDiv = resultCard.querySelector('.domain-ip-list');
            ipCheckResults.clear();

            let successCount = 0;
            const checkPromises = ips.map(async (ip, index) => {
                const ipItem = document.createElement('div');
                ipItem.className = 'ip-item';
                ipItem.innerHTML = \`<div>\${createCopyButton(ip)}</div><span id="domain-ip-status-\${index}">🔄</span>\`;
                ipListDiv.appendChild(ipItem);
                
                try {
                    const data = await fetchAPI('/api/check', new URLSearchParams({ proxyip: ip }));
                    const statusSpan = document.getElementById('domain-ip-status-' + index);
                    if (data.success) {
                        if(statusSpan) statusSpan.textContent = '✅';
                        successCount++;
                    } else {
                        if(statusSpan) statusSpan.textContent = '❌';
                    }
                } catch(e) {
                    const statusSpan = document.getElementById('domain-ip-status-' + index);
                    if(statusSpan) statusSpan.textContent = '⚠️';
                }
            });

            await Promise.all(checkPromises);

            resultCard.classList.remove('result-warning');
            if (successCount === 0) {
                 resultCard.classList.add('result-error');
            } else if (successCount === ips.length) {
                 resultCard.classList.add('result-success');
            }
        } catch (error) {
            resultCard.className = 'result-card result-error';
            resultCard.innerHTML = '<h3>❌ Error resolving ' + domain + '</h3><p>' + error.message + '</p>';
        }
    }

    async function processRangeInput(lines) {
        if (lines.length === 0) return;

        const rangeResultCard = document.getElementById('rangeResultCard');
        const summaryDiv = document.getElementById('rangeResultSummary');
        const listDiv = document.getElementById('successfulRangeIPsList');
        const copyBtn = document.getElementById('copyRangeBtn');

        rangeResultCard.style.display = 'block';
        listDiv.innerHTML = '';
        summaryDiv.innerHTML = 'Total Tested: 0 | Total Successful: 0';
        copyBtn.style.display = 'none';
        rangeSuccessfulIPs = [];

        let totalChecked = 0;
        let allIPsToTest = [];
        lines.forEach(line => {
            if (isIPRange(line)) {
                allIPsToTest.push(...parseIPRange(line));
            } else {
                showToast('Invalid range format: ' + line);
            }
        });
        allIPsToTest = [...new Set(allIPsToTest)];
        if (allIPsToTest.length === 0) {
            rangeResultCard.style.display = 'none';
            return;
        }

        const batchSize = 10;
        for (let i = 0; i < allIPsToTest.length; i += batchSize) {
            const batch = allIPsToTest.slice(i, i + batchSize);
            const checkPromises = batch.map(async (ip) => {
                try {
                    const data = await fetchAPI('/api/check', new URLSearchParams({ proxyip: ip }));
                    if (data.success) {
                        rangeSuccessfulIPs.push(ip);
                    }
                } catch (e) { console.error('Failed to check range IP ' + ip + ':', e); }
                finally { totalChecked++; }
            });
            await Promise.all(checkPromises);
            summaryDiv.innerHTML = 'Total Tested: ' + totalChecked + ' / ' + allIPsToTest.length + ' | Total Successful: ' + rangeSuccessfulIPs.length;
            updateSuccessfulRangeIPsDisplay();
        }

        if (rangeSuccessfulIPs.length > 0) {
            copyBtn.style.display = 'inline-block';
        }
    }

    function updateSuccessfulRangeIPsDisplay() {
        const listDiv = document.getElementById('successfulRangeIPsList');
        if (rangeSuccessfulIPs.length === 0) {
            listDiv.innerHTML = '<p style="text-align:center; color: var(--text-light);">No successful IPs found in range(s).</p>';
            return;
        }
        listDiv.innerHTML = rangeSuccessfulIPs.map(ip => \`<div class="ip-item"><span>\${ip}</span></div>\`).join('');
    }
`;

// --- Main Fetch Handler ---
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    
    // Serve the client-side JavaScript file
    if (path === '/client.js') {
        return new Response(CLIENT_SCRIPT, { headers: { "Content-Type": "application/javascript;charset=UTF-8" } });
    }

    // --- Server-Side Path Handlers ---
    if (path.toLowerCase().startsWith('/iprange/')) {
        const range_string = path.substring(path.indexOf('/', 1) + 1);
        const redirectUrl = new URL(request.url);
        redirectUrl.pathname = '/';
        redirectUrl.hash = '#/action/range/' + encodeURIComponent(range_string);
        return Response.redirect(redirectUrl.toString(), 302);
    }
    
    if (path.toLowerCase().startsWith('/proxyip/')) {
        const ips_string = path.substring(path.indexOf('/', 1) + 1);
        const redirectUrl = new URL(request.url);
        redirectUrl.pathname = '/';
        redirectUrl.hash = '#/action/proxyip/' + encodeURIComponent(ips_string);
        return Response.redirect(redirectUrl.toString(), 302);
    }
    
    if (path.toLowerCase().startsWith('/file/')) {
        try {
            const targetUrl = request.url.substring(request.url.indexOf('/file/') + 6);
            if (!targetUrl || !targetUrl.startsWith('http')) {
                 return new Response('Invalid URL provided.', { status: 400 });
            }
            if (!targetUrl.toLowerCase().endsWith('.txt') && !targetUrl.toLowerCase().endsWith('.csv')) {
                return new Response('Invalid file type. Only .txt and .csv are supported.', { status: 400 });
            }
        
            const response = await fetch(targetUrl, { headers: {'User-Agent': 'ProxyCheckerWorker/1.0'} });
            if (!response.ok) {
                throw new Error('Failed to fetch the URL: ' + response.statusText);
            }
            const text = await response.text();
            const ipRegex = /(\[?([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\]?)|((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))/g;
            const allIPs = [...new Set(text.match(ipRegex) || [])];

            const checkPromises = allIPs.map(ip => checkProxyIP(ip));
            const checkResults = await Promise.allSettled(checkPromises);

            const successfulChecks = checkResults
                .filter(result => result.status === 'fulfilled' && result.value.success)
                .map(result => result.value);
            
            const successfulResultsWithInfo = await Promise.all(successfulChecks.map(async (check) => {
                const info = await getIpInfo(check.proxyIP);
                return { check, info };
            }));
            
            const title = 'Results for File: <a href="' + targetUrl + '" target="_blank" rel="noopener noreferrer">' + targetUrl + '</a>';
            const html = generateSimpleResultHTML(title, successfulResultsWithInfo, true);
            return new Response(html, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });

        } catch (error) {
            return new Response('An error occurred: ' + error.message, { status: 500 });
        }
    }
    
    // --- API Routes ---
    if (path.toLowerCase().startsWith('/api/')) {
      const userAgent = request.headers.get('User-Agent') || 'null';
      const hostname = url.hostname;
      const timestampForToken = Math.ceil(new Date().getTime() / (1000 * 60 * 31));
      temporaryTOKEN = await doubleHash(hostname + timestampForToken + userAgent);
      permanentTOKEN = (env && env.TOKEN) ? env.TOKEN : temporaryTOKEN;

      const isTokenValid = () => {
          if (!env || !env.TOKEN) return true;
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
          const ipWithPort = proxyIPInput.includes(':') || proxyIPInput.includes(']:') ? proxyIPInput : proxyIPInput + ':443';
          const result = await checkProxyIP(ipWithPort);
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
          const response = await fetch('http://ip-api.com/json/' + ip + '?fields=status,message,query,country,countryCode,as&lang=en');
          const data = await response.json();
          return new Response(JSON.stringify(data), { headers: { "Content-Type": "application/json" } });
      }
      
      return new Response('API route not found', { status: 404 });
    }
    
    // --- Main Page ---
    const faviconURL = (env && env.ICO) ? env.ICO : 'https://cf-assets.www.cloudflare.com/dzlvafdwdttg/19kSkLSfWtDcspvQI5pit4/c5630cf25d589a0de91978ca29486259/performance-acceleration-bolt.svg';

    if (path.toLowerCase() === '/favicon.ico') {
        return Response.redirect(faviconURL, 302);
    }
    
    return new Response(generateMainHTML(faviconURL), {
      headers: { "content-type": "text/html;charset=UTF-8" }
    });
  }
};


function generateMainHTML(faviconURL) {
  const year = new Date().getFullYear();
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
    .container { max-width: 800px; width: 100%; padding: 20px; box-sizing: border-box; }
    .header { text-align: center; margin-bottom: 30px; }
    .main-title { font-size: 2.2rem; font-weight: 700; color: #fff; text-shadow: 1px 1px 3px rgba(0,0,0,0.2); }
    .card { background: var(--bg-primary); border-radius: var(--border-radius); padding: 25px; box-shadow: 0 8px 20px rgba(0,0,0,0.1); margin-bottom: 25px; transition: background 0.3s ease; }
    .form-section { display: flex; flex-direction: column; align-items: center; }
    .form-label { display: block; font-weight: 500; margin-bottom: 8px; color: var(--text-primary); width: 100%; max-width: 500px; text-align: left;}
    .input-wrapper { width: 100%; max-width: 500px; margin-bottom: 15px; }
    .form-input { width: 100%; padding: 12px; border: 1px solid var(--border-color); border-radius: var(--border-radius-sm); font-size: 0.95rem; box-sizing: border-box; background-color: var(--bg-secondary); color: var(--text-primary); transition: border-color 0.3s ease, background-color 0.3s ease; }
    textarea.form-input { min-height: 100px; resize: vertical; }
    .btn-primary { background: linear-gradient(135deg, var(--primary-color), #2980b9); color: white; padding: 12px 25px; border: none; border-radius: var(--border-radius-sm); font-size: 1rem; font-weight: 500; cursor: pointer; width: 100%; max-width: 500px; box-sizing: border-box; }
    .btn-primary:disabled { background: #bdc3c7; cursor: not-allowed; }
    .btn-secondary { background-color: var(--bg-secondary); color: var(--text-primary); padding: 8px 15px; border: 1px solid var(--border-color); border-radius: var(--border-radius-sm); font-size: 0.9rem; cursor: pointer; }
    .loading-spinner { width: 16px; height: 16px; border: 2px solid rgba(255,255,255,0.3); border-top-color: white; border-radius: 50%; animation: spin 1s linear infinite; display: none; margin-left: 8px; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .result-section { margin-top: 25px; }
    .result-card { padding: 18px; border-radius: var(--border-radius-sm); margin-bottom: 12px; transition: background-color 0.3s, color 0.3s, border-color 0.3s; }
    .result-success { background-color: var(--result-success-bg); color: var(--result-success-text); }
    .result-error { background-color: var(--result-error-bg); color: var(--result-error-text); }
    .result-warning { background-color: var(--result-warning-bg); color: var(--result-warning-text); }
    .domain-ip-list { border: 1px solid var(--border-color); padding: 10px; border-radius: var(--border-radius-sm); max-height: 250px; overflow-y: auto; margin-top: 15px; }
    .copy-btn { background: var(--bg-secondary); border: 1px solid var(--border-color); padding: 4px 8px; border-radius: 4px; font-size: 0.85em; cursor: pointer; margin-left: 8px;}
    .toast { position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%); background: #333; color: white; padding: 12px 20px; border-radius:var(--border-radius-sm); z-index:1001; opacity:0; transition: opacity 0.3s, transform 0.3s; }
    .toast.show { opacity:1; }
    #successfulRangeIPsList { border: 1px solid var(--border-color); padding: 10px; border-radius: var(--border-radius-sm); max-height: 250px; overflow-y: auto;}
    .ip-item { padding:8px 5px; border-bottom:1px solid var(--border-color); display:flex; justify-content:space-between; align-items:center; }
    #successfulRangeIPsList .ip-item:last-child { border-bottom: none; }
    .api-docs { margin-top: 30px; padding: 25px; background: var(--bg-primary); border-radius: var(--border-radius); transition: background 0.3s ease; }
    .api-docs p { background-color: var(--bg-secondary); border: 1px solid var(--border-color); padding: 10px; border-radius: 4px; margin-bottom: 10px; word-break: break-all; transition: background 0.3s ease, border-color 0.3s ease;}
    .api-docs p code { background: none; padding: 0;}
    .footer { text-align: center; padding: 20px; margin-top: 30px; color: rgba(255,255,255,0.8); font-size: 0.85em; border-top: 1px solid rgba(255,255,255,0.1); }
    .github-corner svg { fill: var(--primary-color); color: #fff; position: fixed; top: 0; border: 0; right: 0; z-index: 1000;}
    body.dark-mode .github-corner svg { fill: #fff; color: #151513; }
    .octo-arm{transform-origin:130px 106px}
    .github-corner:hover .octo-arm{animation:octocat-wave 560ms ease-in-out}
    @keyframes octocat-wave{0%,100%{transform:rotate(0)}20%,60%{transform:rotate(-25deg)}40%,80%{transform:rotate(10deg)}}
    #theme-toggle { position: fixed; bottom: 25px; right: 25px; z-index: 1002; background: var(--bg-primary); border: 1px solid var(--border-color); width: 48px; height: 48px; border-radius: 50%; cursor: pointer; display: flex; align-items: center; justify-content: center; padding: 0; box-shadow: 0 4px 8px rgba(0,0,0,0.15); transition: background-color 0.3s, border-color 0.3s; }
    #theme-toggle svg { width: 24px; height: 24px; stroke: var(--text-primary); transition: all 0.3s ease; }
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
        <label for="mainInput" class="form-label">Enter IPs or Domains (one per line):</label>
        <div class="input-wrapper">
          <textarea id="mainInput" class="form-input" rows="4" placeholder="e.g.,&#10;1.1.1.1&#10;example.com" autocomplete="off"></textarea>
        </div>
        <label for="rangeInput" class="form-label">Enter IP Range(s) (one per line):</label>
        <div class="input-wrapper">
          <textarea id="rangeInput" class="form-input" rows="3" placeholder="e.g.,&#10;1.1.1.0/24&#10;2.2.2.0-255" autocomplete="off"></textarea>
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
       <hr style="border:0; border-top: 1px solid var(--border-color); margin: 20px 0;"/>
       <h4 style="margin-bottom:15px; text-align:center;">Direct URL Usage</h4>
       <p><code>/proxyip/IP1,IP2,...</code> - Server-side check for multiple IPs.</p>
       <p><code>/iprange/1.1.1.0/24</code> - Pre-fills the range input box on the main page.</p>
       <p><code>/file/https://path.to/your/file.txt</code> - Server-side check for IPs in a remote file.</p>
    </div>
    <footer class="footer">
      <p>© ${year} Proxy IP Checker - By <strong>mehdi-hexing</strong></p>
    </footer>
  </div>
  <div id="toast" class="toast"></div>
  <button id="theme-toggle" aria-label="Toggle Theme">
    <svg class="sun-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
    <svg class="moon-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="0.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
  </button>
  <script>${clientScript}</script>
</body>
</html>`;
        }
