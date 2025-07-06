import { connect } from 'cloudflare:sockets';

// --- Server-Side Helper Functions ---

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
    if (!ipv4Response.ok && !ipv6Response.ok) throw new Error('DNS query failed for both IPv4 and IPv6.');
    
    const ipv4Data = ipv4Response.ok ? await ipv4Response.json() : {};
    const ipv6Data = ipv6Response.ok ? await ipv6Response.json() : {};

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

async function checkProxyIP(proxyIP) {
  let portRemote = 443;
  let hostToCheck = proxyIP;

  if (proxyIP.includes('.tp')) {
    const portMatch = proxyIP.match(/\.tp(\d+)\./);
    if (portMatch) portRemote = parseInt(portMatch[1], 10);
    hostToCheck = proxyIP.split('.tp')[0];
  } else if (proxyIP.includes('[') && proxyIP.includes(']:')) {
    portRemote = parseInt(proxyIP.split(']:')[1], 10);
    hostToCheck = proxyIP.split(']:')[0] + ']';
  } else if (proxyIP.includes(':') && !proxyIP.startsWith('[')) {
    const parts = proxyIP.split(':');
    if (parts.length === 2 && parts[0].includes('.')) {
      hostToCheck = parts[0];
      portRemote = parseInt(parts[1], 10) || 443;
    }
  }

  let tcpSocket;
  try {
    tcpSocket = connect({ hostname: hostToCheck.replace(/\[|\]/g, ''), port: portRemote });
    const writer = tcpSocket.writable.getWriter();
    const httpRequest = 'GET /cdn-cgi/trace HTTP/1.1\r\nHost: speed.cloudflare.com\r\nUser-Agent: checkip/mehdi/\r\nConnection: close\r\n\r\n';
    await writer.write(new TextEncoder().encode(httpRequest));

    const reader = tcpSocket.readable.getReader();
    let responseData = new Uint8Array(0);
    const timeout = new Promise((_, reject) => setTimeout(() => reject(new Error("Timeout")), 5000));

    while (responseData.length < 4096) {
      const { value, done } = await Promise.race([reader.read(), timeout]);
      if (done) break;
      if (value) {
        const newData = new Uint8Array(responseData.length + value.length);
        newData.set(responseData);
        newData.set(value, responseData.length);
        responseData = newData;
        if (new TextDecoder().decode(responseData).includes('\r\n\r\n')) break;
      }
    }

    const responseText = new TextDecoder().decode(responseData);
    const statusMatch = responseText.match(/^HTTP\/\d\.\d\s+(\d+)/i);
    const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : null;
    const isSuccessful = statusCode !== null && responseText.includes('cloudflare') && (responseText.includes('plain HTTP request') || responseText.includes('400 Bad Request')) && responseData.length > 100;

    return { success: isSuccessful, proxyIP: hostToCheck, portRemote, statusCode, responseSize: responseData.length, timestamp: new Date().toISOString() };
  } catch (error) {
    return { success: false, proxyIP: hostToCheck, portRemote, timestamp: new Date().toISOString(), error: error.message };
  } finally {
    if (tcpSocket) {
      try { await tcpSocket.close(); } catch (e) {}
    }
  }
}

async function getIpInfo(ip) {
    try {
        const response = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,as&lang=en`);
        if (!response.ok) return { country: 'N/A', countryCode: 'N/A', as: 'N/A' };
        const data = await response.json();
        if (data.status === 'fail') return { country: 'N/A', countryCode: 'N/A', as: 'N/A' };
        return data;
    } catch (e) {
        return { country: 'N/A', countryCode: 'N/A', as: 'N/A' };
    }
}

function parseIPRangeServer(rangeInput) {
    const ips = [];
    const cidrMatch = rangeInput.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/24$/);
    const rangeMatch = rangeInput.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$/);

    if (cidrMatch) {
        const prefix = cidrMatch[1].substring(0, cidrMatch[1].lastIndexOf('.'));
        for (let i = 0; i <= 255; i++) ips.push(`${prefix}.${i}`);
    } else if (rangeMatch) {
        const prefix = rangeMatch[1];
        const start = parseInt(rangeMatch[2], 10);
        const end = parseInt(rangeMatch[3], 10);
        if (!isNaN(start) && !isNaN(end) && start <= end && start >=0 && end <= 255) {
            for (let i = start; i <= end; i++) ips.push(`${prefix}${i}`);
        }
    }
    return ips;
}

const ipv4Regex = /(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/g;
const ipv6Regex = /(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}|\[(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\]/gi;

// --- HTML Page Generators ---

function generateResultsPageHTML({ title, subtitleLabel, subtitleContent, results, pageType, successfulIPsText }) {
    const resultsRows = results.map(item => {
        const detailsParts = [];
        if (item.info && item.info.country) detailsParts.push(item.info.country);
        if (item.info && item.info.as) detailsParts.push(item.info.as);
        const detailsText = detailsParts.length > 0 ? `(${detailsParts.join(' - ')})` : '';

        return `
        <div class="ip-item">
            <span class="ip-tag" onclick="copyToClipboard('${item.check.proxyIP}', this)">${item.check.proxyIP}</span>
            <span class="ip-details">${detailsText}</span>
        </div>`;
    }).join('');

    let subtitleHTML = '';
    if (pageType === 'iprange') {
        const ranges = subtitleContent.split(',').map(r => `<span class="range-tag" data-copy="${r.trim()}">${r.trim()}</span>`).join('<br>');
        subtitleHTML = `<div class="ranges-list"><strong>${subtitleLabel}</strong><br>${ranges}</div>`;
    } else if (pageType === 'file') {
        subtitleHTML = `<div class="ranges-list"><strong>${subtitleLabel}</strong> <a href="${subtitleContent}" class="range-tag" target="_blank" rel="noopener noreferrer">${subtitleContent}</a></div>`;
    }

    let actionButtonsHTML = '';
    if (results.length > 0) {
        let downloadButton = '';
        if (pageType === 'file') {
            const dataUrl = `data:text/plain;charset=utf-8;base64,${btoa(unescape(encodeURIComponent(successfulIPsText)))}`;
            downloadButton = `<a href="${dataUrl}" download="successful_ips.txt" class="btn btn-secondary">📥 Download Results</a>`;
        }
        actionButtonsHTML = `
        <div class="action-buttons">
            ${downloadButton}
            <button class="btn btn-primary" onclick="copyToClipboard('${successfulIPsText.replace(/'/g, "\\'")}')">📋 Copy All</button>
        </div>`;
    }
    
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${title}</title>
    <style>
        :root{--bg-color:#f4f7f9;--card-bg-color:#fff;--text-color:#2c3e50;--border-color:#e1e8ed;--hover-bg-color:#f8f9fa;--primary-color:#3498db;--primary-text-color:#fff;--subtle-text-color:#7f8c8d;--tag-bg-color:#e8eaed;--secondary-color:#95a5a6}body.dark-mode{--bg-color:#2c3e50;--card-bg-color:#34495e;--text-color:#ecf0f1;--border-color:#465b71;--hover-bg-color:#4a6075;--subtle-text-color:#bdc3c7;--tag-bg-color:#2b2b2b;--secondary-color:#7f8c8d}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background-color:var(--bg-color);color:var(--text-color);margin:0;padding:20px;transition:background-color .3s,color .3s}.container{max-width:700px;margin:0 auto}.header{display:flex;justify-content:space-between;align-items:flex-start;padding-bottom:15px;margin-bottom:25px;border-bottom:1px solid var(--border-color)}.title-section h1{font-size:1.8em;margin:0 0 10px}.ranges-list{font-size:.9em;color:var(--subtle-text-color)}.range-tag{display:inline-block;background-color:var(--tag-bg-color);padding:4px 8px;border-radius:6px;font-family:'Courier New',Courier,monospace;cursor:pointer;margin:2px 0;transition:background-color .2s;text-decoration:none;color:var(--text-color)}.range-tag:hover{background-color:var(--primary-color);color:var(--primary-text-color)}.button-group{display:flex;gap:10px;flex-shrink:0;margin-left:20px}.btn{padding:8px 16px;border:none;border-radius:8px;cursor:pointer;font-weight:500;font-size:.9em;transition:transform .2s;text-decoration:none;display:inline-flex;align-items:center}.btn-primary{background-color:var(--primary-color);color:var(--primary-text-color)}.btn-secondary{background-color:var(--secondary-color);color:var(--primary-text-color)}.btn:hover{transform:translateY(-2px)}.theme-toggle{background-color:var(--card-bg-color);border:1px solid var(--border-color);width:38px;height:38px;justify-content:center;padding:0;border-radius:50%}.results-card{background-color:var(--card-bg-color);border:1px solid var(--border-color);border-radius:10px;padding:10px}.ip-item{display:flex;justify-content:space-between;align-items:center;padding:12px 15px;border-radius:6px;}.ip-item:not(:last-child){border-bottom:1px solid var(--border-color)}.ip-tag{background-color:var(--tag-bg-color);padding:3px 7px;border-radius:5px;font-family:'Courier New',Courier,monospace;cursor:pointer;transition:background-color .2s}.ip-tag:hover{background-color:var(--primary-color);color:var(--primary-text-color)}.ip-details{font-size:.9em;color:var(--subtle-text-color);padding-left:15px}.action-buttons{margin-top:20px;display:flex;justify-content:center;gap:10px}.footer{text-align:center;padding:20px;margin-top:30px;color:var(--subtle-text-color);font-size:.9em;border-top:1px solid var(--border-color)}.toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%);background:#333;color:#fff;padding:12px 20px;border-radius:8px;z-index:1001;opacity:0;transition:opacity .3s,transform .3s;pointer-events:none}.toast.show{opacity:1}
        .theme-toggle svg { width: 18px; height: 18px; stroke: var(--text-color); transition: all 0.3s ease; }
        body:not(.dark-mode) .theme-toggle .sun-icon { display: block; fill: none;}
        body:not(.dark-mode) .theme-toggle .moon-icon { display: none; }
        body.dark-mode .theme-toggle .sun-icon { display: none; }
        body.dark-mode .theme-toggle .moon-icon { display: block; fill: var(--text-color); stroke: var(--text-color); }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="title-section">
                <h1>${title}</h1>
                ${subtitleHTML}
            </div>
            <div class="button-group">
                <button class="btn theme-toggle" onclick="toggleTheme()">
                    <svg class="sun-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
                    <svg class="moon-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="0.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
                </button>
            </div>
        </header>
        <main class="results-card">
            ${results.length > 0 ? resultsRows : '<p style="text-align:center; padding: 20px;">No successful proxies found.</p>'}
        </main>
        ${actionButtonsHTML}
        <footer class="footer">
            <p>© ${new Date().getFullYear()} Proxy IP Checker - By <strong>mehdi-hexing</strong></p>
        </footer>
    </div>
    <div id="toast" class="toast"></div>
    <script>
        function showToast(message) { const toast = document.getElementById('toast'); toast.textContent = message; toast.classList.add('show'); setTimeout(() => toast.classList.remove('show'), 3000); }
        function copyToClipboard(text, element) { navigator.clipboard.writeText(text).then(() => { showToast('Copied!'); }).catch(err => { showToast('Copy failed!'); }); }
        function toggleTheme() {
            const body = document.body; body.classList.toggle('dark-mode');
            localStorage.setItem('theme', body.classList.contains('dark-mode') ? 'dark' : 'light');
        }
        if (localStorage.getItem('theme') === 'dark' || (!('theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
            document.body.classList.add('dark-mode');
        }
    </script>
</body>
</html>`;
}

// --- Client-Side Script ---
const CLIENT_SCRIPT = `
    let isChecking = false;
    let TEMP_TOKEN = '';
    let domainCheckCounter = 0;
    let currentSuccessfulRangeIPs = [];

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
            const target = event.target;
            if (target.classList.contains('copy-btn') || target.classList.contains('ip-tag') || target.classList.contains('range-tag')) {
                const text = target.getAttribute('data-copy') || target.textContent;
                if (text) copyToClipboard(text, target);
            }
        });

        const themeToggleBtn = document.getElementById('theme-toggle');
        const body = document.body;
        
        const applyTheme = (theme) => {
            if (theme === 'dark') body.classList.add('dark-mode');
            else body.classList.remove('dark-mode');
        };

        const savedTheme = localStorage.getItem('theme');
        if (savedTheme) applyTheme(savedTheme);
        else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) applyTheme('dark');

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
            if (element) {
                element.textContent = 'Copied ✓';
                setTimeout(() => { if(element) element.textContent = originalText; }, 2000);
            } else {
                 showToast(successMessage);
            }
        }).catch(err => showToast('Copy failed.'));
    }

    function toggleCheckButton(checking) {
        isChecking = checking;
        const checkBtn = document.getElementById('checkBtn');
        checkBtn.disabled = checking;
        const btnText = checkBtn.querySelector('.btn-text');
        const spinner = checkBtn.querySelector('.loading-spinner');
        if(btnText) btnText.style.display = checking ? 'none' : 'inline-block';
        if(spinner) spinner.style.display = checking ? 'inline-block' : 'none';
    }

    async function fetchAPI(path, params) {
        if (!TEMP_TOKEN) {
             await new Promise(resolve => setTimeout(resolve, 500));
             if (!TEMP_TOKEN) await fetch('/api/get-token').then(res => res.json()).then(data => { TEMP_TOKEN = data.token; });
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

    const isIPAddress = (input) => /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(input.split(':')[0].replace(/[\\[\\]]/g, ''));
    const isDomain = (input) => /^(?!-)[a-zA-Z0-9-]+([\\-\\.]{1}[a-zA-Z0-9]+)*\\.[a-zA-Z]{2,}$/.test(input.split(':')[0]);
    const isIPRange = (input) => /^(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\/24$/.test(input) || /^(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.)(\\d{1,3})-(\\d{1,3})$/.test(input);

    function parseIPRange(rangeInput) {
        const ips = [];
        const cidrMatch = rangeInput.match(/^(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\/24$/);
        const rangeMatch = rangeInput.match(/^(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.)(\\d{1,3})-(\\d{1,3})$/);

        if (cidrMatch) {
            const prefix = cidrMatch[1].substring(0, cidrMatch[1].lastIndexOf('.'));
            for (let i = 0; i <= 255; i++) ips.push(\`\${prefix}.\${i}\`);
        } else if (rangeMatch) {
            const prefix = rangeMatch[1];
            const start = parseInt(rangeMatch[2], 10);
            const end = parseInt(rangeMatch[3], 10);
            if (!isNaN(start) && !isNaN(end) && start <= end) {
                for (let i = start; i <= end; i++) ips.push(\`\${prefix}\${i}\`);
            }
        }
        return ips;
    }
    
    async function checkInputs() {
        if (isChecking) return;
        
        const mainInputEl = document.getElementById('proxyip');
        const rangeIpTextareaEl = document.getElementById('proxyipRangeRows');
        const mainInputs = mainInputEl.value.split(/[\\n,;\\s]+/).map(s => s.trim()).filter(Boolean);
        const rangeInputs = rangeIpTextareaEl.value.split('\\n').map(s => s.trim()).filter(Boolean);

        if (mainInputs.length === 0 && rangeInputs.length === 0) {
            showToast('Please enter something to check.');
            return;
        }
        
        toggleCheckButton(true);
        document.getElementById('result').innerHTML = '';
        document.getElementById('rangeResultCard').style.display = 'none';

        if (mainInputs.length > 0) {
            await processMainInputs(mainInputs);
        }
        if (rangeInputs.length > 0) {
            await processRangeInputs_simpleList(rangeInputs);
        }

        toggleCheckButton(false);
    }
    
    async function processMainInputs(inputs) {
        if (inputs.length === 1) {
            const singleInput = inputs[0];
            if (isDomain(singleInput)) {
                await checkAndDisplayDomain_graphical(singleInput);
            } else if (isIPAddress(singleInput)) {
                await checkAndDisplaySingleIP_graphical(singleInput);
            } else {
                document.getElementById('result').innerHTML = '<div class="result-card result-error"><h3>❌ Unrecognized Format</h3></div>';
            }
            return;
        }
        await processMultipleItems_unified(inputs);
    }

    async function checkAndDisplaySingleIP_graphical(proxyip) {
        const resultDiv = document.getElementById('result');
        const resultCard = document.createElement('div');
        resultCard.className = 'result-card';
        resultCard.innerHTML = '<p style="text-align:center;">Checking...</p>';
        resultDiv.appendChild(resultCard);

        try {
            const data = await fetchAPI('/api/check', new URLSearchParams({ proxyip }));
            if (data.success) {
                const ipInfo = await fetchAPI('/api/ip-info', new URLSearchParams({ ip: data.proxyIP }));
                resultCard.classList.add('result-success');
                resultCard.innerHTML = \`
                    <h3><span class="status-icon-prefix">✔</span> Valid Proxy IP</h3>
                    <p><strong>IP Address:</strong> <span class="copy-btn" data-copy="\${data.proxyIP}">\${data.proxyIP}</span></p>
                    <p><strong>Country:</strong> \${ipInfo.country || 'N/A'}</p>
                    <p><strong>AS:</strong> \${ipInfo.as || 'N/A'}</p>
                    <p><strong>Port:</strong> \${data.portRemote}</p>
                \`;
            } else {
                resultCard.classList.add('result-error');
                resultCard.innerHTML = \`
                    <h3><span class="status-icon-prefix">✖</span> Invalid Proxy IP</h3>
                    <p><strong>IP Address:</strong> <span class="copy-btn" data-copy="\${proxyip}">\${proxyip}</span></p>
                    <p><strong>Error:</strong> \${data.error || 'Check failed.'}</p>
                \`;
            }
        } catch (error) {
            resultCard.classList.add('result-error');
            resultCard.innerHTML = \`<h3>❌ Error</h3><p>\${error.message}</p>\`;
        }
    }
    
    async function checkAndDisplayDomain_graphical(domain) {
        const resultDiv = document.getElementById('result');
        const resultCard = document.createElement('div');
        resultCard.className = 'result-card result-warning';
        resultCard.innerHTML = '<h3><span class="status-icon-prefix">⟳</span> Resolving Domain...</h3>';
        resultDiv.appendChild(resultCard);

        try {
            const resolveData = await fetchAPI('/api/resolve', new URLSearchParams({ domain }));
            if (!resolveData.success || !resolveData.ips || resolveData.ips.length === 0) {
                throw new Error(resolveData.error || 'Could not resolve domain.');
            }
            const ips = resolveData.ips;
            resultCard.innerHTML = \`
                <h3><span class="status-icon-prefix">⟳</span> Checking \${ips.length} IPs for \${domain}</h3>
                <div class="domain-ip-list"></div>
            \`;
            const ipListDiv = resultCard.querySelector('.domain-ip-list');

            let successCount = 0;
            const checkPromises = ips.map(async (ip, index) => {
                const ipItem = document.createElement('div');
                ipItem.className = 'ip-item-multi';
                ipItem.innerHTML = \`
                    <span class="ip-tag" data-copy="\${ip}">\${ip}</span>
                    <span class="ip-details" id="status-\${index}">🔄</span>
                \`;
                ipListDiv.appendChild(ipItem);
                
                try {
                    const checkData = await fetchAPI('/api/check', new URLSearchParams({ proxyip: ip }));
                    const statusSpan = document.getElementById(\`status-\${index}\`);
                    if (checkData.success) {
                        successCount++;
                        const ipInfo = await fetchAPI('/api/ip-info', new URLSearchParams({ ip: ip }));
                        statusSpan.innerHTML = \`✅ (\${ipInfo.country || 'N/A'})\`;
                    } else {
                        statusSpan.textContent = '❌';
                    }
                } catch(e) {
                     document.getElementById(\`status-\${index}\`).textContent = '⚠️';
                }
            });

            await Promise.all(checkPromises);

            resultCard.classList.remove('result-warning');
            resultCard.classList.add(successCount > 0 ? 'result-success' : 'result-error');
            resultCard.querySelector('h3 .status-icon-prefix').textContent = successCount > 0 ? '✔' : '✖';
            resultCard.querySelector('h3').childNodes[1].nodeValue = \` \${successCount} of \${ips.length} IPs are valid\`;

        } catch (error) {
            resultCard.className = 'result-card result-error';
            resultCard.innerHTML = \`<h3>❌ Error</h3><p>\${error.message}</p>\`;
        }
    }
    
    async function processMultipleInputs(mainInputs, rangeInputs) {
        const resultDiv = document.getElementById('result');
        resultDiv.innerHTML = '<div class="result-card"><p style="text-align:center;">Processing all inputs...</p></div>';
        
        let allSuccessfulIPs = [];
        let finalHTML = '';

        const domains = mainInputs.filter(isDomain);
        const directIPs = mainInputs.filter(isIPAddress);
        
        if (domains.length > 0) {
            finalHTML += '<h2>Domain Results</h2>';
            domainCheckCounter = 0;
            domains.forEach(domain => {
                domainCheckCounter++;
                finalHTML += \`<div class="domain-card"><strong>Domain: <span class="copy-btn" data-copy="\${domain}">\${domain}</span></strong><div id="domain-list-\${domainCheckCounter}" class="domain-ip-list"><p style="text-align:center;color:var(--text-light)">Resolving...</p></div></div>\`;
            });
        }
        
        // This part is for rendering other IPs if they exist alongside domains.
        // It's kept separate from the dedicated range checker.
        if (directIPs.length > 0) {
            finalHTML += '<h2>Direct IP Results</h2><div class="domain-ip-list" id="direct-results-list"><p style="text-align:center;color:var(--text-light)">Checking...</p></div>';
        }

        resultDiv.innerHTML = \`<div class="result-card">\${finalHTML}</div>\`;

        // Asynchronously process domains
        let domainCounter = 0;
        for (const domain of domains) {
            domainCounter++;
            const domainListContainer = document.getElementById(\`domain-list-\${domainCounter}\`);
            try {
                const resolveData = await fetchAPI('/api/resolve', new URLSearchParams({ domain }));
                if (!resolveData.success || !resolveData.ips) throw new Error('Could not resolve');
                
                const checkPromises = resolveData.ips.map(async (ip) => {
                    const checkData = await fetchAPI('/api/check', new URLSearchParams({ proxyip: ip }));
                    if (checkData.success) {
                        const ipInfo = await fetchAPI('/api/ip-info', new URLSearchParams({ ip: checkData.proxyIP }));
                        return { ip: checkData.proxyIP, info: ipInfo };
                    }
                    return null;
                });
                
                const successfulResolvedIPs = (await Promise.all(checkPromises)).filter(Boolean);
                allSuccessfulIPs.push(...successfulResolvedIPs.map(item => item.ip));

                domainListContainer.innerHTML = successfulResolvedIPs.length > 0 ?
                    successfulResolvedIPs.map(item => \`<div class="ip-item-multi"><span class="ip-tag" data-copy="\${item.ip}">\${item.ip}</span><span class="ip-details">(\${item.info.country || 'N/A'} - \${item.info.as || 'N/A'})</span></div>\`).join('') :
                    '<p>No valid proxies found.</p>';

            } catch (e) {
                if(domainListContainer) domainListContainer.innerHTML = \`<p>Error resolving: \${e.message}</p>\`;
            }
        }
        
        if (directIPs.length > 0) {
            const directResultsContainer = document.getElementById('direct-results-list');
            const checkPromises = directIPs.map(async ip => {
                 const checkData = await fetchAPI('/api/check', new URLSearchParams({ proxyip: ip }));
                 if(checkData.success) {
                     const ipInfo = await fetchAPI('/api/ip-info', new URLSearchParams({ ip: checkData.proxyIP }));
                     return { ip: checkData.proxyIP, info: ipInfo };
                 }
                 return null;
            });
            const successfulDirectIPs = (await Promise.all(checkPromises)).filter(Boolean);
            allSuccessfulIPs.push(...successfulDirectIPs.map(item => item.ip));

            if (successfulDirectIPs.length > 0) {
                 directResultsContainer.innerHTML = successfulDirectIPs.map(item => {
                    const details = \`(\${item.info.country || 'N/A'} - \${item.info.as || 'N/A'})\`;
                    return \`<div class="ip-item-multi"><span class="ip-tag" data-copy="\${item.ip}">\${item.ip}</span><span class="ip-details">\${details}</span></div>\`;
                }).join('');
            } else {
                directResultsContainer.innerHTML = '<p>No valid proxies found.</p>';
            }
        }
        
        if (allSuccessfulIPs.length > 0) {
            const actionButtonHTML = \`<div class="action-buttons"><button class="btn btn-primary" onclick="copyToClipboard('\${[...new Set(allSuccessfulIPs)].join('\\n')}')">📋 Copy All Successful IPs</button></div>\`;
            resultDiv.querySelector('.result-card').insertAdjacentHTML('beforeend', actionButtonHTML);
        }
    }

    async function processRangeInputs_simpleList(rangeInputs) {
        const rangeResultCard = document.getElementById('rangeResultCard');
        const summaryDiv = document.getElementById('rangeResultSummary');
        const listDiv = document.getElementById('successfulRangeIPsList');
        const copyBtn = document.getElementById('copyRangeBtn');
        const rangeIcon = document.getElementById('rangeResultIcon');

        rangeResultCard.style.display = 'block';
        rangeResultCard.className = 'result-card result-section result-warning';
        if(rangeIcon) rangeIcon.textContent = '⟳';
        listDiv.innerHTML = '<p style="text-align:center;">Processing...</p>';
        summaryDiv.innerHTML = 'Total Tested: 0 | Total Successful: 0';
        copyBtn.style.display = 'none';
        currentSuccessfulRangeIPs = [];
        
        const allIPsToTest = [...new Set(rangeInputs.flatMap(parseIPRange))];
        if (allIPsToTest.length === 0) {
            rangeResultCard.className = 'result-card result-section result-error';
            if(rangeIcon) rangeIcon.textContent = '✖';
            summaryDiv.innerHTML = 'Invalid range format provided.';
            listDiv.innerHTML = '';
            return;
        }

        let successCount = 0;
        let checkedCount = 0;

        const batchSize = 20;
        for (let i = 0; i < allIPsToTest.length; i += batchSize) {
            const batch = allIPsToTest.slice(i, i + batchSize);
            const batchPromises = batch.map(ip => 
                fetchAPI('/api/check', new URLSearchParams({ proxyip: ip }))
                    .then(async (data) => {
                        checkedCount++;
                        if (data.success) {
                            successCount++;
                            const ipInfo = await fetchAPI('/api/ip-info', new URLSearchParams({ ip: data.proxyIP }));
                            currentSuccessfulRangeIPs.push({ ip: data.proxyIP, countryCode: ipInfo.countryCode || 'N/A' });
                        }
                    })
                    .catch(err => {
                        checkedCount++;
                        console.error("Error checking IP in range:", ip, err);
                    })
            );
            await Promise.all(batchPromises);
            summaryDiv.innerHTML = \`Tested: \${checkedCount}/\${allIPsToTest.length} | Successful: \${successCount}\`;
            updateSuccessfulRangeIPsDisplay();
        }
        
        rangeResultCard.classList.remove('result-warning');
        if(successCount > 0) rangeResultCard.classList.add('result-success');
        else rangeResultCard.classList.add('result-error');
        if(rangeIcon) rangeIcon.textContent = successCount > 0 ? '✔' : '✖';
        if (currentSuccessfulRangeIPs.length > 0) copyBtn.style.display = 'inline-block';
    }

    function updateSuccessfulRangeIPsDisplay() {
        const listDiv = document.getElementById('successfulRangeIPsList');
        if (currentSuccessfulRangeIPs.length === 0) {
            listDiv.innerHTML = '<p style="text-align:center; color: var(--text-light);">No successful IPs found in range(s).</p>';
            return;
        }
        listDiv.innerHTML = currentSuccessfulRangeIPs.map(item => 
            \`<div class="ip-item-multi">
                <span class="ip-tag" data-copy="\${item.ip}">\${item.ip}</span>
                <span class="ip-details">\${item.countryCode}</span>
            </div>\`
        ).join('');
    }
`;

// --- HTML Generation Functions ---
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
    :root{--bg-gradient:linear-gradient(135deg,#667eea 0%,#764ba2 100%);--bg-primary:#fff;--bg-secondary:#f8f9fa;--text-primary:#2c3e50;--text-light:#adb5bd;--border-color:#dee2e6;--primary-color:#3498db;--success-color:#2ecc71;--error-color:#e74c3c;--result-success-bg:#d4edda;--result-success-text:#155724;--result-error-bg:#f8d7da;--result-error-text:#721c24;--result-warning-bg:#fff3cd;--result-warning-text:#856404;--border-radius:12px;--border-radius-sm:8px}body.dark-mode{--bg-gradient:linear-gradient(135deg,#232526 0%,#414345 100%);--bg-primary:#2c3e50;--bg-secondary:#34495e;--text-primary:#ecf0f1;--text-light:#95a5a6;--border-color:#465b71;--result-success-bg:#2c5a3d;--result-success-text:#fff;--result-error-bg:#5a2c2c;--result-error-text:#fff;--result-warning-bg:#5a4b1e;--result-warning-text:#fff8dd}html{height:100%}body{font-family:'Inter',sans-serif;background:var(--bg-gradient);background-attachment:fixed;color:var(--text-primary);line-height:1.6;margin:0;padding:0;min-height:100%;display:flex;flex-direction:column;align-items:center;transition:background .3s ease,color .3s ease}.container{max-width:800px;width:100%;padding:20px;box-sizing:border-box}.header{text-align:center;margin-bottom:30px}.main-title{font-size:2.2rem;font-weight:700;color:#fff;text-shadow:1px 1px 3px rgba(0,0,0,.2)}.card{background:var(--bg-primary);border-radius:var(--border-radius);padding:25px;box-shadow:0 8px 20px rgba(0,0,0,.1);margin-bottom:25px;transition:background .3s ease}.form-section{display:flex;flex-direction:column;align-items:center}.form-label{display:block;font-weight:500;margin-bottom:8px;color:var(--text-primary);width:100%;max-width:450px;text-align:left}.input-wrapper{width:100%;max-width:450px;margin-bottom:15px}.form-input{width:100%;padding:12px;border:1px solid var(--border-color);border-radius:var(--border-radius-sm);font-size:.95rem;box-sizing:border-box;background-color:var(--bg-secondary);color:var(--text-primary);transition:border-color .3s ease,background-color .3s ease}textarea.form-input{min-height:60px;resize:vertical}.btn-primary{background:linear-gradient(135deg,var(--primary-color),#2980b9);color:#fff;padding:12px 25px;border:none;border-radius:var(--border-radius-sm);font-size:1rem;font-weight:500;cursor:pointer;width:100%;max-width:450px;box-sizing:border-box;display:flex;align-items:center;justify-content:center}.btn-primary:disabled{background:#bdc3c7;cursor:not-allowed}.loading-spinner{width:16px;height:16px;border:2px solid hsla(0,0%,100%,.3);border-top-color:#fff;border-radius:50%;animation:spin 1s linear infinite;display:none;margin-left:8px}@keyframes spin{to{transform:rotate(360deg)}}.result-section{margin-top:25px}.result-card{padding:18px;border-radius:var(--border-radius-sm);margin-bottom:12px;transition:background-color .3s,color .3s,border-color .3s;background-color:var(--bg-secondary)}.result-card h2{margin-top:0;border-bottom:1px solid var(--border-color);padding-bottom:10px;margin-bottom:15px}.domain-card{margin-bottom:20px}.domain-ip-list,.ip-grid{border:1px solid var(--border-color);padding:10px;border-radius:var(--border-radius-sm);max-height:250px;overflow-y:auto;margin-top:10px}.result-success{background-color:var(--result-success-bg);border-left:4px solid var(--success-color);color:var(--result-success-text)}.result-error{background-color:var(--result-error-bg);border-left:4px solid var(--error-color);color:var(--result-error-text)}.result-warning{background-color:var(--result-warning-bg);border-left:4px solid #f39c12;color:var(--result-warning-text)}.result-card h3 .status-icon-prefix{margin-right:8px}.ip-item-multi{display:flex;justify-content:space-between;align-items:center;padding:8px 5px}.ip-item-multi:not(:last-child){border-bottom:1px solid var(--border-color)}.ip-tag{background-color:var(--bg-primary);padding:3px 7px;border-radius:5px;font-family:'Courier New',Courier,monospace;cursor:pointer}.ip-details{font-size:.9em;color:var(--text-light);padding-left:15px}.copy-btn{cursor:pointer;font-weight:600}.action-buttons{margin-top:20px;display:flex;justify-content:center}.toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%);background:#333;color:#fff;padding:12px 20px;border-radius:var(--border-radius-sm);z-index:1001;opacity:0;transition:opacity .3s,transform .3s}.toast.show{opacity:1}.api-docs{margin-top:30px;padding:25px;background:var(--bg-primary);border-radius:var(--border-radius);transition:background .3s ease}.api-docs p{background-color:var(--bg-secondary);border:1px solid var(--border-color);padding:10px;border-radius:4px;margin-bottom:10px;word-break:break-all;transition:background .3s ease,border-color .3s ease}.api-docs p code{background:none;padding:0}.footer{text-align:center;padding:20px;margin-top:30px;color:hsla(0,0%,100%,.8);font-size:.85em;border-top:1px solid hsla(0,0%,100%,.1)}.github-corner svg{fill:var(--primary-color);color:#fff;position:fixed;top:0;border:0;right:0;z-index:1000}body.dark-mode .github-corner svg{fill:#fff;color:#151513}.octo-arm{transform-origin:130px 106px}.github-corner:hover .octo-arm{animation:octocat-wave 560ms ease-in-out}@keyframes octocat-wave{0%,100%{transform:rotate(0)}20%,60%{transform:rotate(-25deg)}40%,80%{transform:rotate(10deg)}}#theme-toggle{position:fixed;bottom:25px;right:25px;z-index:1002;background:var(--bg-primary);border:1px solid var(--border-color);width:48px;height:48px;border-radius:50%;cursor:pointer;display:flex;align-items:center;justify-content:center;padding:0;box-shadow:0 4px 8px rgba(0,0,0,.15);transition:background-color .3s,border-color .3s}#theme-toggle svg{width:24px;height:24px;stroke:var(--text-primary);transition:all .3s ease}body:not(.dark-mode) #theme-toggle .sun-icon{display:block;fill:none}body:not(.dark-mode) #theme-toggle .moon-icon{display:none}body.dark-mode #theme-toggle .sun-icon{display:none}body.dark-mode #theme-toggle .moon-icon{display:block;fill:var(--text-primary);stroke:var(--text-primary)}
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
        <label for="proxyip" class="form-label">Enter IPs or Domains (one per line):</label>
        <div class="input-wrapper">
          <textarea id="proxyip" class="form-input" rows="4" placeholder="127.0.0.1 or nima.nscl.ir" autocomplete="off"></textarea>
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
         <h3><span id="rangeResultIcon"></span>Successful IPs in Range:</h3>
         <div id="rangeResultSummary" style="margin-bottom: 10px;"></div>
         <div id="successfulRangeIPsList" class="domain-ip-list"></div>
         <button id="copyRangeBtn" class="btn-secondary" style="display:none; margin-top: 15px;">Copy Successful IPs</button>
      </div>

    </div>
    <div class="api-docs">
       <h3 style="margin-bottom:15px; text-align:center;">PATH URL Documentation</h3>
       <p><code>GET /proxyip/IP1,IP2,IP3,...</code></p>
       <p><code>GET /iprange/127.0.0.0-255,128.0.0.0-255,...</code></p>
       <p><code>GET /file/https://your.file/ip.txt or ip.csv</code></p>
       <hr style="border:0; border-top: 1px solid var(--border-color); margin: 20px 0;"/>
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
  <script src="/client.js"></script>
</body>
</html>`;
}

// --- Main Fetch Handler ---
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        const UA = request.headers.get('User-Agent') || 'null';
        const hostname = url.hostname;
        
        const processAndRender = async (allIPs, options) => {
            try {
                if (!allIPs || allIPs.length === 0) {
                    return new Response(generateResultsPageHTML({ ...options, results: [], successfulIPsText: '' }), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
                }
                const uniqueIPs = [...new Set(allIPs)];
                const allResults = [];
                const batchSize = 20;

                for (let i = 0; i < uniqueIPs.length; i += batchSize) {
                    const batch = uniqueIPs.slice(i, i + batchSize);
                    const checkPromises = batch.map(ip => checkProxyIP(ip));
                    const batchResults = await Promise.all(checkPromises);
                    allResults.push(...batchResults);
                }
                
                const successfulChecks = allResults.filter(result => result.success);
                const successfulIPsText = successfulChecks.map(c => c.proxyIP).join('\n');
                
                const successfulResultsWithInfo = await Promise.all(successfulChecks.map(async (check) => {
                    const info = await getIpInfo(check.proxyIP);
                    return { check, info };
                }));

                const html = generateResultsPageHTML({ ...options, results: successfulResultsWithInfo, successfulIPsText });
                return new Response(html, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
            } catch (error) {
                return new Response(`An error occurred: ${error.message}`, { status: 500 });
            }
        };

        if (path.toLowerCase().startsWith('/proxyip/')) {
            const ips_string = decodeURIComponent(path.substring('/proxyip/'.length));
            const allIPsToTest = ips_string.split(',').map(s => s.trim()).filter(Boolean);
            return processAndRender(allIPsToTest, {
                title: 'Proxy IP Results:',
                pageType: 'proxyip'
            });
        }

        if (path.toLowerCase().startsWith('/iprange/')) {
            const ranges_string = decodeURIComponent(path.substring('/iprange/'.length));
            const allIPsToTest = ranges_string.split(',').flatMap(range => parseIPRangeServer(range.trim()));
            return processAndRender(allIPsToTest, {
                title: "IP Range's Results:",
                subtitleLabel: "Range's:",
                subtitleContent: ranges_string,
                pageType: 'iprange'
            });
        }
        
        if (path.toLowerCase().startsWith('/file/')) {
            const targetUrl = request.url.substring(request.url.indexOf('/file/') + 6);
            if (!targetUrl || !targetUrl.startsWith('http') || (!targetUrl.toLowerCase().endsWith('.txt') && !targetUrl.toLowerCase().endsWith('.csv'))) {
                return new Response('Invalid URL or file type.', { status: 400 });
            }
            try {
                const response = await fetch(targetUrl, { headers: {'User-Agent': 'ProxyChecker/1.0'} });
                if (!response.ok) throw new Error(`Failed to fetch file: ${response.statusText}`);
                const text = await response.text();
                
                const foundIPs = [...(text.match(ipv4Regex) || []), ...(text.match(ipv6Regex) || [])];
                const filteredIPs = foundIPs.filter(ipWithPort => {
                    const parts = ipWithPort.split(':');
                    return parts.length === 1 || parts[1] === '443';
                });

                return processAndRender(filteredIPs, {
                    title: 'File Test Results:',
                    subtitleLabel: 'File Link Address:',
                    subtitleContent: targetUrl,
                    pageType: 'file'
                });
            } catch(e) {
                return new Response(`Error processing file: ${e.message}`, { status: 500 });
            }
        }
        
        if (path === '/client.js') {
            return new Response(CLIENT_SCRIPT, { headers: { "Content-Type": "application/javascript;charset=UTF-8" } });
        }

        if (path.toLowerCase().startsWith('/api/')) {
            const timestampForToken = Math.ceil(new Date().getTime() / (1000 * 60 * 31));
            const temporaryTOKEN = await doubleHash(hostname + timestampForToken + UA);
            const permanentTOKEN = env.TOKEN || temporaryTOKEN;
            
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
                const proxyIPInput = url.searchParams.get('proxyip');
                if (!proxyIPInput) return new Response(JSON.stringify({success: false, error: 'Missing proxyip parameter'}), { status: 400, headers: { "Content-Type": "application/json" }});
                const result = await checkProxyIP(proxyIPInput);
                return new Response(JSON.stringify(result), {
                    status: 200, headers: { "Content-Type": "application/json" }
                });
            }
            
            if (path.toLowerCase() === '/api/resolve') {
                const domain = url.searchParams.get('domain');
                if (!domain) return new Response(JSON.stringify({success: false, error: 'Missing domain parameter'}), { status: 400, headers: { "Content-Type": "application/json" }});
                try {
                    const ips = await resolveDomain(domain);
                    return new Response(JSON.stringify({ success: true, domain, ips }), { headers: { "Content-Type": "application/json" } });
                } catch (error) {
                    return new Response(JSON.stringify({ success: false, error: error.message }), { status: 500, headers: { "Content-Type": "application/json" } });
                }
            }

            if (path.toLowerCase() === '/api/ip-info') {
                let ip = url.searchParams.get('ip') || request.headers.get('CF-Connecting-IP');
                if (!ip) return new Response(JSON.stringify({success: false, error: 'IP parameter not provided'}), { status: 400, headers: { "Content-Type": "application/json" }});
                if (ip.includes('[')) ip = ip.replace(/\[|\]/g, '');
                const data = await getIpInfo(ip);
                return new Response(JSON.stringify(data), { headers: { "Content-Type": "application/json" } });
            }
            
            return new Response(JSON.stringify({success: false, error: 'API route not found'}), { status: 404, headers: { "Content-Type": "application/json" } });
        }
        
        const faviconURL = env.ICO || 'https://github.com/user-attachments/assets/31a6ced0-62b8-429f-a98e-082ea5ac1990';

        if (path.toLowerCase() === '/favicon.ico') {
            return Response.redirect(faviconURL, 302);
        }
        
        if (path === '/') {
            return new Response(generateMainHTML(faviconURL), {
                headers: { "content-type": "text/html;charset=UTF-8" }
            });
        }
        
        return new Response('Not Found', { status: 404 });
    }
};
