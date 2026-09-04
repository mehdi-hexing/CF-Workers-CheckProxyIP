import { connect } from 'cloudflare:sockets';

// --- HELPER FUNCTIONS ---

async function checkProxyIPTCP(proxyIP, port) {
    try {
        const startTime = Date.now();
        const connectHost = (proxyIP.includes(':') && !proxyIP.startsWith('[')) ? `[${proxyIP}]` : proxyIP;
        const tcpSocket = connect({ hostname: connectHost, port: port });
        const ping = Date.now() - startTime;

        const writer = tcpSocket.writable.getWriter();
        await writer.write(new TextEncoder().encode(
            'GET /cdn-cgi/trace HTTP/1.1\r\n' +
            'Host: speed.cloudflare.com\r\n' +
            'User-Agent: checkip/mehdi/\r\n' +
            'Connection: close\r\n\r\n'
        ));
        writer.releaseLock();

        const reader = tcpSocket.readable.getReader();
        let responseData = new Uint8Array(0);
        const timeout = new Promise(resolve => setTimeout(() => resolve({ done: true }), 10000));
        
        while (true) {
            const { value, done } = await Promise.race([reader.read(), timeout]);
            if (done) break;
            if (value) {
                const newData = new Uint8Array(responseData.length + value.length);
                newData.set(responseData);
                newData.set(value, responseData.length);
                responseData = newData;
            }
        }
        reader.releaseLock();
        await tcpSocket.close();

        const responseText = new TextDecoder().decode(responseData);
        const looksLikeCloudflare = responseText.includes('cloudflare');
        const isExpectedError = responseText.includes('plain HTTP request') || responseText.includes('400 Bad Request');
        const hasBody = responseData.length > 100;
        
        return {
            success: looksLikeCloudflare && isExpectedError && hasBody,
            ping: ping,
            method: 'TCP Fallback'
        };
    } catch (error) {
        return { success: false, error: error.message, method: 'TCP Fallback' };
    }
}

async function checkProxyIP(proxyIPInput, env) {
    const API_TIMEOUT = 10000;
    let portRemote = 443;
    let hostToCheck = proxyIPInput;

    if (proxyIPInput.includes('.tp')) {
        const portMatch = proxyIPInput.match(/\.tp(\d+)\./);
        if (portMatch) portRemote = parseInt(portMatch[1], 10);
        hostToCheck = proxyIPInput.split('.tp')[0];
    } else if (proxyIPInput.includes('[') && proxyIPInput.includes(']:')) {
        portRemote = parseInt(proxyIPInput.split(']:')[1], 10);
        hostToCheck = proxyIPInput.split(']:')[0] + ']';
    } else if (proxyIPInput.includes(':') && !proxyIPInput.startsWith('[')) {
        const parts = proxyIPInput.split(':');
        if (parts.length === 2 && parts[0].includes('.')) {
            hostToCheck = parts[0];
            portRemote = parseInt(parts[1], 10) || 443;
        }
    }
    const cleanIp = hostToCheck.replace(/\[|\]/g, '');

    const apiUrls = [
        `https://YourServerIP:PORT/api/v1/check?proxyip=${encodeURIComponent(proxyIPInput)}`,
        `https://YourServerRender.onrender.com/api/v1/check?proxyip=${encodeURIComponent(proxyIPInput)}`
    ];
    let lastApiError = 'No response from APIs.';

    for (const apiUrl of apiUrls) {
        try {
            const timeoutPromise = new Promise((_, reject) =>
                setTimeout(() => reject(new Error('API request timed out')), API_TIMEOUT)
            );
            const fetchPromise = fetch(apiUrl);
            const response = await Promise.race([fetchPromise, timeoutPromise]);

            if (!response.ok) {
                throw new Error(`API failed with status: ${response.status}`);
            }
            const data = await response.json();
            if (data.proxyip === true) {
                let ipInfo = await getIpInfo(cleanIp);
                if (ipInfo.as === 'N/A' && data.asOrganization) {
                    ipInfo.as = data.asOrganization;
                }
                return {
                    success: true,
                    proxyIP: hostToCheck,
                    portRemote: portRemote,
                    ping: data.ping,
                    timestamp: new Date().toISOString(),
                    info: ipInfo,
                    method: 'API'
                };
            }
        } catch (error) {
            console.error(`API check failed for ${apiUrl}:`, error.message);
            lastApiError = error.message;
        }
    }
    
    console.log(`All APIs failed or timed out. Falling back to TCP check for ${hostToCheck}:${portRemote}`);
    const tcpResult = await checkProxyIPTCP(cleanIp, portRemote);
    
    if (tcpResult.success) {
        const ipInfo = await getIpInfo(cleanIp);
        return {
            success: true,
            proxyIP: hostToCheck,
            portRemote: portRemote,
            ping: tcpResult.ping,
            timestamp: new Date().toISOString(),
            info: ipInfo,
            method: 'TCP Fallback'
        };
    }
    
    return {
        success: false,
        proxyIP: proxyIPInput,
        timestamp: new Date().toISOString(),
        error: `API check failed: ${lastApiError}. TCP fallback also failed: ${tcpResult.error || 'Connection failed.'}`
    };
}

async function getScamalyticsFallback(ip) {
    const cleanIp = ip.replace(/\[|\]/g, '');
    try {
        const response = await fetch(`https://Cloudflare-scamalytics.pages.dev/${encodeURIComponent(cleanIp)}`, {
            headers: { 'User-Agent': 'Mozilla/5.0 (compatible; ProxyIPChecker/1.0)' }
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        if (!data || !data.info || data.info.success !== true) throw new Error('Malformed fallback response');
        return data;
    } catch (e) {
        console.error("Scamalytics fallback mirror failed:", e.message);
        return null;
    }
}

async function getIpInfo(ip) {
    const defaultResponse = { status: 'fail', country: 'N/A', countryCode: 'N/A', as: 'N/A' };
    try {
        const response = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,as&lang=en`);
        if (response.ok) {
            const data = await response.json();
            if (data.status !== 'fail') {
                return data;
            }
        }
    } catch (e) {
        console.error("Geo API (ip-api.com) failed:", e.message);
    }

    const fallback = await getScamalyticsFallback(ip);
    if (fallback && fallback.details) {
        const d = fallback.details;
        const asLabel = [d.asn ? `AS${d.asn}` : '', d.isp || d.organization || ''].filter(Boolean).join(' ');
        return {
            status: 'success',
            country: d.country || 'N/A',
            countryCode: d.country_code || 'N/A',
            as: asLabel || 'N/A'
        };
    }
    return defaultResponse;
}


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

function simpleHash(str) {
    let hash = 0;
    if (str.length === 0) return hash.toString();
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = (hash << 5) - hash + char;
        hash |= 0;
    }
    return hash.toString();
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
    if (ipv4Data.Answer) ips.push(...ipv4Data.Answer.filter(r => r.type === 1).map(r => r.data));
    if (ipv6Data.Answer) ips.push(...ipv6Data.Answer.filter(r => r.type === 28).map(r => `[${r.data}]`));
    if (ips.length === 0) throw new Error('No A or AAAA records found for this domain.');
    return ips;
  } catch (error) {
    throw new Error(`DNS resolution failed: ${error.message}`);
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

const forgivingIPv4Regex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
function isValidIPv6Core(str) {
    if (str === '') return false;
    if (str.indexOf('::') !== -1) {
        if ((str.match(/::/g) || []).length > 1) return false;
        const parts = str.split('::');
        const head = parts[0] ? parts[0].split(':') : [];
        const tail = parts[1] ? parts[1].split(':') : [];
        if (head.length + tail.length > 7) return false;
        return [...head, ...tail].every(g => /^[A-Fa-f0-9]{1,4}$/.test(g));
    }
    const groups = str.split(':');
    if (groups.length !== 8) return false;
    return groups.every(g => /^[A-Fa-f0-9]{1,4}$/.test(g));
}

function extractIPv6FromText(text) {
    const candidateRegex = /\[[A-Fa-f0-9:]{2,45}\](?::\d{1,5})?|(?<![A-Fa-f0-9:])[A-Fa-f0-9:]{2,45}(?![A-Fa-f0-9:])/g;
    const candidates = text.match(candidateRegex) || [];
    const results = [];
    for (const c of candidates) {
        let core = c;
        if (core.startsWith('[')) {
            const m = core.match(/^\[([A-Fa-f0-9:]+)\](?::\d{1,5})?$/);
            if (!m) continue;
            core = m[1];
        }
        if (core.indexOf(':') === -1) continue;
        if (isValidIPv6Core(core)) results.push(c);
    }
    return results;
}
const cidrRangeRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\/24\b/g;
const hyphenatedRangeRegex = /\b(?:\d{1,3}\.){3}\d{1,3}-\d{1,3}\b/g;

function generateDomainCheckPageHTML({ domains, temporaryTOKEN }) {
    const domainsJson = JSON.stringify(domains);
    const domainsHTML = domains.map(domain => 
        `<div><strong>Domain:</strong> <span class="range-tag" onclick="copyToClipboard('${domain}', this)">${domain}</span></div>`
    ).join('');

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Domain Resolve Results</title>
    <style>
        :root{--bg-color:#f6f8fa;--card-bg-color:#ffffff;--text-color:#1f2328;--border-color:#d1d9e0;--hover-bg-color:#f3f4f6;--primary-color:#0969da;--primary-text-color:#fff;--subtle-text-color:#656d76;--tag-bg-color:#eef1f4;--secondary-color:#656d76;--success-color:#1a7f37;--error-color:#d1242f;--warning-color:#9a6700;--card-bg-color-rgb:255,255,255;--tag-bg-color-rgb:238,241,244;--success-color-rgb:26,127,55;--error-color-rgb:209,36,47;--warning-color-rgb:154,103,0;--critical-color-rgb:102,10,10;--secondary-color-rgb:101,109,118;--primary-color-rgb:9,105,218;--glass-border:rgba(255,255,255,.6);--glass-shadow:0 8px 24px rgba(31,35,40,.08)}body.dark-mode{--bg-color:#0d1117;--card-bg-color:#161b22;--text-color:#e6edf3;--border-color:#30363d;--hover-bg-color:#21262d;--subtle-text-color:#8b949e;--tag-bg-color:#21262d;--secondary-color:#8b949e;--success-color:#3fb950;--error-color:#f85149;--warning-color:#d29922;--primary-color:#4493f8;--card-bg-color-rgb:22,27,34;--tag-bg-color-rgb:33,38,45;--success-color-rgb:63,185,80;--error-color-rgb:248,81,73;--warning-color-rgb:210,153,34;--critical-color-rgb:139,15,15;--secondary-color-rgb:139,148,158;--primary-color-rgb:68,147,248;--glass-border:rgba(255,255,255,.08);--glass-shadow:0 8px 24px rgba(0,0,0,.5)}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background-color:var(--bg-color);background-image:radial-gradient(circle at 15% -10%, rgba(9,105,218,.09), transparent 55%),radial-gradient(circle at 90% 0%, rgba(130,80,223,.07), transparent 50%);background-attachment:fixed;color:var(--text-color);margin:0;padding:20px;transition:background-color .3s,color .3s}.container{max-width:700px;margin:0 auto}.header{display:flex;justify-content:space-between;align-items:flex-start;padding-bottom:15px;margin-bottom:25px;border-bottom:1px solid var(--border-color)}.title-section h1{font-size:clamp(1.375rem,4vw,1.8rem);font-weight:700;letter-spacing:-.01em;margin:0 0 10px}body:not(.dark-mode) .title-section h1{text-shadow:0 1px 0 rgba(255,255,255,.6),0 3px 8px rgba(31,35,40,.12)}body.dark-mode .title-section h1{text-shadow:0 0 10px rgba(68,147,248,.45),0 0 26px rgba(68,147,248,.22)}.domains-list{font-size:.875rem;color:var(--subtle-text-color); display: flex; flex-direction: column; gap: 5px;}.range-tag{display:inline-flex;align-items:center;background-color:rgba(var(--tag-bg-color-rgb),.75);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);padding:6px 10px;border-radius:9px;border:1px solid var(--glass-border);font-family:'SF Mono','Courier New',Courier,monospace;cursor:pointer;margin:2px 0;transition:background-color .2s,transform .15s;text-decoration:none;color:var(--text-color);word-break:break-all;}.range-tag:hover{background-color:var(--primary-color);color:var(--primary-text-color)}.button-group{display:flex;gap:10px;flex-shrink:0;margin-left:20px}.btn{padding:8px 16px;border:none;border-radius:8px;cursor:pointer;font-weight:500;font-size:.9em;transition:transform .2s;text-decoration:none;display:inline-flex;align-items:center}.btn-primary{background:linear-gradient(135deg,var(--primary-color),#2980b9);color:var(--primary-text-color)}.btn-secondary{background-color:var(--secondary-color);color:var(--primary-text-color)}.btn:hover{transform:translateY(-2px)}.theme-toggle{background-color:var(--card-bg-color);border:1px solid var(--border-color);width:38px;height:38px;justify-content:center;padding:0;border-radius:50%}.results-card{background-color:rgba(var(--card-bg-color-rgb),.68);backdrop-filter:blur(18px) saturate(160%);-webkit-backdrop-filter:blur(18px) saturate(160%);border:1px solid var(--glass-border);border-radius:20px;padding:12px;min-height:50px;box-shadow:var(--glass-shadow);}.ip-item{display:flex;justify-content:space-between;align-items:flex-start;padding:12px 15px;gap:15px;border-radius:14px;}.ip-item:not(:last-child){border-bottom:1px solid var(--border-color)}.ip-tag{display:inline-flex;align-items:center;height:26px;box-sizing:border-box;background-color:rgba(var(--tag-bg-color-rgb),.75);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);padding:0 10px;border-radius:9px;border:1px solid var(--glass-border);font-family:'SF Mono','Courier New',Courier,monospace;font-size:.85rem;cursor:pointer;transition:background-color .2s,transform .15s;word-break:break-all;white-space:nowrap;}.ip-tag:hover{background-color:var(--primary-color);color:var(--primary-text-color)}.ip-details{display:flex;flex-wrap:wrap;align-items:center;justify-content:flex-end;gap:6px;font-size:.875rem;color:var(--subtle-text-color);word-break:break-word;min-width:0;flex:1 1 auto;}.detail-chip{display:inline-flex;align-items:center;justify-content:center;gap:3px;white-space:nowrap;height:22px;box-sizing:border-box;padding:0 .6em;border-radius:8px;background-color:rgba(var(--secondary-color-rgb,150,150,150),.12);border:1px solid rgba(var(--secondary-color-rgb,150,150,150),.18);backdrop-filter:blur(4px);-webkit-backdrop-filter:blur(4px)}.action-buttons{margin-top:20px;display:flex;justify-content:center;gap:10px}.footer{text-align:center;padding:20px;margin-top:30px;color:var(--subtle-text-color);font-size:.8125rem;border-top:1px solid var(--border-color)}.footer-repo-link{display:inline-flex;align-items:center;gap:4px;color:var(--primary-color);text-decoration:none;font-weight:600;vertical-align:middle}.footer-repo-link:hover{text-decoration:underline}.footer-repo-link svg{width:13px;height:13px}.toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%);background:#333;color:#fff;padding:12px 20px;border-radius:8px;z-index:1001;opacity:0;transition:opacity .3s,transform .3s;pointer-events:none}.toast.show{opacity:1}
        .theme-toggle svg { width: 18px; height: 18px; stroke: var(--text-color); transition: all 0.3s ease; }
        body:not(.dark-mode) .theme-toggle .sun-icon { display: block; fill: none;}
        body:not(.dark-mode) .theme-toggle .moon-icon { display: none; }
        body.dark-mode .theme-toggle .sun-icon { display: none; }
        body.dark-mode .theme-toggle .moon-icon { display: block; fill: var(--text-color); stroke: var(--text-color); }
        .badge{position:relative;overflow:hidden;isolation:isolate;display:inline-flex;align-items:center;justify-content:center;height:24px;box-sizing:border-box;padding:0 .8em;font-size:.72rem;font-weight:700;line-height:1;letter-spacing:.03em;text-align:center;white-space:nowrap;vertical-align:middle;border-radius:9px;border:1px solid rgba(255,255,255,.35);color:#fff;text-shadow:0 1px 2px rgba(0,0,0,.35);backdrop-filter:blur(14px) saturate(180%);-webkit-backdrop-filter:blur(14px) saturate(180%)}.badge::before{content:'';position:absolute;inset:0;z-index:-1;background:linear-gradient(160deg,rgba(255,255,255,.38),rgba(255,255,255,0) 55%)}.badge.success{background-color:rgba(var(--success-color-rgb),.5);box-shadow:inset 0 1px 0 rgba(255,255,255,.3),0 3px 8px rgba(var(--success-color-rgb),.3)}.badge.error{background-color:rgba(var(--error-color-rgb),.5);box-shadow:inset 0 1px 0 rgba(255,255,255,.3),0 3px 8px rgba(var(--error-color-rgb),.3)}.badge.warning{background-color:rgba(var(--warning-color-rgb),.5);box-shadow:inset 0 1px 0 rgba(255,255,255,.3),0 3px 8px rgba(var(--warning-color-rgb),.28)}.badge.critical{background-color:rgba(var(--critical-color-rgb),.62);border-color:rgba(255,255,255,.2);box-shadow:inset 0 1px 0 rgba(255,255,255,.22),0 3px 10px rgba(var(--critical-color-rgb),.45),0 0 0 1px rgba(0,0,0,.15)}.badge.info{background-color:rgba(var(--secondary-color-rgb),.5);box-shadow:inset 0 1px 0 rgba(255,255,255,.3),0 3px 8px rgba(0,0,0,.12)}
        .risk-link-button{position:relative;overflow:hidden;display:inline-flex;align-items:center;justify-content:center;height:24px;box-sizing:border-box;background-color:rgba(var(--secondary-color-rgb),.82);backdrop-filter:blur(8px) saturate(160%);-webkit-backdrop-filter:blur(8px) saturate(160%);color:#fff;text-shadow:0 1px 1px rgba(0,0,0,.18);padding:0 .8em;font-size:.72rem;font-weight:700;letter-spacing:.03em;border-radius:9px;border:1px solid rgba(255,255,255,.3);box-shadow:inset 0 1px 0 rgba(255,255,255,.3),0 3px 8px rgba(0,0,0,.15);text-decoration:none;transition:opacity .2s,transform .15s}.risk-link-button::before{content:'';position:absolute;inset:0;background:linear-gradient(160deg,rgba(255,255,255,.32),rgba(255,255,255,0) 55%);pointer-events:none}.risk-link-button:hover{opacity:.85;transform:translateY(-1px)}
        .failed-details{margin-top:16px;background-color:rgba(var(--error-color-rgb),.06);border:1px solid var(--glass-border);border-radius:16px;padding:2px 14px;}
        .failed-details summary{cursor:pointer;padding:10px 0;font-size:.85rem;font-weight:600;color:var(--error-color);display:flex;align-items:center;gap:10px;list-style:none}
        .failed-details summary::-webkit-details-marker{display:none}
        .failed-details summary::before{content:'\\25B8';margin-right:2px;opacity:.7;font-size:.8em;transition:transform .2s}
        .failed-details[open] summary::before{transform:rotate(90deg)}
        .failed-list{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:8px;padding:4px 0 14px}
        .failed-item{display:flex;align-items:center;justify-content:space-between;gap:6px;width:100%;min-width:0;box-sizing:border-box;background-color:rgba(var(--tag-bg-color-rgb),.75);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);border:1px solid rgba(var(--error-color-rgb),.5);border-radius:9px;padding:4px 9px;font-family:'SF Mono','Courier New',Courier,monospace;font-size:.8rem}
        .failed-item>span:first-child{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:0 0 auto;max-width:70%}
        .failed-item .fail-reason{color:var(--subtle-text-color);font-family:-apple-system,BlinkMacSystemFont,sans-serif;font-size:.75em;flex:1 1 auto;min-width:0;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
        @media (max-width: 600px){
            .failed-list{grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:6px}
            .failed-item{padding:4px 7px;font-size:.72rem}
            .failed-item .fail-reason{font-size:.7em}
            .ip-item{flex-direction:column;align-items:stretch;gap:8px;padding:12px}
            .ip-details{justify-content:flex-start;padding-left:0;width:100%}
            .ip-tag{font-size:.8rem}
            .detail-chip{font-size:.8rem}
            .header{flex-direction:column;align-items:stretch;gap:12px}
            .button-group{margin-left:0;align-self:flex-end}
        }
        @media (max-width: 420px){
            .failed-list{grid-template-columns:1fr}
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="title-section">
                <h1 id="main-title">Domain Resolve Results:</h1>
                <div class="domains-list">${domainsHTML}</div>
            </div>
            <div class="button-group">
                <button class="btn theme-toggle" onclick="toggleTheme()">
                    <svg class="sun-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
                    <svg class="moon-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="0.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
                </button>
            </div>
        </header>
        <p id="summary">Resolving domains and preparing to check IPs...</p>
        <main id="results-container" class="results-card">
            <p style="text-align:center; padding: 20px;">Processing...</p>
        </main>
        <details id="failed-details" class="failed-details" style="display:none;">
            <summary>❌ Failed IPs (<span id="failed-count">0</span>)</summary>
            <div id="failed-list" class="failed-list"></div>
        </details>
        <div id="action-buttons-container"></div>
        <footer class="footer">
            <p>© ${new Date().getFullYear()} Proxy IP Checker - By <a href="https://github.com/mehdi-hexing/CF-ProxyIPChecker" target="_blank" rel="noopener" class="footer-repo-link"><svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>mehdi-hexing</a></p>
        </footer>
    </div>
    <div id="toast" class="toast"></div>
    <script>
        const domainsToCheck = ${domainsJson};
        const TEMP_TOKEN = "${temporaryTOKEN}";
        const storageKey = 'proxy_results_' + window.location.pathname;
        let successfulIPs = [];
        let failedIPs = [];
        let checkedCount = 0;
        let totalIPs = 0;
        let allResults = {};
        let persistTimer = null;

        function persistResultsNow() {
            if (persistTimer) { clearTimeout(persistTimer); persistTimer = null; }
            try { localStorage.setItem(storageKey, JSON.stringify({ results: allResults })); }
            catch(e) { console.error('Failed to persist results cache', e); }
        }
        function schedulePersist() {
            if (persistTimer) return;
            persistTimer = setTimeout(persistResultsNow, 350);
        }
        window.addEventListener('pagehide', persistResultsNow);
        window.addEventListener('beforeunload', persistResultsNow);
        document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden') persistResultsNow(); });

        function showToast(message) { const toast = document.getElementById('toast'); toast.textContent = message; toast.classList.add('show'); setTimeout(() => toast.classList.remove('show'), 3000); }
        function copyToClipboard(text, element) { navigator.clipboard.writeText(text).then(() => { const o = element ? element.textContent : ''; if(element) {element.textContent = 'Copied!'; setTimeout(()=>element.textContent=o, 2000);} else { showToast('Copied!')} }).catch(err => { showToast('Copy failed!'); console.error(err); }); }
        function toggleTheme() {
            const body = document.body; body.classList.toggle('dark-mode');
            localStorage.setItem('theme', body.classList.contains('dark-mode') ? 'dark' : 'light');
        }

        async function fetchAPI(path, params) {
            params.append('token', TEMP_TOKEN);
            const url = '/api' + path + '?' + params.toString();
            let lastError;
            for (let attempt = 1; attempt <= 3; attempt++) {
                try {
                    const response = await fetch(url);
                    return await response.json();
                } catch (e) {
                    lastError = e;
                    const isNetworkFailure = e instanceof TypeError || /failed to fetch|networkerror|load failed/i.test(e.message || '');
                    if (!isNetworkFailure || attempt === 3) throw e;
                    await new Promise(r => setTimeout(r, 500 * attempt));
                }
            }
            throw lastError;
        }

        function formatRiskBadge(riskData, ip) {
            if (!riskData || !riskData.scamalytics || riskData.scamalytics.status !== 'ok') {
                const cleanIp = ip.replace(/\\[|\\]/g, '');
                return \`<a href="https://cloudflare-scamalytics.pages.dev/\${cleanIp}" target="_blank" rel="noopener noreferrer" class="risk-link-button">Click Here</a>\`;
            }
            const score = riskData.scamalytics.scamalytics_score;
            const risk = riskData.scamalytics.scamalytics_risk;
            const normRisk = (risk || '').toLowerCase().replace(/_/g, ' ').trim();
            let badgeClass = 'info';
            if (normRisk === 'low') badgeClass = 'success';
            else if (normRisk === 'medium') badgeClass = 'warning';
            else if (normRisk === 'very high') badgeClass = 'critical';
            else if (normRisk === 'high') badgeClass = 'error';
            return \`<span class="badge \${badgeClass}">\${risk} (Score: \${score})</span>\`;
        }

        function renderAllResults() {
            const container = document.getElementById('results-container');
            successfulIPs.sort((a, b) => (a.risk?.scamalytics?.scamalytics_score ?? 999) - (b.risk?.scamalytics?.scamalytics_score ?? 999));
            
            if (successfulIPs.length > 0) {
                 container.innerHTML = ''; 
                 successfulIPs.forEach(item => {
                    const riskText = formatRiskBadge(item.risk, item.ip);
                    const pingText = item.ping ? \`<span class="detail-chip">⚡️ \${item.ping}ms</span>\` : '';
                    const geoText = item.info ? \`<span class="detail-chip">\${item.info.country || 'N/A'}\${item.info.as ? ' · ' + item.info.as.substring(0, 25) : ''}</span>\` : '';
                    const itemHTML = \`<div class="ip-item">\` + 
                                     \`<div><span class="ip-tag" onclick="copyToClipboard('\${item.ip}', this)">\${item.ip}</span></div>\` +
                                     \`<span class="ip-details">\${riskText}\${pingText}\${geoText}</span></div>\`;
                    container.insertAdjacentHTML('beforeend', itemHTML);
                 });
            } else if (checkedCount >= totalIPs) {
                 container.innerHTML = '<p style="text-align:center;">No successful proxies found.</p>';
            }
        }

        function renderFailedResults() {
            const details = document.getElementById('failed-details');
            const list = document.getElementById('failed-list');
            const countEl = document.getElementById('failed-count');
            countEl.textContent = failedIPs.length;
            if (failedIPs.length === 0) {
                details.style.display = 'none';
                list.innerHTML = '';
                return;
            }
            details.style.display = '';
            list.innerHTML = failedIPs.slice().sort((a,b)=>(a.error||'').length-(b.error||'').length).map(f => \`<span class="failed-item"><span onclick="copyToClipboard('\${f.ip}', this)" style="cursor:pointer;">\${f.ip}</span><span class="fail-reason" title="\${(f.error||'').replace(/"/g,'&quot;')}">\${f.error || 'Failed'}</span></span>\`).join('');
        }

        function updateSummary() {
            document.getElementById('summary').textContent = \`Checked: \${checkedCount} / \${totalIPs} | Successful: \${successfulIPs.length} | Failed: \${failedIPs.length}\`;
        }

        async function startChecking() {
            let allIPsToTest = [];
            document.getElementById('results-container').innerHTML = '<p style="text-align:center; padding: 20px;">Resolving domains...</p>';

            const resolvePromises = domainsToCheck.map(async (domain) => {
                try {
                    const resolveData = await fetchAPI('/resolve', new URLSearchParams({ domain }));
                    if (resolveData.success) {
                        return resolveData.ips;
                    }
                } catch (e) { console.error("Failed to resolve", domain, e); }
                return [];
            });

            const resolvedIPArrays = await Promise.all(resolvePromises);
            allIPsToTest = [...new Set(resolvedIPArrays.flat())];
            totalIPs = allIPsToTest.length;

            if (totalIPs === 0) {
                 document.getElementById('summary').textContent = 'No IPs found for the given domains.';
                 document.getElementById('results-container').innerHTML = '<p style="text-align:center;">Could not resolve any IPs.</p>';
                 return;
            }
            try {
                const savedJSON = localStorage.getItem(storageKey);
                if (savedJSON) allResults = JSON.parse(savedJSON).results || {};
            } catch(e) { console.error('Error loading cached results', e); allResults = {}; }

            for (const ip of allIPsToTest) {
                if (allResults[ip]) {
                    if (allResults[ip].success) successfulIPs.push({ ip: allResults[ip].proxyIP || ip, ...allResults[ip] });
                    else failedIPs.push({ ip, error: allResults[ip].error || 'Not a valid proxy' });
                }
            }
            checkedCount = allIPsToTest.filter(ip => allResults[ip]).length;
            if (successfulIPs.length > 0) renderAllResults();
            renderFailedResults();
            updateSummary();

            const ipsToActuallyTest = allIPsToTest.filter(ip => !allResults[ip]);
            if (ipsToActuallyTest.length === 0) {
                document.getElementById('summary').textContent += ' (All IPs loaded from cache)';
            }
            
            document.getElementById('results-container').innerHTML = successfulIPs.length > 0 ? '' : '<p style="text-align:center; padding: 20px;">Checking IPs...</p>';
            updateSummary();

            const batchSize = 20;
            for (let i = 0; i < ipsToActuallyTest.length; i += batchSize) {
                const batch = ipsToActuallyTest.slice(i, i + batchSize);
                const promises = batch.map(async (ip) => {
                    try {
                        const checkData = await fetchAPI('/check', new URLSearchParams({ proxyip: ip }));
                        if (checkData.success) {
                            const riskData = await fetchAPI('/scamalytics-lookup', new URLSearchParams({ ip: checkData.proxyIP }));
                            allResults[ip] = { success: true, ping: checkData.ping, info: checkData.info, risk: riskData, proxyIP: checkData.proxyIP, portRemote: checkData.portRemote };
                            successfulIPs.push({ ip: checkData.proxyIP, ...checkData, risk: riskData });
                        } else {
                            allResults[ip] = { success: false, error: checkData.error || 'Not a valid proxy' };
                            failedIPs.push({ ip, error: checkData.error || 'Not a valid proxy' });
                        }
                    } catch (e) {
                        console.error('Failed to check ip:', ip, e);
                        allResults[ip] = { success: false, error: e.message || 'Request failed' };
                        failedIPs.push({ ip, error: e.message || 'Request failed' });
                    } finally {
                        checkedCount++;
                        schedulePersist();
                    }
                });
                await Promise.allSettled(promises);
                persistResultsNow();
                updateSummary();
                renderFailedResults();
            }

            renderAllResults(); 
            renderFailedResults();
            
            document.title = \`\${successfulIPs.length} Successful IPs Found\`;
            const actionContainer = document.getElementById('action-buttons-container');
            if (successfulIPs.length > 0) {
                 const successfulIPsText = successfulIPs.map(i=>i.ip).join('\\n');
                 const dataUrl = \`data:text/plain;charset=utf-8;base64,\${btoa(unescape(encodeURIComponent(successfulIPsText)))}\`;
                 const downloadButton = \`<a href="\${dataUrl}" download="successful_ips.txt" class="btn btn-secondary">📥 Download Results</a>\`;
                 actionContainer.innerHTML = \`<div class="action-buttons">\${downloadButton}<button class="btn btn-primary" onclick='copyToClipboard(\${JSON.stringify(successfulIPsText)})'>📋 Copy All</button></div>\`;
            }
        }
        
        document.addEventListener('DOMContentLoaded', () => {
            if (localStorage.getItem('theme') === 'dark' || (!('theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
                 document.body.classList.add('dark-mode');
            }
            startChecking();
        });
    </script>
</body>
</html>`;
}

function generateClientSideCheckPageHTML({ title, subtitleLabel, subtitleContent, ipsToCheck, temporaryTOKEN, pageType, contentHash }) {
    const ipsJson = JSON.stringify(ipsToCheck);
    let subtitleHTML = '';
    if (subtitleLabel && subtitleContent) {
        if (pageType === 'file') {
             subtitleHTML = `<div class="ranges-list"><strong>${subtitleLabel}</strong> <a href="${subtitleContent}" class="range-tag" target="_blank" rel="noopener noreferrer">${subtitleContent}</a></div>`;
        } else if (pageType === 'iprange') {
             const ranges = subtitleContent.split(',').map(r => `<span class="range-tag" onclick="copyToClipboard('${r.trim()}', this)">${r.trim()}</span>`).join('<br>');
             subtitleHTML = `<div class="ranges-list"><strong>${subtitleLabel}</strong><br>${ranges}</div>`;
        } else {
             subtitleHTML = `<div class="ranges-list"><strong>${subtitleLabel}</strong> <span class="range-tag">${subtitleContent}</span></div>`;
        }
    }

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Checking IPs...</title>
    <style>
        :root{--bg-color:#f6f8fa;--card-bg-color:#ffffff;--text-color:#1f2328;--border-color:#d1d9e0;--hover-bg-color:#f3f4f6;--primary-color:#0969da;--primary-text-color:#fff;--subtle-text-color:#656d76;--tag-bg-color:#eef1f4;--secondary-color:#656d76;--success-color:#1a7f37;--error-color:#d1242f;--warning-color:#9a6700;--card-bg-color-rgb:255,255,255;--tag-bg-color-rgb:238,241,244;--success-color-rgb:26,127,55;--error-color-rgb:209,36,47;--warning-color-rgb:154,103,0;--critical-color-rgb:102,10,10;--secondary-color-rgb:101,109,118;--primary-color-rgb:9,105,218;--glass-border:rgba(255,255,255,.6);--glass-shadow:0 8px 24px rgba(31,35,40,.08)}body.dark-mode{--bg-color:#0d1117;--card-bg-color:#161b22;--text-color:#e6edf3;--border-color:#30363d;--hover-bg-color:#21262d;--subtle-text-color:#8b949e;--tag-bg-color:#21262d;--secondary-color:#8b949e;--success-color:#3fb950;--error-color:#f85149;--warning-color:#d29922;--primary-color:#4493f8;--card-bg-color-rgb:22,27,34;--tag-bg-color-rgb:33,38,45;--success-color-rgb:63,185,80;--error-color-rgb:248,81,73;--warning-color-rgb:210,153,34;--critical-color-rgb:139,15,15;--secondary-color-rgb:139,148,158;--primary-color-rgb:68,147,248;--glass-border:rgba(255,255,255,.08);--glass-shadow:0 8px 24px rgba(0,0,0,.5)}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background-color:var(--bg-color);background-image:radial-gradient(circle at 15% -10%, rgba(9,105,218,.09), transparent 55%),radial-gradient(circle at 90% 0%, rgba(130,80,223,.07), transparent 50%);background-attachment:fixed;color:var(--text-color);margin:0;padding:20px;transition:background-color .3s,color .3s}.container{max-width:700px;margin:0 auto}.header{display:flex;justify-content:space-between;align-items:flex-start;padding-bottom:15px;margin-bottom:25px;border-bottom:1px solid var(--border-color)}.title-section h1{font-size:clamp(1.375rem,4vw,1.8rem);font-weight:700;letter-spacing:-.01em;margin:0 0 10px}body:not(.dark-mode) .title-section h1{text-shadow:0 1px 0 rgba(255,255,255,.6),0 3px 8px rgba(31,35,40,.12)}body.dark-mode .title-section h1{text-shadow:0 0 10px rgba(68,147,248,.45),0 0 26px rgba(68,147,248,.22)}.ranges-list{font-size:.875rem;color:var(--subtle-text-color)}.range-tag{display:inline-flex;align-items:center;background-color:rgba(var(--tag-bg-color-rgb),.75);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);padding:6px 10px;border-radius:9px;border:1px solid var(--glass-border);font-family:'SF Mono','Courier New',Courier,monospace;cursor:pointer;margin:2px 0;transition:background-color .2s,transform .15s;text-decoration:none;color:var(--text-color);word-break:break-all;}.range-tag:hover{background-color:var(--primary-color);color:var(--primary-text-color)}.button-group{display:flex;gap:10px;flex-shrink:0;margin-left:20px}.btn{padding:8px 16px;border:none;border-radius:8px;cursor:pointer;font-weight:500;font-size:.9em;transition:transform .2s;text-decoration:none;display:inline-flex;align-items:center}.btn-primary{background:linear-gradient(135deg,var(--primary-color),#2980b9);color:var(--primary-text-color)}.btn-secondary{background-color:var(--secondary-color);color:var(--primary-text-color)}.btn:hover{transform:translateY(-2px)}.theme-toggle{background-color:var(--card-bg-color);border:1px solid var(--border-color);width:38px;height:38px;justify-content:center;padding:0;border-radius:50%}.results-card{background-color:rgba(var(--card-bg-color-rgb),.68);backdrop-filter:blur(18px) saturate(160%);-webkit-backdrop-filter:blur(18px) saturate(160%);border:1px solid var(--glass-border);border-radius:20px;padding:12px;min-height:50px;box-shadow:var(--glass-shadow);}.ip-item{display:flex;justify-content:space-between;align-items:flex-start;padding:12px 15px;gap:15px;border-radius:14px;}.ip-item:not(:last-child){border-bottom:1px solid var(--border-color)}.ip-tag{display:inline-flex;align-items:center;height:26px;box-sizing:border-box;background-color:rgba(var(--tag-bg-color-rgb),.75);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);padding:0 10px;border-radius:9px;border:1px solid var(--glass-border);font-family:'SF Mono','Courier New',Courier,monospace;font-size:.85rem;cursor:pointer;transition:background-color .2s,transform .15s;word-break:break-all;white-space:nowrap;}.ip-tag:hover{background-color:var(--primary-color);color:var(--primary-text-color)}.ip-details{display:flex;flex-wrap:wrap;align-items:center;justify-content:flex-end;gap:6px;font-size:.875rem;color:var(--subtle-text-color);word-break:break-word;min-width:0;flex:1 1 auto;}.detail-chip{display:inline-flex;align-items:center;justify-content:center;gap:3px;white-space:nowrap;height:22px;box-sizing:border-box;padding:0 .6em;border-radius:8px;background-color:rgba(var(--secondary-color-rgb,150,150,150),.12);border:1px solid rgba(var(--secondary-color-rgb,150,150,150),.18);backdrop-filter:blur(4px);-webkit-backdrop-filter:blur(4px)}.action-buttons{margin-top:20px;display:flex;justify-content:center;gap:10px}.footer{text-align:center;padding:20px;margin-top:30px;color:var(--subtle-text-color);font-size:.8125rem;border-top:1px solid var(--border-color)}.footer-repo-link{display:inline-flex;align-items:center;gap:4px;color:var(--primary-color);text-decoration:none;font-weight:600;vertical-align:middle}.footer-repo-link:hover{text-decoration:underline}.footer-repo-link svg{width:13px;height:13px}.toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%);background:#333;color:#fff;padding:12px 20px;border-radius:8px;z-index:1001;opacity:0;transition:opacity .3s,transform .3s;pointer-events:none}.toast.show{opacity:1}
        .theme-toggle svg { width: 18px; height: 18px; stroke: var(--text-color); transition: all 0.3s ease; }
        body:not(.dark-mode) .theme-toggle .sun-icon { display: block; fill: none;}
        body:not(.dark-mode) .theme-toggle .moon-icon { display: none; }
        body.dark-mode .theme-toggle .sun-icon { display: none; }
        body.dark-mode .theme-toggle .moon-icon { display: block; fill: var(--text-color); stroke: var(--text-color); }
        .badge{position:relative;overflow:hidden;isolation:isolate;display:inline-flex;align-items:center;justify-content:center;height:24px;box-sizing:border-box;padding:0 .8em;font-size:.72rem;font-weight:700;line-height:1;letter-spacing:.03em;text-align:center;white-space:nowrap;vertical-align:middle;border-radius:9px;border:1px solid rgba(255,255,255,.35);color:#fff;text-shadow:0 1px 2px rgba(0,0,0,.35);backdrop-filter:blur(14px) saturate(180%);-webkit-backdrop-filter:blur(14px) saturate(180%)}.badge::before{content:'';position:absolute;inset:0;z-index:-1;background:linear-gradient(160deg,rgba(255,255,255,.38),rgba(255,255,255,0) 55%)}.badge.success{background-color:rgba(var(--success-color-rgb),.5);box-shadow:inset 0 1px 0 rgba(255,255,255,.3),0 3px 8px rgba(var(--success-color-rgb),.3)}.badge.error{background-color:rgba(var(--error-color-rgb),.5);box-shadow:inset 0 1px 0 rgba(255,255,255,.3),0 3px 8px rgba(var(--error-color-rgb),.3)}.badge.warning{background-color:rgba(var(--warning-color-rgb),.5);box-shadow:inset 0 1px 0 rgba(255,255,255,.3),0 3px 8px rgba(var(--warning-color-rgb),.28)}.badge.critical{background-color:rgba(var(--critical-color-rgb),.62);border-color:rgba(255,255,255,.2);box-shadow:inset 0 1px 0 rgba(255,255,255,.22),0 3px 10px rgba(var(--critical-color-rgb),.45),0 0 0 1px rgba(0,0,0,.15)}.badge.info{background-color:rgba(var(--secondary-color-rgb),.5);box-shadow:inset 0 1px 0 rgba(255,255,255,.3),0 3px 8px rgba(0,0,0,.12)}
        .risk-link-button{position:relative;overflow:hidden;display:inline-flex;align-items:center;justify-content:center;height:24px;box-sizing:border-box;background-color:rgba(var(--secondary-color-rgb),.82);backdrop-filter:blur(8px) saturate(160%);-webkit-backdrop-filter:blur(8px) saturate(160%);color:#fff;text-shadow:0 1px 1px rgba(0,0,0,.18);padding:0 .8em;font-size:.72rem;font-weight:700;letter-spacing:.03em;border-radius:9px;border:1px solid rgba(255,255,255,.3);box-shadow:inset 0 1px 0 rgba(255,255,255,.3),0 3px 8px rgba(0,0,0,.15);text-decoration:none;transition:opacity .2s,transform .15s}.risk-link-button::before{content:'';position:absolute;inset:0;background:linear-gradient(160deg,rgba(255,255,255,.32),rgba(255,255,255,0) 55%);pointer-events:none}.risk-link-button:hover{opacity:.85;transform:translateY(-1px)}
        .failed-details{margin-top:16px;background-color:rgba(var(--error-color-rgb),.06);border:1px solid var(--glass-border);border-radius:16px;padding:2px 14px;}
        .failed-details summary{cursor:pointer;padding:10px 0;font-size:.85rem;font-weight:600;color:var(--error-color);display:flex;align-items:center;gap:10px;list-style:none}
        .failed-details summary::-webkit-details-marker{display:none}
        .failed-details summary::before{content:'\\25B8';margin-right:2px;opacity:.7;font-size:.8em;transition:transform .2s}
        .failed-details[open] summary::before{transform:rotate(90deg)}
        .failed-list{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:8px;padding:4px 0 14px}
        .failed-item{display:flex;align-items:center;justify-content:space-between;gap:6px;width:100%;min-width:0;box-sizing:border-box;background-color:rgba(var(--tag-bg-color-rgb),.75);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);border:1px solid rgba(var(--error-color-rgb),.5);border-radius:9px;padding:4px 9px;font-family:'SF Mono','Courier New',Courier,monospace;font-size:.8rem}
        .failed-item>span:first-child{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:0 0 auto;max-width:70%}
        .failed-item .fail-reason{color:var(--subtle-text-color);font-family:-apple-system,BlinkMacSystemFont,sans-serif;font-size:.75em;flex:1 1 auto;min-width:0;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
        @media (max-width: 600px){
            .failed-list{grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:6px}
            .failed-item{padding:4px 7px;font-size:.72rem}
            .failed-item .fail-reason{font-size:.7em}
            .ip-item{flex-direction:column;align-items:stretch;gap:8px;padding:12px}
            .ip-details{justify-content:flex-start;padding-left:0;width:100%}
            .ip-tag{font-size:.8rem}
            .detail-chip{font-size:.8rem}
            .header{flex-direction:column;align-items:stretch;gap:12px}
            .button-group{margin-left:0;align-self:flex-end}
        }
        @media (max-width: 420px){
            .failed-list{grid-template-columns:1fr}
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="title-section">
                <h1 id="main-title">${title}</h1>
                ${subtitleHTML}
            </div>
            <div class="button-group">
                <button class="btn theme-toggle" onclick="toggleTheme()">
                    <svg class="sun-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
                    <svg class="moon-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="0.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
                </button>
            </div>
        </header>
        <p id="summary">Total IPs to check: ${ipsToCheck.length}. Starting tests...</p>
        <main id="results-container" class="results-card">
            <p style="text-align:center; padding: 20px;">Processing...</p>
        </main>
        <details id="failed-details" class="failed-details" style="display:none;">
            <summary>❌ Failed IPs (<span id="failed-count">0</span>)</summary>
            <div id="failed-list" class="failed-list"></div>
        </details>
        <div id="action-buttons-container"></div>
        <footer class="footer">
            <p>© ${new Date().getFullYear()} Proxy IP Checker - By <a href="https://github.com/mehdi-hexing/CF-ProxyIPChecker" target="_blank" rel="noopener" class="footer-repo-link"><svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>mehdi-hexing</a></p>
        </footer>
    </div>
    <div id="toast" class="toast"></div>
    <script>
        const ipsToCheck = ${ipsJson};
        const TEMP_TOKEN = "${temporaryTOKEN}";
        const pageType = "${pageType}";
        const contentHash = "${contentHash || ''}";
        const storageKey = 'proxy_results_' + window.location.pathname;
        let successfulIPs = [];
        let failedIPs = [];
        let checkedCount = 0;
        let allResults = {};
        let persistTimer = null;

        function persistResultsNow() {
            if (persistTimer) { clearTimeout(persistTimer); persistTimer = null; }
            try { localStorage.setItem(storageKey, JSON.stringify({ hash: contentHash, results: allResults })); }
            catch(e) { console.error('Failed to persist results cache', e); }
        }
        function schedulePersist() {
            if (persistTimer) return;
            persistTimer = setTimeout(persistResultsNow, 350);
        }
        window.addEventListener('pagehide', persistResultsNow);
        window.addEventListener('beforeunload', persistResultsNow);
        document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden') persistResultsNow(); });

        function showToast(message) { const toast = document.getElementById('toast'); toast.textContent = message; toast.classList.add('show'); setTimeout(() => toast.classList.remove('show'), 3000); }
        function copyToClipboard(text, element) { navigator.clipboard.writeText(text).then(() => { const o = element ? element.textContent : ''; if(element) {element.textContent = 'Copied!'; setTimeout(()=>element.textContent=o, 2000);} else { showToast('Copied!')} }).catch(err => { showToast('Copy failed!'); console.error(err); }); }
        function toggleTheme() {
            const body = document.body; body.classList.toggle('dark-mode');
            localStorage.setItem('theme', body.classList.contains('dark-mode') ? 'dark' : 'light');
        }

        async function fetchAPI(path, params) {
            params.append('token', TEMP_TOKEN);
            const url = '/api' + path + '?' + params.toString();
            let lastError;
            for (let attempt = 1; attempt <= 3; attempt++) {
                try {
                    const response = await fetch(url);
                    return await response.json();
                } catch (e) {
                    lastError = e;
                    const isNetworkFailure = e instanceof TypeError || /failed to fetch|networkerror|load failed/i.test(e.message || '');
                    if (!isNetworkFailure || attempt === 3) throw e;
                    await new Promise(r => setTimeout(r, 500 * attempt));
                }
            }
            throw lastError;
        }
        
        function formatRiskBadge(riskData, ip) {
            if (!riskData || !riskData.scamalytics || riskData.scamalytics.status !== 'ok') {
                const cleanIp = ip.replace(/\\[|\\]/g, '');
                return \`<a href="https://cloudflare-scamalytics.pages.dev/\${cleanIp}" target="_blank" rel="noopener noreferrer" class="risk-link-button">Click Here</a>\`;
            }
            const score = riskData.scamalytics.scamalytics_score;
            const risk = riskData.scamalytics.scamalytics_risk;
            const normRisk = (risk || '').toLowerCase().replace(/_/g, ' ').trim();
            let badgeClass = 'info';
            if (normRisk === 'low') badgeClass = 'success';
            else if (normRisk === 'medium') badgeClass = 'warning';
            else if (normRisk === 'very high') badgeClass = 'critical';
            else if (normRisk === 'high') badgeClass = 'error';
            return \`<span class="badge \${badgeClass}">\${risk} (Score: \${score})</span>\`;
        }

        function renderAllResults() {
            const container = document.getElementById('results-container');
            successfulIPs.sort((a, b) => (a.risk?.scamalytics?.scamalytics_score ?? 999) - (b.risk?.scamalytics?.scamalytics_score ?? 999));
            
            if (successfulIPs.length > 0) {
                 container.innerHTML = ''; 
                 successfulIPs.forEach(item => {
                    const riskText = formatRiskBadge(item.risk, item.ip);
                    const pingText = item.ping ? \`<span class="detail-chip">⚡️ \${item.ping}ms</span>\` : '';
                    const geoText = item.info ? \`<span class="detail-chip">\${item.info.country || 'N/A'}\${item.info.as ? ' · ' + item.info.as.substring(0, 25) : ''}</span>\` : '';
                    const itemHTML = \`<div class="ip-item">\` + 
                                     \`<div><span class="ip-tag" onclick="copyToClipboard('\${item.ip}', this)">\${item.ip}</span></div>\` +
                                     \`<span class="ip-details">\${riskText}\${pingText}\${geoText}</span></div>\`;
                    container.insertAdjacentHTML('beforeend', itemHTML);
                 });
            } else if (checkedCount >= ipsToCheck.length) {
                 container.innerHTML = '<p style="text-align:center;">No successful proxies found.</p>';
            }
        }

        function renderFailedResults() {
            const details = document.getElementById('failed-details');
            const list = document.getElementById('failed-list');
            const countEl = document.getElementById('failed-count');
            countEl.textContent = failedIPs.length;
            if (failedIPs.length === 0) {
                details.style.display = 'none';
                list.innerHTML = '';
                return;
            }
            details.style.display = '';
            list.innerHTML = failedIPs.slice().sort((a,b)=>(a.error||'').length-(b.error||'').length).map(f => \`<span class="failed-item"><span onclick="copyToClipboard('\${f.ip}', this)" style="cursor:pointer;">\${f.ip}</span><span class="fail-reason" title="\${(f.error||'').replace(/"/g,'&quot;')}">\${f.error || 'Failed'}</span></span>\`).join('');
        }
        
        function updateSummary() {
            document.getElementById('summary').textContent = \`Checked: \${checkedCount} / \${ipsToCheck.length} | Successful: \${successfulIPs.length} | Failed: \${failedIPs.length}\`;
        }
        
        function loadSavedResults() {
            try {
                const savedJSON = localStorage.getItem(storageKey);
                if (!savedJSON) return;
                const cachedData = JSON.parse(savedJSON);

                if (pageType === 'file' && contentHash && cachedData.hash !== contentHash) {
                    localStorage.removeItem(storageKey);
                    showToast('File content has changed. Starting fresh check.');
                    return;
                }

                allResults = cachedData.results || {};
                for(const ip in allResults) {
                    if(allResults[ip].success) {
                        const resultItem = { ip: ip, ...allResults[ip] };
                        successfulIPs.push(resultItem);
                    } else {
                        failedIPs.push({ ip: ip, error: allResults[ip].error || 'Not a valid proxy' });
                    }
                }
                checkedCount = Object.keys(allResults).length;
                if(successfulIPs.length > 0) renderAllResults();
                renderFailedResults();
                updateSummary();
            } catch(e) { console.error("Error loading from cache", e); allResults = {}; }
        }

        async function startChecking() {
            document.title = \`Checking \${ipsToCheck.length} IPs...\`;
            
            loadSavedResults();

            const ipsToActuallyTest = ipsToCheck.filter(ip => !allResults[ip]);
            if (ipsToActuallyTest.length === 0 && ipsToCheck.length > 0) {
                 document.getElementById('summary').textContent += ' (All IPs loaded from cache)';
                 if(successfulIPs.length === 0) document.getElementById('results-container').innerHTML = '<p style="text-align:center;">No successful proxies found.</p>';
            }

            const batchSize = 20;
            for (let i = 0; i < ipsToActuallyTest.length; i += batchSize) {
                const batch = ipsToActuallyTest.slice(i, i + batchSize);
                const promises = batch.map(async (ip) => {
                    try {
                        const checkData = await fetchAPI('/check', new URLSearchParams({ proxyip: ip }));
                        let riskData = { scamalytics: { status: 'fail' }};
                        if(checkData.success) {
                             riskData = await fetchAPI('/scamalytics-lookup', new URLSearchParams({ ip: checkData.proxyIP }));
                        }
                        
                        allResults[ip] = { success: checkData.success, ping: checkData.ping, info: checkData.info, risk: riskData, ip: checkData.proxyIP, error: checkData.error }; 

                        if (checkData.success) {
                            successfulIPs.push({ ip: ip, ...checkData, risk: riskData });
                        } else {
                            failedIPs.push({ ip, error: checkData.error || 'Not a valid proxy' });
                        }
                    } catch (e) {
                        console.error('Failed to check ip:', ip, e);
                        allResults[ip] = { success: false, error: e.message };
                        failedIPs.push({ ip, error: e.message || 'Request failed' });
                    } finally {
                        checkedCount++;
                        schedulePersist();
                    }
                });
                await Promise.allSettled(promises);
                persistResultsNow();
                updateSummary();
                renderFailedResults();
            }

            renderAllResults(); 
            renderFailedResults();

            document.title = \`\${successfulIPs.length} Successful IPs Found\`;
            const actionContainer = document.getElementById('action-buttons-container');
            if (successfulIPs.length > 0) {
                 let downloadButton = '';
                 const successfulIPsText = successfulIPs.map(i=>i.ip).join('\\n');
                 if (pageType === 'file') {
                    const dataUrl = \`data:text/plain;charset=utf-8;base64,\${btoa(unescape(encodeURIComponent(successfulIPsText)))}\`;
                    downloadButton = \`<a href="\${dataUrl}" download="successful_ips.txt" class="btn btn-secondary">📥 Download Results</a>\`;
                 }
                 actionContainer.innerHTML = \`<div class="action-buttons">\${downloadButton}<button class="btn btn-primary" onclick='copyToClipboard(\${JSON.stringify(successfulIPsText)})'>📋 Copy All</button></div>\`;
            }
        }
        
        document.addEventListener('DOMContentLoaded', () => {
            if (localStorage.getItem('theme') === 'dark' || (!('theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
                 document.body.classList.add('dark-mode');
            }
            startChecking();
        });
    </script>
</body>
</html>`;
}

const CLIENT_SCRIPT = `
    let isChecking = false;
    let TEMP_TOKEN = '';
    let currentSuccessfulRangeIPs = [];
    let currentFailedRangeIPs = [];

    document.addEventListener('DOMContentLoaded', () => {
        fetch('/api/get-token').then(res => res.json()).then(data => { TEMP_TOKEN = data.token; });
        document.getElementById('checkBtn').addEventListener('click', checkInputs);
        
        document.getElementById('copyRangeBtn').addEventListener('click', () => {
            if (currentSuccessfulRangeIPs.length > 0) {
                const textToCopy = currentSuccessfulRangeIPs.map(item => item.ip).join('\\n');
                copyToClipboard(textToCopy, document.getElementById('copyRangeBtn'), "All successful IPs copied!");
            }
        });

        document.body.addEventListener('click', event => {
            const target = event.target;
            if (target.classList.contains('copy-btn') || target.classList.contains('ip-tag') || target.classList.contains('range-tag')) {
                const text = target.getAttribute('data-copy') || target.textContent;
                if (text) copyToClipboard(text, target);
            }
        });
        
        const drawerToggle = document.getElementById('drawer-toggle');
        const drawerContent = document.getElementById('drawer-content');
        if (drawerToggle && drawerContent) {
            drawerToggle.addEventListener('click', () => {
                drawerContent.classList.toggle('visible');
                drawerToggle.classList.toggle('active');
            });
        }

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
        }).catch(err => { showToast('Copy failed.'); console.error(err); });
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
        const fullPathWithParams = '/api' + path + '?' + params.toString();

        let lastError;
        for (let attempt = 1; attempt <= 3; attempt++) {
            try {
                const response = await fetch(fullPathWithParams);
                return await response.json();
            } catch (e) {
                lastError = e;
                const isNetworkFailure = e instanceof TypeError || /failed to fetch|networkerror|load failed/i.test(e.message || '');
                if (!isNetworkFailure || attempt === 3) throw e;
                await new Promise(r => setTimeout(r, 500 * attempt));
            }
        }
        throw lastError;
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
    
    function formatRiskBadge(riskData, ip) {
        if (!riskData || !riskData.scamalytics || riskData.scamalytics.status !== 'ok') {
            const cleanIp = ip.replace(/\\[|\\]/g, '');
            return \`<a href="https://cloudflare-scamalytics.pages.dev/\${cleanIp}" target="_blank" rel="noopener noreferrer" class="risk-link-button">Click Here</a>\`;
        }
        const score = riskData.scamalytics.scamalytics_score;
        const risk = riskData.scamalytics.scamalytics_risk;
        const normRisk = (risk || '').toLowerCase().replace(/_/g, ' ').trim();
        let badgeClass = 'info';
        if (normRisk === 'low') badgeClass = 'success';
        else if (normRisk === 'medium') badgeClass = 'warning';
        else if (normRisk === 'very high') badgeClass = 'critical';
        else if (normRisk === 'high') badgeClass = 'error';
        return \`<span class="badge \${badgeClass}">\${risk} (Score: \${score})</span>\`;
    }

    function simpleHash(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) hash = ((hash << 5) - hash + str.charCodeAt(i)) | 0;
        return (hash >>> 0).toString(36);
    }
    function loadCachedResults(storageKey) {
        try {
            const saved = localStorage.getItem(storageKey);
            if (saved) return JSON.parse(saved).results || {};
        } catch(e) { console.error('Error loading cached results', e); }
        return {};
    }
    const activePersisters = [];
    window.addEventListener('pagehide', () => activePersisters.forEach(p => p.flush()));
    window.addEventListener('beforeunload', () => activePersisters.forEach(p => p.flush()));
    document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden') activePersisters.forEach(p => p.flush()); });
    function makePersister(storageKey, getResults) {
        let timer = null;
        const persister = {
            flush: () => {
                if (timer) { clearTimeout(timer); timer = null; }
                try { localStorage.setItem(storageKey, JSON.stringify({ results: getResults() })); }
                catch(e) { console.error('Failed to persist results cache', e); }
            },
            schedule: () => { if (!timer) timer = setTimeout(persister.flush, 350); }
        };
        activePersisters.push(persister);
        return persister;
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

        try {
            if (mainInputs.length === 1 && rangeInputs.length === 0) {
                const singleInput = mainInputs[0];
                if (isDomain(singleInput)) await checkAndDisplayDomain_graphical(singleInput);
                else await checkAndDisplaySingleIP_graphical(singleInput);
            } else if (mainInputs.length > 0) {
                await processMultipleInputs(mainInputs);
            }
            
            if (rangeInputs.length > 0) {
                 await processRangeInputs(rangeInputs);
            }
        } catch (e) {
            console.error(e);
            showToast("An unexpected error occurred.");
        } finally {
            toggleCheckButton(false);
        }
    }
    
    async function checkAndDisplaySingleIP_graphical(proxyip) {
        const resultDiv = document.getElementById('result');
        resultDiv.innerHTML = '<div class="result-card"><p style="text-align:center;">Checking...</p></div>';
        try {
            const data = await fetchAPI('/check', new URLSearchParams({ proxyip }));
            const resultCard = resultDiv.firstChild;
            if (data.success) {
                const riskData = await fetchAPI('/scamalytics-lookup', new URLSearchParams({ ip: data.proxyIP }));
                resultCard.className = 'result-card result-success';
                resultCard.innerHTML = \`
                    <h3>✅ Valid Proxy IP</h3>
                    <div class="result-item"><strong>IP Address:</strong><span class="value"><span class="ip-tag" data-copy="\${data.proxyIP}">\${data.proxyIP}</span></span></div>
                    <div class="result-item"><strong>⚡️ Ping:</strong><span class="value">\${data.ping !== undefined ? data.ping + ' ms' : 'N/A'}</span></div>
                    <div class="result-item"><strong>⚠️ Risk:</strong><span class="value">\${formatRiskBadge(riskData, data.proxyIP)}</span></div>
                    <div class="result-item"><strong>🌍 Country:</strong><span class="value">\${data.info.country || 'N/A'}</span></div>
                    <div class="result-item"><strong>🌐 AS:</strong><span class="value">\${data.info.as || 'N/A'}</span></div>
                    <div class="result-item"><strong>🔌 Port:</strong><span class="value">\${data.portRemote}</span></div>
                \`;
            } else {
                resultCard.className = 'result-card result-error';
                resultCard.innerHTML = \`
                    <h3>❌ Invalid Proxy IP</h3>
                    <div class="result-item"><strong>IP Address:</strong><span class="value"><span class="ip-tag" data-copy="\${proxyip}">\${proxyip}</span></span></div>
                    <div class="result-item"><strong>Error:</strong><span class="value">\${data.error || 'Check failed.'}</span></div>
                \`;
            }
        } catch (error) {
            resultDiv.innerHTML = \`<div class="result-card result-error"><h3>❌ Error</h3><p>\${error.message}</p></div>\`;
        }
    }
    
    async function checkAndDisplayDomain_graphical(domain) {
        const resultDiv = document.getElementById('result');
        resultDiv.innerHTML = '<div class="result-card"><p style="text-align:center;">Resolving & Checking...</p></div>';
        const resultCard = resultDiv.firstChild;

        try {
            resultCard.className = 'result-card';
            const resolveData = await fetchAPI('/resolve', new URLSearchParams({ domain }));
            if (!resolveData.success || !resolveData.ips || resolveData.ips.length === 0) {
                throw new Error(resolveData.error || 'Could not resolve domain.');
            }
            const ips = resolveData.ips;
            resultCard.innerHTML = \`
                <h3>Checking \${ips.length} IPs for \${domain}</h3>
                <div class="domain-ip-list"></div>
            \`;
            const ipListDiv = resultCard.querySelector('.domain-ip-list');
            ipListDiv.innerHTML = '<p style="text-align:center;">Checking IPs...</p>';

            const storageKey = 'proxy_domain_' + simpleHash(domain);
            const cachedResults = loadCachedResults(storageKey);
            const persister = makePersister(storageKey, () => cachedResults);

            const checkPromises = ips.map(async (ip) => {
                if (cachedResults[ip]) {
                    const c = cachedResults[ip];
                    if (c.success) return { ok: true, proxyIP: c.proxyIP || ip, ping: c.ping, info: c.info, risk: c.risk, portRemote: c.portRemote };
                    return { ok: false, ip, error: c.error || 'Not a valid proxy' };
                }
                try {
                    const checkData = await fetchAPI('/check', new URLSearchParams({ proxyip: ip }));
                    if(checkData.success) {
                        const riskData = await fetchAPI('/scamalytics-lookup', new URLSearchParams({ ip: checkData.proxyIP }));
                        cachedResults[ip] = { success: true, proxyIP: checkData.proxyIP, ping: checkData.ping, info: checkData.info, risk: riskData, portRemote: checkData.portRemote };
                        persister.schedule();
                        return { ok: true, ...checkData, risk: riskData };
                    }
                    cachedResults[ip] = { success: false, error: checkData.error || 'Not a valid proxy' };
                    persister.schedule();
                    return { ok: false, ip, error: checkData.error || 'Not a valid proxy' };
                } catch (e) {
                    cachedResults[ip] = { success: false, error: e.message || 'Request failed' };
                    persister.schedule();
                    return { ok: false, ip, error: e.message || 'Request failed' };
                }
            });

            const allChecked = await Promise.all(checkPromises);
            persister.flush();
            const results = allChecked.filter(r => r.ok);
            const failed = allChecked.filter(r => !r.ok);
            
            results.sort((a, b) => (a.risk.scamalytics.scamalytics_score ?? 999) - (b.risk.scamalytics.scamalytics_score ?? 999));
            
            ipListDiv.innerHTML = ''; 

            results.forEach(item => {
                 const pingText = item.ping ? \`<span class="detail-chip">⚡️\${item.ping}ms</span>\` : '';
                 const riskDetails = formatRiskBadge(item.risk, item.proxyIP);
                 const geoText = \`<span class="detail-chip">\${item.info.country || 'N/A'}\${item.info.as ? ' · ' + item.info.as.substring(0,20) : ''}</span>\`;
                 const ipItem = document.createElement('div');
                 ipItem.className = 'ip-item-multi';
                 ipItem.innerHTML = \`<div><span class="ip-tag" data-copy="\${item.proxyIP}">\${item.proxyIP}</span></div><span class="ip-details">\${riskDetails}\${pingText}\${geoText}</span>\`;
                 ipListDiv.appendChild(ipItem);
            });

            if (failed.length > 0) {
                const failedHTML = \`<details class="failed-details" open style="margin-top:15px;"><summary>❌ Failed IPs (\${failed.length})</summary><div class="failed-list">\${failed.slice().sort((a,b)=>(a.error||'').length-(b.error||'').length).map(f => \`<span class="failed-item"><span onclick="copyToClipboard('\${f.ip}', this)" style="cursor:pointer;">\${f.ip}</span><span class="fail-reason" title="\${(f.error||'').replace(/"/g,'&quot;')}">\${f.error || 'Failed'}</span></span>\`).join('')}</div></details>\`;
                ipListDiv.insertAdjacentHTML('afterend', failedHTML);
            }
            
            resultCard.classList.add(results.length > 0 ? 'result-success' : 'result-error');
            resultCard.querySelector('h3').innerHTML = \`\${results.length > 0 ? '✅' : '❌'} \${results.length} of \${ips.length} IPs are valid for \${domain}\`;

            if (results.length > 0) {
                const textToCopy = results.map(i => i.proxyIP).join('\\n');
                const actionButtonHTML = \`<div class="action-buttons"><button class="btn btn-primary" onclick='copyToClipboard(\${JSON.stringify(textToCopy)})'>📋 Copy All Successful IPs</button></div>\`;
                resultCard.insertAdjacentHTML('beforeend', actionButtonHTML);
            }

        } catch (error) {
            resultCard.className = 'result-card result-error';
            resultCard.innerHTML = \`<h3>❌ Error</h3><p>\${error.message}</p>\`;
        }
    }
    
    async function processMultipleInputs(mainInputs) {
        const resultDiv = document.getElementById('result');
        resultDiv.innerHTML = '<div class="result-card"><p style="text-align:center; padding: 20px;">Processing...</p></div>';
        
        const mainCard = resultDiv.querySelector('.result-card');
        
        const domains = mainInputs.filter(isDomain);
        const directIPs = mainInputs.filter(ip => !isDomain(ip));
        const numberEmojis = ['0️⃣', '1️⃣', '2️⃣', '3️⃣', '4️⃣', '5️⃣', '6️⃣', '7️⃣', '8️⃣', '9️⃣'];
        const formatNumber = (n) => (n).toString().split('').map(digit => numberEmojis[parseInt(digit)]).join('');
        
        let allIPsToTest = directIPs.map(ip => ({ ip, domainIndex: -1 })); 
        
        let domainListHTML = '';
        if (domains.length > 0) {
            domainListHTML = '<h2>Domains to Check</h2>';
            domains.forEach((d, i) => {
                domainListHTML += \`<p style="margin: 0; margin-bottom: 5px;">\${formatNumber(i + 1)} <span class="copy-btn" data-copy="\${d}">\${d}</span></p>\`;
            });
        }
        mainCard.innerHTML = domainListHTML + (domains.length > 0 ? '<hr style="margin: 15px 0;">' : '') + '<div id="multi-ip-list" class="domain-ip-list"><p style="text-align:center;">Resolving and preparing IP list...</p></div>';
        
        const resolvePromises = domains.map(async (domain, index) => {
            try {
                const resolveData = await fetchAPI('/resolve', new URLSearchParams({ domain }));
                if (resolveData.success) {
                    resolveData.ips.forEach(ip => allIPsToTest.push({ ip, domainIndex: index }));
                }
            } catch (e) { console.error("Failed to resolve", domain, e); }
        });
        await Promise.allSettled(resolvePromises);
        
        allIPsToTest = [...new Map(allIPsToTest.map(item => [item.ip, item])).values()];
        
        const ipListContainer = document.getElementById('multi-ip-list');
        ipListContainer.innerHTML = '<p style="text-align:center;">Checking all IPs...</p>';
        
        const storageKey = 'proxy_multi_' + simpleHash(mainInputs.slice().sort().join(','));
        const cachedResults = loadCachedResults(storageKey);
        const persister = makePersister(storageKey, () => cachedResults);

        const checkPromises = allIPsToTest.map(async (ipObject) => {
            if (cachedResults[ipObject.ip]) {
                const c = cachedResults[ipObject.ip];
                if (c.success) return { ok: true, proxyIP: c.proxyIP || ipObject.ip, ping: c.ping, info: c.info, risk: c.risk, portRemote: c.portRemote, domainIndex: ipObject.domainIndex };
                return { ok: false, ip: ipObject.ip, error: c.error || 'Not a valid proxy' };
            }
            try {
                const checkData = await fetchAPI('/check', new URLSearchParams({ proxyip: ipObject.ip }));
                if (checkData.success) {
                    const riskData = await fetchAPI('/scamalytics-lookup', new URLSearchParams({ ip: checkData.proxyIP }));
                    cachedResults[ipObject.ip] = { success: true, proxyIP: checkData.proxyIP, ping: checkData.ping, info: checkData.info, risk: riskData, portRemote: checkData.portRemote };
                    persister.schedule();
                    return { ok: true, ...checkData, risk: riskData, domainIndex: ipObject.domainIndex };
                }
                cachedResults[ipObject.ip] = { success: false, error: checkData.error || 'Not a valid proxy' };
                persister.schedule();
                return { ok: false, ip: ipObject.ip, error: checkData.error || 'Not a valid proxy' };
            } catch (e) {
                cachedResults[ipObject.ip] = { success: false, error: e.message || 'Request failed' };
                persister.schedule();
                return { ok: false, ip: ipObject.ip, error: e.message || 'Request failed' };
            }
        });

        const allChecked = await Promise.all(checkPromises);
        persister.flush();
        let successfulIPs = allChecked.filter(r => r.ok);
        const failedIPs = allChecked.filter(r => !r.ok);
        successfulIPs.sort((a, b) => (a.risk.scamalytics.scamalytics_score ?? 999) - (b.risk.scamalytics.scamalytics_score ?? 999));

        if (successfulIPs.length > 0) {
            ipListContainer.innerHTML = '<h2>Successful IPs</h2>' + successfulIPs.map(item => {
                const geoDetails = \`<span class="detail-chip">\${item.info.country || 'N/A'}\${item.info.as ? ' · ' + item.info.as.substring(0, 20) : ''}</span>\`;
                const riskDetails = formatRiskBadge(item.risk, item.proxyIP);
                const pingText = item.ping ? \`<span class="detail-chip">⚡️\${item.ping}ms</span>\` : '';
                const prefix = item.domainIndex > -1 ? \`\${formatNumber(item.domainIndex + 1)} \` : '';
                return \`<div class="ip-item-multi"><div>\${prefix}<span class="ip-tag" data-copy="\${item.proxyIP}">\${item.proxyIP}</span></div><span class="ip-details">\${riskDetails}\${pingText}\${geoDetails}</span></div>\`;
            }).join('');
        } else {
            ipListContainer.innerHTML = '<p>No valid proxies found.</p>';
        }

        if (failedIPs.length > 0) {
            const failedHTML = \`<details class="failed-details" open style="margin-top:15px;"><summary>❌ Failed IPs (\${failedIPs.length})</summary><div class="failed-list">\${failedIPs.slice().sort((a,b)=>(a.error||'').length-(b.error||'').length).map(f => \`<span class="failed-item"><span onclick="copyToClipboard('\${f.ip}', this)" style="cursor:pointer;">\${f.ip}</span><span class="fail-reason" title="\${(f.error||'').replace(/"/g,'&quot;')}">\${f.error || 'Failed'}</span></span>\`).join('')}</div></details>\`;
            mainCard.insertAdjacentHTML('beforeend', failedHTML);
        }

        if (successfulIPs.length > 0) {
            const textToCopy = successfulIPs.map(i => i.proxyIP).join('\\n');
            const actionButtonHTML = \`<div class="action-buttons"><button class="btn btn-primary" onclick='copyToClipboard(\${JSON.stringify(textToCopy)})'>📋 Copy All Successful IPs</button></div>\`;
            mainCard.insertAdjacentHTML('beforeend', actionButtonHTML);
        }
    }
    
    async function processRangeInputs(rangeInputs) {
        const rangeResultCard = document.getElementById('rangeResultCard');
        const summaryDiv = document.getElementById('rangeResultSummary');
        const listDiv = document.getElementById('successfulRangeIPsList');
        const copyBtn = document.getElementById('copyRangeBtn');
        
        rangeResultCard.style.display = 'block';
        rangeResultCard.className = 'result-card result-section';
        listDiv.innerHTML = '<p style="text-align:center;">Processing...</p>';
        summaryDiv.innerHTML = 'Total Tested: 0 | Total Successful: 0';
        copyBtn.style.display = 'none';
        currentSuccessfulRangeIPs = [];
        currentFailedRangeIPs = [];
        
        const allIPsToTest = [...new Set(rangeInputs.flatMap(parseIPRange))];
        if (allIPsToTest.length === 0) {
            summaryDiv.innerHTML = 'Invalid range format provided.';
            listDiv.innerHTML = '';
            return;
        }

        const storageKey = 'proxy_range_' + simpleHash(rangeInputs.slice().sort().join(','));
        const cachedResults = loadCachedResults(storageKey);
        const persister = makePersister(storageKey, () => cachedResults);

        let checkedCount = 0;
        for (const ip of allIPsToTest) {
            const c = cachedResults[ip];
            if (!c) continue;
            checkedCount++;
            if (c.success) currentSuccessfulRangeIPs.push({ ip: c.proxyIP || ip, ...c });
            else currentFailedRangeIPs.push({ ip, error: c.error || 'Not a valid proxy' });
        }
        if (checkedCount > 0) {
            updateSuccessfulRangeIPsDisplay();
            updateFailedRangeIPsDisplay();
            summaryDiv.innerHTML = \`Tested: \${checkedCount}/\${allIPsToTest.length} | Successful: \${currentSuccessfulRangeIPs.length} | Failed: \${currentFailedRangeIPs.length} (resumed from cache)\`;
        }
        const ipsToActuallyTest = allIPsToTest.filter(ip => !cachedResults[ip]);

        const batchSize = 20;

        for (let i = 0; i < ipsToActuallyTest.length; i += batchSize) {
            const batch = ipsToActuallyTest.slice(i, i + batchSize);
            const batchPromises = batch.map(async ip => {
                try {
                    const data = await fetchAPI('/check', new URLSearchParams({ proxyip: ip }));
                    if (data.success) {
                        const riskData = await fetchAPI('/scamalytics-lookup', new URLSearchParams({ ip: data.proxyIP }));
                        cachedResults[ip] = { success: true, proxyIP: data.proxyIP, ping: data.ping, info: data.info, risk: riskData, portRemote: data.portRemote };
                        currentSuccessfulRangeIPs.push({ ip: data.proxyIP, ...data, risk: riskData });
                    } else {
                        cachedResults[ip] = { success: false, error: data.error || 'Not a valid proxy' };
                        currentFailedRangeIPs.push({ ip, error: data.error || 'Not a valid proxy' });
                    }
                } catch (e) {
                    cachedResults[ip] = { success: false, error: e.message || 'Request failed' };
                    currentFailedRangeIPs.push({ ip, error: e.message || 'Request failed' });
                }
                checkedCount++;
                persister.schedule();
            });
            await Promise.all(batchPromises);
            persister.flush();
            summaryDiv.innerHTML = \`Tested: \${checkedCount}/\${allIPsToTest.length} | Successful: \${currentSuccessfulRangeIPs.length} | Failed: \${currentFailedRangeIPs.length}\`;
            updateSuccessfulRangeIPsDisplay();
            updateFailedRangeIPsDisplay();
        }
        
        if (currentSuccessfulRangeIPs.length > 0) copyBtn.style.display = 'inline-block';
    }

    function updateSuccessfulRangeIPsDisplay() {
        const listDiv = document.getElementById('successfulRangeIPsList');
        currentSuccessfulRangeIPs.sort((a,b) => (a.risk.scamalytics.scamalytics_score ?? 999) - (b.risk.scamalytics.scamalytics_score ?? 999));
        
        if (currentSuccessfulRangeIPs.length === 0) {
            listDiv.innerHTML = '<p style="text-align:center; color: var(--text-light);">No successful IPs found in range(s).</p>';
            return;
        }
        listDiv.innerHTML = currentSuccessfulRangeIPs.map(item => {
            const pingText = item.ping ? \`<span class="detail-chip">⚡️\${item.ping}ms</span>\` : '';
            const riskDetails = formatRiskBadge(item.risk, item.ip);
            const countryChip = item.info.countryCode ? \`<span class="detail-chip">\${item.info.countryCode}</span>\` : '';
            return \`<div class="ip-item-multi">
                <div><span class="ip-tag" data-copy="\${item.ip}">\${item.ip}</span></div>
                <span class="ip-details">\${riskDetails}\${pingText}\${countryChip}</span>
            </div>\`
        }).join('');
    }

    function updateFailedRangeIPsDisplay() {
        const details = document.getElementById('rangeFailedDetails');
        const list = document.getElementById('rangeFailedList');
        const countEl = document.getElementById('rangeFailedCount');
        countEl.textContent = currentFailedRangeIPs.length;
        if (currentFailedRangeIPs.length === 0) {
            details.style.display = 'none';
            list.innerHTML = '';
            return;
        }
        details.style.display = '';
        list.innerHTML = currentFailedRangeIPs.slice().sort((a,b)=>(a.error||'').length-(b.error||'').length).map(f => \`<span class="failed-item"><span onclick="copyToClipboard('\${f.ip}', this)" style="cursor:pointer;">\${f.ip}</span><span class="fail-reason" title="\${(f.error||'').replace(/"/g,'&quot;')}">\${f.error || 'Failed'}</span></span>\`).join('');
    }
`;

function generateMainHTML(faviconURL) {
  const year = new Date().getFullYear();
  const countries = {
    'ALL': 'All Countries', 'AE': 'United Arab Emirates', 'AL': 'Albania', 'AM': 'Armenia', 'AR': 'Argentina', 'AT': 'Austria', 'AU': 'Australia', 'AZ': 'Azerbaijan', 'BE': 'Belgium', 'BG': 'Bulgaria', 'BR': 'Brazil', 'CA': 'Canada', 'CH': 'Switzerland', 'CN': 'China', 'CO': 'Colombia', 'CY': 'Cyprus', 'CZ': 'Czech Republic', 'DE': 'Germany', 'DK': 'Denmark', 'EE': 'Estonia', 'ES': 'Spain', 'FI': 'Finland', 'FR': 'France', 'GB': 'United Kingdom', 'GI': 'Gibraltar', 'HK': 'Hong Kong', 'HU': 'Hungary', 'ID': 'Indonesia', 'IE': 'Ireland', 'IL': 'Israel', 'IN': 'India', 'IR': 'Iran', 'IT': 'Italy', 'JP': 'Japan', 'KR': 'South Korea', 'KZ': 'Kazakhstan', 'LT': 'Lithuania', 'LU': 'Luxembourg', 'LV': 'Latvia', 'MD': 'Moldova', 'MX': 'Mexico', 'MY': 'Malaysia', 'NL': 'Netherlands', 'NZ': 'New Zealand', 'PH': 'Philippines', 'PL': 'Poland', 'PR': 'Puerto Rico', 'PT': 'Portugal', 'QA': 'Qatar', 'RO': 'Romania', 'RS': 'Serbia', 'RU': 'Russia', 'SA': 'Saudi Arabia', 'SC': 'Seychelles', 'SE': 'Sweden', 'SG': 'Singapore', 'SK': 'Slovakia', 'TH': 'Thailand', 'TR': 'Turkey', 'TW': 'Taiwan', 'UA': 'Ukraine', 'US': 'United States', 'UZ': 'Uzbekistan', 'VN': 'Vietnam'
  };

  const allCountriesButtonImage = 'https://raw.githubusercontent.com/mehdi-hexing/Get-Github-Achievements/main/527112cc-4097-432b-b30c-0b9657451c5f.jpg';
  const allCountriesURL = `https://raw.githubusercontent.com/NiREvil/vless/main/sub/country_proxies/02_proxies.csv`;
  const countryFileBaseURL = `https://raw.githubusercontent.com/NiREvil/vless/main/sub/country_proxies/`;

  let countryButtonsHTML = `
    <div class="country-item">
        <a href="/file/${encodeURIComponent(allCountriesURL)}" class="country-button" style="background-image: url('${allCountriesButtonImage}');"></a>
        <p class="country-name">${countries['ALL']}</p>
    </div>
  `;
  
  for (const code in countries) {
      if (code === 'ALL') continue;
      const fileUrl = `${countryFileBaseURL}${code.toUpperCase()}.txt`;
      countryButtonsHTML += `
        <div class="country-item">
            <a href="/file/${encodeURIComponent(fileUrl)}" class="country-button" style="background-image: url('https://flagcdn.com/${code.toLowerCase()}.svg');"></a>
            <p class="country-name">${countries[code]}</p>
        </div>
      `;
  }
  
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
    :root{--bg-gradient:linear-gradient(160deg,#f6f8fa 0%,#eaeef2 55%,#e6ecf1 100%);--bg-primary:#ffffff;--bg-secondary:#f6f8fa;--text-primary:#1f2328;--text-light:#656d76;--border-color:#d1d9e0;--primary-color:#0969da;--success-color:#1a7f37;--error-color:#d1242f;--warning-color:#9a6700;--result-success-bg:#dafbe1;--result-success-text:#1a7f37;--result-error-bg:#ffebe9;--result-error-text:#d1242f;--result-warning-bg:#fff8c5;--result-warning-text:#9a6700;--border-radius:24px;--border-radius-sm:14px;--bg-primary-rgb:255,255,255;--bg-secondary-rgb:246,248,250;--success-color-rgb:26,127,55;--error-color-rgb:209,36,47;--warning-color-rgb:154,103,0;--critical-color-rgb:102,10,10;--secondary-color-rgb:101,109,118;--primary-color-rgb:9,105,218;--glass-border:rgba(255,255,255,.6);--glass-shadow:0 10px 30px rgba(31,35,40,.10)}body.dark-mode{--bg-gradient:linear-gradient(160deg,#0d1117 0%,#161b22 55%,#10151c 100%);--bg-primary:#161b22;--bg-secondary:#21262d;--text-primary:#e6edf3;--text-light:#8b949e;--border-color:#30363d;--primary-color:#4493f8;--success-color:#3fb950;--error-color:#f85149;--warning-color:#d29922;--result-success-bg:#0f2e1b;--result-success-text:#3fb950;--result-error-bg:#2d1214;--result-error-text:#f85149;--result-warning-bg:#3b2900;--result-warning-text:#d29922;--bg-primary-rgb:22,27,34;--bg-secondary-rgb:33,38,45;--success-color-rgb:63,185,80;--error-color-rgb:248,81,73;--warning-color-rgb:210,153,34;--critical-color-rgb:139,15,15;--secondary-color-rgb:139,148,158;--primary-color-rgb:68,147,248;--glass-border:rgba(255,255,255,.09);--glass-shadow:0 10px 30px rgba(0,0,0,.5)}html{height:100%}body{font-family:'Inter',sans-serif;background:var(--bg-gradient);background-attachment:fixed;color:var(--text-primary);line-height:1.6;margin:0;padding:0;min-height:100%;display:flex;flex-direction:column;align-items:center;transition:background .3s ease,color .3s ease}.container{max-width:800px;width:100%;padding:20px;box-sizing:border-box}.header{text-align:center;margin-bottom:30px}.main-title{font-size:clamp(1.8rem,5vw,2.35rem);font-weight:800;letter-spacing:-.02em;color:var(--text-primary)}body:not(.dark-mode) .main-title{text-shadow:0 1px 0 rgba(255,255,255,.7),0 4px 10px rgba(31,35,40,.15)}body.dark-mode .main-title{text-shadow:0 0 12px rgba(68,147,248,.5),0 0 30px rgba(68,147,248,.28)}.card{background:rgba(var(--bg-primary-rgb),.72);backdrop-filter:blur(24px) saturate(180%);-webkit-backdrop-filter:blur(24px) saturate(180%);border:1px solid var(--glass-border);border-radius:var(--border-radius);padding:25px;box-shadow:var(--glass-shadow);margin-bottom:25px;transition:background .3s ease}.form-section{display:flex;flex-direction:column;align-items:center}.form-label{display:block;font-size:.9rem;font-weight:600;margin-bottom:8px;color:var(--text-primary);width:100%;max-width:450px;text-align:left}.input-wrapper{width:100%;max-width:450px;margin-bottom:15px}.form-input{width:100%;padding:12px;border-radius:var(--border-radius-sm);font-size:.95rem;box-sizing:border-box;background-color:var(--bg-secondary);color:var(--text-primary);transition:box-shadow .3s ease,background-color .3s ease;overflow-wrap:break-word;border:1px solid transparent;box-shadow:inset 0 0 0 1px var(--border-color);resize:none}.btn-primary{background:linear-gradient(135deg,var(--primary-color),#2980b9);color:#fff;padding:12px 25px;border:none;border-radius:var(--border-radius-sm);font-size:1rem;font-weight:500;cursor:pointer;width:100%;max-width:450px;box-sizing:border-box;display:flex;align-items:center;justify-content:center}.btn-primary:disabled{background:#bdc3c7;cursor:not-allowed}.btn-secondary{background:rgba(230,230,230,0.5);color:var(--text-primary);padding:8px 15px;border:1px solid rgba(0,0,0,0.1);border-radius:var(--border-radius-sm);font-size:.9rem;cursor:pointer;backdrop-filter:blur(5px);-webkit-backdrop-filter:blur(5px)}.loading-spinner{width:16px;height:16px;border:2px solid hsla(0,0%,100%,.3);border-top-color:#fff;border-radius:50%;animation:spin 1s linear infinite;display:none;margin-left:8px}@keyframes spin{to{transform:rotate(360deg)}}.result-section{margin-top:25px}.result-card{padding:18px;border-radius:var(--border-radius-sm);margin-bottom:12px;transition:background-color .3s,color .3s,border-color .3s;background-color:rgba(var(--bg-secondary-rgb),.65);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);border:1px solid var(--glass-border)}.result-card h2{margin-top:0;border-bottom:1px solid var(--border-color);padding-bottom:10px;margin-bottom:15px}.domain-card{margin-bottom:20px}.domain-ip-list{border:1px solid var(--border-color);padding:10px;border-radius:var(--border-radius-sm);max-height:250px;overflow-y:auto;margin-top:10px}.result-success{background-color:var(--result-success-bg);border-left:4px solid var(--success-color);color:var(--result-success-text)}.result-error{background-color:var(--result-error-bg);border-left:4px solid var(--error-color);color:var(--result-error-text)}.result-warning{background-color:var(--result-warning-bg);border-left:4px solid #f39c12;color:var(--result-warning-text)}.result-card h3{display:flex;align-items:center;margin-top:0}.result-card h3 .status-icon-prefix{margin-right:8px}.ip-item-multi{display:flex;justify-content:space-between;align-items:center;padding:8px 5px}.ip-item-multi:not(:last-child){border-bottom:1px solid var(--border-color)}.ip-tag{display:inline-flex;align-items:center;height:26px;box-sizing:border-box;background-color:rgba(var(--bg-primary-rgb),.8);backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);padding:0 10px;border-radius:9px;border:1px solid var(--glass-border);font-family:'SF Mono','Courier New',Courier,monospace;font-size:.85rem;cursor:pointer;word-break:break-all;white-space:nowrap;}.ip-details{display:flex;flex-wrap:wrap;align-items:center;justify-content:flex-end;gap:6px;font-size:.875rem;color:var(--text-light);padding-left:15px;flex:1 1 auto;}.detail-chip{display:inline-flex;align-items:center;justify-content:center;gap:3px;white-space:nowrap;height:22px;box-sizing:border-box;padding:0 .6em;border-radius:8px;background-color:rgba(var(--secondary-color-rgb,150,150,150),.12);border:1px solid rgba(var(--secondary-color-rgb,150,150,150),.18);backdrop-filter:blur(4px);-webkit-backdrop-filter:blur(4px)}.copy-btn{cursor:pointer;font-weight:600}.action-buttons{margin-top:20px;display:flex;justify-content:center}.toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%);background:#333;color:#fff;padding:12px 20px;border-radius:var(--border-radius-sm);z-index:1001;opacity:0;transition:opacity .3s,transform .3s}.toast.show{opacity:1}.api-docs{margin-top:30px;padding:25px;background:rgba(var(--bg-primary-rgb),.7);backdrop-filter:blur(20px) saturate(160%);-webkit-backdrop-filter:blur(20px) saturate(160%);border:1px solid var(--glass-border);border-radius:var(--border-radius);box-shadow:var(--glass-shadow);transition:background .3s ease}.api-docs p{background-color:rgba(var(--bg-secondary-rgb),.6);border:1px solid var(--glass-border);padding:12px 14px;border-radius:12px;margin-bottom:10px;word-break:break-all;transition:background .3s ease,border-color .3s ease}.api-docs p code{background:none;padding:0}.api-docs p{display:flex;flex-direction:column;gap:4px}.api-docs-label{font-size:.8em;color:var(--text-light);font-weight:500}.footer{text-align:center;padding:20px;margin-top:30px;color:var(--text-light);font-size:.8125rem;border-top:1px solid var(--border-color)}.footer-repo-link{display:inline-flex;align-items:center;gap:4px;color:var(--primary-color);text-decoration:none;font-weight:600;vertical-align:middle}.footer-repo-link:hover{text-decoration:underline}.footer-repo-link svg{width:13px;height:13px}#theme-toggle{position:fixed;bottom:25px;right:25px;z-index:1002;background:var(--bg-primary);border:1px solid var(--border-color);width:48px;height:48px;border-radius:50%;cursor:pointer;display:flex;align-items:center;justify-content:center;padding:0;box-shadow:0 4px 8px rgba(0,0,0,.15);transition:background-color .3s,border-color .3s}#theme-toggle svg{width:24px;height:24px;stroke:var(--text-primary);transition:all .3s ease}body:not(.dark-mode) #theme-toggle .sun-icon{display:block;fill:none}body:not(.dark-mode) #theme-toggle .moon-icon{display:none}body.dark-mode #theme-toggle .sun-icon{display:none}body.dark-mode #theme-toggle .moon-icon{display:block;fill:var(--text-primary);stroke:var(--text-primary)}
    .country-drawer{margin-top:25px;}.drawer-toggle{width:100%;padding:15px;background-color:rgba(var(--bg-secondary-rgb),.6);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);border:1px solid var(--glass-border);border-radius:var(--border-radius-sm);color:var(--text-primary);font-size:1rem;font-weight:600;cursor:pointer;text-align:center;transition:background-color .2s,color .2s;position:relative}.drawer-toggle:hover,.drawer-toggle.active{background-color:var(--primary-color);color:#fff;border-color:var(--primary-color)}.drawer-toggle::after{content:'▼';font-size:.7em;position:absolute;right:20px;top:50%;transform:translateY(-50%) rotate(0);transition:transform .3s ease-in-out}.drawer-toggle.active::after{transform:translateY(-50%) rotate(180deg)}.drawer-content{max-height:0;overflow:hidden;transition:max-height .5s ease-in-out,padding .5s ease-in-out;background:rgba(var(--bg-secondary-rgb),.55);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border:1px solid var(--glass-border);border-radius:var(--border-radius);margin-top:10px;padding:0}.drawer-content.visible{max-height:60vh;overflow-y:auto;padding:20px}.country-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:20px}.country-item{text-align:center}.country-button{display:block;width:100%;padding-top:60%;position:relative;background-size:cover;background-position:center;border:1px solid var(--border-color);border-radius:var(--border-radius-sm);transition:transform .2s,box-shadow .2s;overflow:hidden}.country-button:hover{transform:scale(1.05);box-shadow:0 5px 15px rgba(0,0,0,.1)}.country-name{margin-top:8px;font-size:.8rem;color:var(--text-light);font-weight:500}
    .badge{position:relative;overflow:hidden;isolation:isolate;display:inline-flex;align-items:center;justify-content:center;height:24px;box-sizing:border-box;padding:0 .8em;font-size:.72rem;font-weight:700;line-height:1;letter-spacing:.03em;text-align:center;white-space:nowrap;vertical-align:middle;border-radius:9px;border:1px solid rgba(255,255,255,.35);color:#fff;text-shadow:0 1px 2px rgba(0,0,0,.35);backdrop-filter:blur(14px) saturate(180%);-webkit-backdrop-filter:blur(14px) saturate(180%)}.badge::before{content:'';position:absolute;inset:0;z-index:-1;background:linear-gradient(160deg,rgba(255,255,255,.38),rgba(255,255,255,0) 55%)}.badge.success{background-color:rgba(var(--success-color-rgb),.5);box-shadow:inset 0 1px 0 rgba(255,255,255,.3),0 3px 8px rgba(var(--success-color-rgb),.3)}.badge.error{background-color:rgba(var(--error-color-rgb),.5);box-shadow:inset 0 1px 0 rgba(255,255,255,.3),0 3px 8px rgba(var(--error-color-rgb),.3)}.badge.warning{background-color:rgba(var(--warning-color-rgb),.5);box-shadow:inset 0 1px 0 rgba(255,255,255,.3),0 3px 8px rgba(var(--warning-color-rgb),.28)}.badge.critical{background-color:rgba(var(--critical-color-rgb),.62);border-color:rgba(255,255,255,.2);box-shadow:inset 0 1px 0 rgba(255,255,255,.22),0 3px 10px rgba(var(--critical-color-rgb),.45),0 0 0 1px rgba(0,0,0,.15)}.badge.info{background-color:rgba(var(--secondary-color-rgb),.5);box-shadow:inset 0 1px 0 rgba(255,255,255,.3),0 3px 8px rgba(0,0,0,.12)}
    .risk-link-button{position:relative;overflow:hidden;display:inline-flex;align-items:center;justify-content:center;height:24px;box-sizing:border-box;background-color:rgba(var(--secondary-color-rgb),.82);backdrop-filter:blur(8px) saturate(160%);-webkit-backdrop-filter:blur(8px) saturate(160%);color:#fff;text-shadow:0 1px 1px rgba(0,0,0,.18);padding:0 .8em;font-size:.72rem;font-weight:700;letter-spacing:.03em;border-radius:9px;border:1px solid rgba(255,255,255,.3);box-shadow:inset 0 1px 0 rgba(255,255,255,.3),0 3px 8px rgba(0,0,0,.15);text-decoration:none;transition:opacity .2s,transform .15s}.risk-link-button::before{content:'';position:absolute;inset:0;background:linear-gradient(160deg,rgba(255,255,255,.32),rgba(255,255,255,0) 55%);pointer-events:none}.risk-link-button:hover{opacity:.85;transform:translateY(-1px)}
    .failed-details{margin-top:16px;background-color:rgba(var(--error-color-rgb),.06);border:1px solid var(--glass-border);border-radius:16px;padding:2px 14px;}
    .failed-details summary{cursor:pointer;padding:10px 0;font-size:.85rem;font-weight:600;color:var(--error-color);display:flex;align-items:center;gap:10px;list-style:none}
    .failed-details summary::-webkit-details-marker{display:none}
    .failed-details summary::before{content:'\\25B8';margin-right:2px;opacity:.7;font-size:.8em;transition:transform .2s}
    .failed-details[open] summary::before{transform:rotate(90deg)}
    .failed-list{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:8px;padding:4px 0 14px}
    .failed-item{display:flex;align-items:center;justify-content:space-between;gap:6px;width:100%;min-width:0;box-sizing:border-box;background-color:rgba(var(--bg-secondary-rgb),.75);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);border:1px solid rgba(var(--error-color-rgb),.5);border-radius:9px;padding:4px 9px;font-family:'SF Mono','Courier New',Courier,monospace;font-size:.8rem}
    .failed-item>span:first-child{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:0 0 auto;max-width:70%}
    .failed-item .fail-reason{color:var(--text-light);font-family:-apple-system,BlinkMacSystemFont,sans-serif;font-size:.75em;flex:1 1 auto;min-width:0;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

    .result-item{display:flex;justify-content:flex-start;align-items:flex-start;gap:8px;margin-bottom:10px;line-height:1.5}.result-item strong{flex-shrink:0;white-space:nowrap}.result-item .value{word-break:break-all;min-width:0}
    @media (max-width: 600px){
        .failed-list{grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:6px}
        .failed-item{padding:4px 7px;font-size:.72rem}
        .failed-item .fail-reason{font-size:.7em}
        .ip-item-multi{flex-direction:column;align-items:stretch;gap:8px;padding:12px 5px}
        .ip-details{justify-content:flex-start;padding-left:0}
        .ip-tag{font-size:.8rem}
        .detail-chip{font-size:.8rem}
        .country-grid{grid-template-columns:repeat(auto-fill,minmax(110px,1fr));gap:14px}
        .card,.api-docs{padding:18px}
    }
    @media (max-width: 420px){
        .failed-list{grid-template-columns:1fr}
    }
  </style>
</head>
<body>
  <div class="container">
    <header class="header">
      <h1 class="main-title">Proxy IP Checker</h1>
    </header>
    <div class="card">
      <div class="form-section">
        <label for="proxyip" class="form-label">Enter IPs or Domains (one per line):</label>
        <div class="input-wrapper">
          <textarea id="proxyip" class="form-input" rows="4" placeholder="127.0.0.1:443 or di.nscl.ir" autocomplete="off"></textarea>
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
         <h3 style="font-size:1.15rem; font-weight:700;">Successful IPs in Range</h3>
         <div id="rangeResultSummary" style="margin-bottom: 10px;"></div>
         <div id="successfulRangeIPsList" class="domain-ip-list"></div>
         <button id="copyRangeBtn" class="btn-primary" style="display:none; margin-top: 15px; width: 100%;">Copy Successful IPs</button>
         <details id="rangeFailedDetails" class="failed-details" style="display:none; margin-top:15px;">
            <summary>❌ Failed IPs (<span id="rangeFailedCount">0</span>)</summary>
            <div id="rangeFailedList" class="failed-list"></div>
         </details>
      </div>
    </div>
    <div class="country-drawer">
        <button id="drawer-toggle" class="drawer-toggle">Do You Need ProxyIP? Click Here</button>
        <div id="drawer-content" class="drawer-content">
            <div class="country-grid">
                ${countryButtonsHTML}
            </div>
        </div>
    </div>
    <div class="api-docs">
       <h3 style="margin-bottom:15px; text-align:center; font-size:1.15rem; font-weight:700;">URL PATH Documentation</h3>
       <p><span class="api-docs-label">Check one or more IPs (comma separated)</span><code>/proxyip/127.0.0.1:443,192.168.1.1:8443</code></p>
       <p><span class="api-docs-label">Check an IP range or CIDR block</span><code>/iprange/127.0.0.0/24,... or 127.0.0.0-255,...</code></p>
       <p><span class="api-docs-label">Check every IP listed inside a remote file</span><code>/file/https://your.file/ip1.txt or ip1.csv</code></p>
       <p><span class="api-docs-label">Resolve a domain and check every IP behind it</span><code>/domain/domain1.com,domain2.com,...</code></p>
    </div>
    <footer class="footer">
      <p>© ${year} Proxy IP Checker - By <a href="https://github.com/mehdi-hexing/CF-ProxyIPChecker" target="_blank" rel="noopener" class="footer-repo-link"><svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>mehdi-hexing</a></p>
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

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        const UA = request.headers.get('User-Agent') || 'null';
        const hostname = url.hostname;
        
        if (path.toLowerCase().startsWith('/domain/')) {
            const domains_string = decodeURIComponent(path.substring('/domain/'.length));
            const domains = domains_string.split(',').map(s => s.trim()).filter(Boolean);
            if (domains.length === 0) return new Response('No domains provided', { status: 400 });
            
            const timestamp = Math.ceil(new Date().getTime() / (1000 * 60 * 31));
            const temporaryTOKEN = await doubleHash(hostname + timestamp + UA);
            return new Response(generateDomainCheckPageHTML({ domains, temporaryTOKEN }), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
        }
        
        if (path.toLowerCase().startsWith('/file/') || path.toLowerCase().startsWith('/iprange/') || path.toLowerCase().startsWith('/proxyip/')) {
            const timestamp = Math.ceil(new Date().getTime() / (1000 * 60 * 31));
            const temporaryTOKEN = await doubleHash(hostname + timestamp + UA);
            let ipsToCheck = [];
            let options = {};
            let pageType = '';
            let contentHash = '';

            if (path.toLowerCase().startsWith('/proxyip/')) {
                pageType = 'proxyip';
                const ips_string = decodeURIComponent(path.substring('/proxyip/'.length));
                ipsToCheck = ips_string.split(',').map(s => s.trim()).filter(Boolean);
                contentHash = simpleHash(ipsToCheck.join(''));
                options = { title: "Proxy IP's Results:", subtitleLabel: "IPs:", subtitleContent: ips_string };
            } else if (path.toLowerCase().startsWith('/iprange/')) {
                pageType = 'iprange';
                const ranges_string = decodeURIComponent(path.substring('/iprange/'.length));
                ipsToCheck = ranges_string.split(',').flatMap(range => parseIPRangeServer(range.trim()));
                contentHash = simpleHash(ipsToCheck.join(''));
                options = { title: "IP Range's Results:", subtitleLabel: "Range's:", subtitleContent: ranges_string };
            } else { // /file/ path
                pageType = 'file';
                const targetUrl = decodeURIComponent(request.url.substring(request.url.indexOf('/file/') + 6));
                if (!targetUrl || !targetUrl.startsWith('http')) return new Response('Invalid URL', {status: 400});
                 try {
                    const response = await fetch(targetUrl, { headers: {'User-Agent': 'ProxyChecker/1.0'} });
                    if (!response.ok) throw new Error(`Fetch failed: ${response.statusText}`);
                    const text = await response.text();
                    contentHash = simpleHash(text);
                    
                    const foundIPs = [...new Set([...(text.match(forgivingIPv4Regex) || []), ...extractIPv6FromText(text)])];
                    const foundCIDRRanges = text.match(cidrRangeRegex) || [];
                    const foundHyphenatedRanges = text.match(hyphenatedRangeRegex) || [];
                    
                    let processedIPs = foundIPs.filter(ip => {
                        const parts = ip.split(':');
                        return parts.length === 1 || !isNaN(parseInt(parts[parts.length - 1]));
                    });

                    foundCIDRRanges.forEach(range => {
                        processedIPs.push(...parseIPRangeServer(range));
                    });
                    foundHyphenatedRanges.forEach(range => {
                        processedIPs.push(...parseIPRangeServer(range));
                    });

                    ipsToCheck = [...new Set(processedIPs)]; 
                     options = { title: 'File Test Results:', subtitleLabel: 'File Link Address:', subtitleContent: targetUrl };
                } catch(e) {
                    return new Response(`Error processing file: ${e.message}`, { status: 500 });
                }
            }
            return new Response(generateClientSideCheckPageHTML({ ...options, ipsToCheck, temporaryTOKEN, pageType, contentHash }), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
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
                try {
                    const result = await checkProxyIP(proxyIPInput, env);
                    return new Response(JSON.stringify(result), { status: 200, headers: { "Content-Type": "application/json" } });
                } catch (error) {
                    console.error('Unexpected error in /api/check, forcing a direct worker-side TCP check:', error.message);
                    try {
                        const cleanIp = proxyIPInput.replace(/\[|\]/g, '').split(':')[0];
                        const tcpResult = await checkProxyIPTCP(cleanIp, 443);
                        if (tcpResult.success) {
                            const ipInfo = await getIpInfo(cleanIp);
                            return new Response(JSON.stringify({
                                success: true, proxyIP: proxyIPInput, portRemote: 443,
                                ping: tcpResult.ping, timestamp: new Date().toISOString(),
                                info: ipInfo, method: 'TCP Fallback (recovered)'
                            }), { status: 200, headers: { "Content-Type": "application/json" } });
                        }
                        return new Response(JSON.stringify({ success: false, proxyIP: proxyIPInput, error: `Worker-side check failed: ${tcpResult.error || 'Connection failed.'}` }), { status: 200, headers: { "Content-Type": "application/json" } });
                    } catch (fallbackError) {
                        return new Response(JSON.stringify({ success: false, proxyIP: proxyIPInput, error: `Worker-side check failed: ${fallbackError.message}` }), { status: 200, headers: { "Content-Type": "application/json" } });
                    }
                }
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

            if (path.toLowerCase() === '/api/scamalytics-lookup') {
                const ip = url.searchParams.get('ip');
                if (!ip) return new Response(JSON.stringify({ error: 'Missing IP parameter' }), { status: 400, headers: { 'Content-Type': 'application/json' }});

                if (env.SCAMALYTICS_USERNAME && env.SCAMALYTICS_API_KEY) {
                    try {
                        const scamalyticsUrl = `${env.SCAMALYTICS_API_BASE_URL || 'https://api.scamalytics.com'}/${env.SCAMALYTICS_USERNAME}/?key=${env.SCAMALYTICS_API_KEY}&ip=${ip}`;
                        const response = await fetch(scamalyticsUrl);
                        if (response.ok) {
                            const data = await response.json();
                            if (data?.scamalytics?.status === 'ok') {
                                return new Response(JSON.stringify(data), { headers: { "Content-Type": "application/json" } });
                            }
                            console.log('Scamalytics official API returned non-ok status, falling back:', data?.scamalytics?.status);
                        } else {
                            console.log(`Scamalytics official API HTTP ${response.status} (likely quota exceeded), falling back.`);
                        }
                    } catch (error) {
                        console.error('Scamalytics official API request failed, falling back:', error.message);
                    }
                }
                const fallback = await getScamalyticsFallback(ip);
                if (fallback && fallback.info) {
                    const normalized = {
                        scamalytics: {
                            status: 'ok',
                            scamalytics_score: fallback.info.fraud_score,
                            scamalytics_risk: (fallback.info.risk || 'unknown').toLowerCase()
                        },
                        external_datasources: {
                            dbip: {
                                ip_country_name: fallback.details?.country,
                                ip_country_code: fallback.details?.country_code,
                                ip_city: fallback.details?.city,
                                ip_asn: fallback.details?.asn,
                                ip_isp_name: fallback.details?.isp || fallback.details?.organization
                            }
                        },
                        source: 'fallback-mirror'
                    };
                    return new Response(JSON.stringify(normalized), { headers: { "Content-Type": "application/json" } });
                }

                return new Response(JSON.stringify({ scamalytics: { status: 'fail' }, error: 'All risk-scoring sources are currently unavailable.' }), { status: 200, headers: { 'Content-Type': 'application/json' }});
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
