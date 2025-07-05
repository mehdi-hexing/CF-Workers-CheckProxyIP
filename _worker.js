import { connect } from "cloudflare:sockets";

var temporaryTOKEN, permanentTOKEN;

// --- Server-Side Helper Functions ---

async function doubleHash(text) {
  var encoder = new TextEncoder();
  var firstHashBuffer = await crypto.subtle.digest('MD5', encoder.encode(text));
  var firstHashArray = Array.from(new Uint8Array(firstHashBuffer));
  var firstHex = firstHashArray.map(function(byte) { return byte.toString(16).padStart(2, '0'); }).join('');
  var secondHashBuffer = await crypto.subtle.digest('MD5', encoder.encode(firstHex.slice(7, 27)));
  var secondHashArray = Array.from(new Uint8Array(secondHashBuffer));
  var secondHex = secondHashArray.map(function(byte) { return byte.toString(16).padStart(2, '0'); }).join('');
  return secondHex.toLowerCase();
}

async function checkProxyIP(proxyIPWithPort) {
  var portRemote = 443;
  var hostToCheck = proxyIPWithPort;

  if (proxyIPWithPort.includes(':') && !proxyIPWithPort.startsWith('[')) {
    var parts = proxyIPWithPort.split(':');
    if (parts.length === 2 && (parts[0].includes('.') || parts[0].includes(']'))) {
      hostToCheck = parts[0];
      var parsedPort = parseInt(parts[1]);
      if (!isNaN(parsedPort)) {
        portRemote = parsedPort;
      }
    }
  }

  try {
    var tcpSocket = connect({ hostname: hostToCheck, port: portRemote });
    var writer = tcpSocket.writable.getWriter();
    var httpRequest = 'GET /cdn-cgi/trace HTTP/1.1\r\nHost: speed.cloudflare.com\r\nUser-Agent: CheckProxyIP/CloudflareWorker\r\nConnection: close\r\n\r\n';
    await writer.write(new TextEncoder().encode(httpRequest));
    writer.releaseLock();

    var reader = tcpSocket.readable.getReader();
    var responseData = new Uint8Array(0);
    var timeoutPromise = new Promise(function(resolve) { setTimeout(function() { resolve({ done: true, timeout: true }); }, 5000); });

    while (true) {
      var result = await Promise.race([reader.read(), timeoutPromise]);
      if (result.done) break;
      if (result.value) {
        var newData = new Uint8Array(responseData.length + result.value.length);
        newData.set(responseData);
        newData.set(result.value, responseData.length);
        responseData = newData;
        var responseText = new TextDecoder().decode(responseData);
        if (responseText.includes("\r\n\r\n") && (responseText.toLowerCase().includes("connection: close") || responseText.includes("content-length"))) {
          break;
        }
      }
    }
    reader.releaseLock();

    var responseText = new TextDecoder().decode(responseData);
    var statusMatch = responseText.match(/^HTTP\/\d\.\d\s+(\d+)/i);
    var statusCode = statusMatch ? parseInt(statusMatch[1]) : null;
    var looksLikeCloudflare = responseText.toLowerCase().includes("cloudflare");
    var isExpectedError = responseText.includes("plain HTTP request") || responseText.includes("400 Bad Request");
    var hasSufficientBody = responseData.length > 50;
    var isSuccessful = statusCode !== null && looksLikeCloudflare && isExpectedError && hasSufficientBody;

    await tcpSocket.close();
    return { success: isSuccessful, proxyIP: hostToCheck, portRemote: portRemote, statusCode: statusCode, responseSize: responseData.length, timestamp: new Date().toISOString() };
  } catch (error) {
    return { success: false, proxyIP: hostToCheck, portRemote: portRemote, timestamp: new Date().toISOString(), error: error.message || error.toString() };
  }
}

async function getIpInfo(ip) {
    if (!ip) return {};
    if (ip.includes('[')) ip = ip.replace(/\[|\]/g, '');
    var response = await fetch('http://ip-api.com/json/' + ip + '?fields=status,message,query,country,as&lang=en');
    return response.json();
}

async function resolveDomain(domain) {
  domain = domain.includes(':') ? domain.split(':')[0] : domain;
  try {
    var [ipv4Response, ipv6Response] = await Promise.all([
      fetch('https://1.1.1.1/dns-query?name=' + domain + '&type=A', { headers: { 'Accept': 'application/dns-json' } }),
      fetch('https://1.1.1.1/dns-query?name=' + domain + '&type=AAAA', { headers: { 'Accept': 'application/dns-json' } })
    ]);
    var [ipv4Data, ipv6Data] = await Promise.all([ipv4Response.json(), ipv6Response.json()]);
    var ips = [];
    if (ipv4Data.Answer) {
      ips.push.apply(ips, ipv4Data.Answer.filter(function(r) { return r.type === 1; }).map(function(r) { return r.data; }));
    }
    if (ipv6Data.Answer) {
      ips.push.apply(ips, ipv6Data.Answer.filter(function(r) { return r.type === 28; }).map(function(r) { return '[' + r.data + ']'; }));
    }
    if (ips.length === 0) throw new Error('No A or AAAA records found for this domain.');
    return ips;
  } catch (error) {
    throw new Error('DNS resolution failed: ' + error.message);
  }
}

function generateSimpleResultHTML(title, successfulResults, showDownloadButton) {
    var resultsHTML = '';
    var allIPs = [];
    if (successfulResults.length > 0) {
        successfulResults.forEach(function(result) {
            allIPs.push(result.check.proxyIP);
            resultsHTML +=
            '<div class="result-box">' +
                '<p><strong>IP Address:</strong> <code>' + result.check.proxyIP + '</code></p>' +
                '<p><strong>Port:</strong> ' + result.check.portRemote + '</p>' +
                '<p><strong>Country:</strong> ' + (result.info.country || 'N/A') + '</p>' +
                '<p><strong>AS:</strong> ' + (result.info.as || 'N/A') + '</p>' +
            '</div>';
        });
    } else {
        resultsHTML = '<p>No successful proxies found.</p>';
    }

    var downloadButtonHTML = showDownloadButton ? '<button class="btn btn-download" id="downloadBtn">Download .txt</button>' : '';

    return '<!DOCTYPE html>' +
    '<html lang="en">' +
    '<head>' +
      '<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Proxy Check Results</title>' +
      '<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">' +
      '<style>' +
        'body { font-family: \'Inter\', sans-serif; margin: 0; padding: 20px; background-color: #f4f7f9; color: #2c3e50; display: flex; justify-content: center; align-items: flex-start; min-height: 100vh; }' +
        '.container { background-color: #fff; border-radius: 12px; padding: 30px; box-shadow: 0 8px 20px rgba(0,0,0,0.1); max-width: 800px; width: 100%; box-sizing: border-box; }' +
        'h1 { font-size: 1.8rem; margin-bottom: 20px; border-bottom: 2px solid #eee; padding-bottom: 15px; word-break: break-word; }' +
        'h1 a { color: #3498db; text-decoration: none; } h1 a:hover { text-decoration: underline; }' +
        '.actions { margin-bottom: 20px; display: flex; gap: 10px; }' +
        '.btn { padding: 10px 20px; border: none; border-radius: 8px; font-size: 1rem; cursor: pointer; }' +
        '.btn-copy { background-color: #3498db; color: white; }' +
        '.btn-download { background-color: #2ecc71; color: white; }' +
        '.result-box { border: 1px solid #d4edda; background-color: #fafffa; border-radius: 8px; padding: 15px; margin-bottom: 15px; }' +
        '.result-box p { margin: 5px 0; word-break: break-all; }' +
        '.toast { position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%); background: #333; color: white; padding: 12px 20px; border-radius: 8px; z-index:1001; opacity:0; transition: opacity 0.3s, transform 0.3s; }' +
        '.toast.show { opacity:1; }' +
      '</style>' +
    '</head>' +
    '<body>' +
      '<div class="container">' +
        '<h1>' + title + '</h1>' +
        '<div class="actions">' +
          '<button class="btn btn-copy" id="copyBtn">Copy All</button>' +
          downloadButtonHTML +
        '</div>' +
        '<div id="results-container">' + resultsHTML + '</div>' +
        '<div id="toast" class="toast"></div>' +
      '</div>' +
      '<script>' +
        'var allIPs = ' + JSON.stringify(allIPs) + ';' +
        'document.getElementById("copyBtn").addEventListener("click", function() {' +
            'if(allIPs.length === 0) return showToast("No IPs to copy.");' +
            'navigator.clipboard.writeText(allIPs.join("\\n")).then(function() { showToast("All successful IPs copied!"); }).catch(function(err) { showToast("Failed to copy."); });' +
        '});' +
        'var downloadBtn = document.getElementById("downloadBtn");' +
        'if (downloadBtn) {' +
            'downloadBtn.addEventListener("click", function() {' +
                'if(allIPs.length === 0) return showToast("No IPs to download.");' +
                'var blob = new Blob([allIPs.join("\\n")], { type: "text/plain" });' +
                'var url = URL.createObjectURL(blob);' +
                'var a = document.createElement("a"); a.href = url; a.download = "successful_proxies.txt";' +
                'document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);' +
            '});' +
        '}' +
        'function showToast(message) {' +
          'var toast = document.getElementById("toast");' +
          'toast.textContent = message;' +
          'toast.classList.add("show");' +
          'setTimeout(function() { toast.classList.remove("show"); }, 2000);' +
        '}' +
      '</script>' +
    '</body>' +
    '</html>';
}

// --- Main Fetch Handler ---

export default {
  async fetch(request, env, ctx) {
    var url = new URL(request.url);
    var path = url.pathname;
    var userAgent = request.headers.get('User-Agent') || 'null';
    var hostname = url.hostname;
    
    var timestampForToken = Math.ceil(new Date().getTime() / (1000 * 60 * 31));
    temporaryTOKEN = await doubleHash(hostname + timestampForToken + userAgent);
    permanentTOKEN = (env && env.TOKEN) ? env.TOKEN : temporaryTOKEN;

    if (path.toLowerCase().startsWith('/iprange/')) {
        var range_string = path.substring(path.indexOf('/', 1) + 1);
        var redirectUrl = new URL(request.url);
        redirectUrl.pathname = '/';
        redirectUrl.hash = '#/action/range/' + encodeURIComponent(range_string);
        return Response.redirect(redirectUrl.toString(), 302);
    }
    
    if (path.toLowerCase().startsWith('/proxyip/')) {
        var ips_string = path.substring(path.indexOf('/', 1) + 1);
        var redirectUrl = new URL(request.url);
        redirectUrl.pathname = '/';
        redirectUrl.hash = '#/action/proxyip/' + encodeURIComponent(ips_string);
        return Response.redirect(redirectUrl.toString(), 302);
    }
    
    if (path.toLowerCase().startsWith('/file/')) {
        try {
            var targetUrl = request.url.substring(request.url.indexOf('/file/') + 6);
            if (!targetUrl || !targetUrl.startsWith('http')) {
                 return new Response('Invalid URL provided.', { status: 400 });
            }
            if (!targetUrl.toLowerCase().endsWith('.txt') && !targetUrl.toLowerCase().endsWith('.csv')) {
                return new Response('Invalid file type. Only .txt and .csv are supported.', { status: 400 });
            }
        
            var response = await fetch(targetUrl, { headers: {'User-Agent': 'ProxyCheckerWorker/1.0'} });
            if (!response.ok) {
                throw new Error('Failed to fetch the URL: ' + response.statusText);
            }
            var text = await response.text();
            var ipRegex = /(\[?([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\]?)|((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))/g;
            var allIPs = [...new Set(text.match(ipRegex) || [])];

            var checkPromises = allIPs.map(function(ip) { return checkProxyIP(ip); });
            var checkResults = await Promise.allSettled(checkPromises);

            var successfulChecks = checkResults
                .filter(function(result) { return result.status === 'fulfilled' && result.value.success; })
                .map(function(result) { return result.value; });
            
            var successfulResultsWithInfo = await Promise.all(successfulChecks.map(async function(check) {
                var info = await getIpInfo(check.proxyIP);
                return { check: check, info: info };
            }));
            
            var title = 'Results for File: <a href="' + targetUrl + '" target="_blank" rel="noopener noreferrer">' + targetUrl + '</a>';
            var html = generateSimpleResultHTML(title, successfulResultsWithInfo, true);
            return new Response(html, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });

        } catch (error) {
            return new Response('An error occurred: ' + error.message, { status: 500 });
        }
    }
    
    if (path.toLowerCase().startsWith('/api/')) {
        var isTokenValid = function() {
            if (!(env && env.TOKEN)) return true;
            var providedToken = url.searchParams.get('token');
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
            var proxyIPInput = url.searchParams.get('proxyip');
            var ipWithPort = proxyIPInput.includes(':') || proxyIPInput.includes(']:') ? proxyIPInput : '' + proxyIPInput + ':443';
            var result = await checkProxyIP(ipWithPort);
            return new Response(JSON.stringify(result), {
                status: result.success ? 200 : 502, headers: { "Content-Type": "application/json" }
            });
        }
        
        if (path.toLowerCase() === '/api/resolve') {
            if (!url.searchParams.has('domain')) return new Response('Missing domain parameter', { status: 400 });
            var domain = url.searchParams.get('domain');
            try {
                var ips = await resolveDomain(domain);
                return new Response(JSON.stringify({ success: true, domain: domain, ips: ips }), { headers: { "Content-Type": "application/json" } });
            } catch (error) {
                return new Response(JSON.stringify({ success: false, error: error.message }), { status: 500, headers: { "Content-Type": "application/json" } });
            }
        }

        if (path.toLowerCase() === '/api/ip-info') {
            let ip = url.searchParams.get('ip') || request.headers.get('CF-Connecting-IP');
            if (!ip) return new Response('IP parameter not provided', { status: 400 });
            if (ip.includes('[')) ip = ip.replace(/\[|\]/g, '');
            var response = await fetch('http://ip-api.com/json/' + ip + '?fields=status,message,query,country,countryCode,as&lang=en');
            var data = await response.json();
            return new Response(JSON.stringify(data), { headers: { "Content-Type": "application/json" } });
        }
        
        return new Response('API route not found', { status: 404 });
    }
    
    var faviconURL = (env && env.ICO) ? env.ICO : 'https://cf-assets.www.cloudflare.com/dzlvafdwdttg/19kSkLSfWtDcspvQI5pit4/c5630cf25d589a0de91978ca29486259/performance-acceleration-bolt.svg';

    if (path.toLowerCase() === '/favicon.ico') {
        return Response.redirect(faviconURL, 302);
    }
    
    return new Response(generateMainHTML(faviconURL), {
      headers: { "content-type": "text/html;charset=UTF-8" }
    });
  }
};

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
      <p>© ${new Date().getFullYear()} Proxy IP Checker - By <strong>mehdi-hexing</strong></p>
    </footer>
  </div>
  <div id="toast" class="toast"></div>
  <button id="theme-toggle" aria-label="Toggle Theme">
    <svg class="sun-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
    <svg class="moon-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="0.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
  </button>
  <script>${CLIENT_SCRIPT}</script>
</body>
</html>`;
}
