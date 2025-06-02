import { connect } from "cloudflare:sockets";
let 临时TOKEN, 永久TOKEN; //

export default {
  async fetch(request, env, ctx) {
    const 网站图标 = env.ICO || 'https://cf-assets.www.cloudflare.com/dzlvafdwdttg/19kSkLSfWtDcspvQI5pit4/c5630cf25d589a0de91978ca29486259/performance-acceleration-bolt.svg'; //
    const url = new URL(request.url);
    const UA = request.headers.get('User-Agent') || 'null'; //
    const path = url.pathname;
    const hostname = url.hostname;
    const currentDate = new Date();
    const timestamp = Math.ceil(currentDate.getTime() / (1000 * 60 * 31)); // 每31分钟一个时间戳
    临时TOKEN = await 双重哈希(url.hostname + timestamp + UA); //
    永久TOKEN = env.TOKEN || 临时TOKEN; //

    // 不区分大小写检查路径
    if (path.toLowerCase() === '/check') { //
      if (!url.searchParams.has('proxyip')) return new Response('Missing proxyip parameter', { status: 400 }); //
      if (url.searchParams.get('proxyip') === '') return new Response('Invalid proxyip parameter', { status: 400 }); //

      if (env.TOKEN) { //
        if (!url.searchParams.has('token') || url.searchParams.get('token') !== 永久TOKEN) { //
          return new Response(JSON.stringify({
            status: "error",
            message: `ProxyIP查询失败: 无效的TOKEN`, //
            timestamp: new Date().toISOString()
          }, null, 4), {
            status: 403,
            headers: {
              "content-type": "application/json; charset=UTF-8", //
              'Access-Control-Allow-Origin': '*' //
            }
          });
        }
      }
      const proxyIPInput = url.searchParams.get('proxyip').toLowerCase(); //
      const result = await CheckProxyIP(proxyIPInput); //

      return new Response(JSON.stringify(result, null, 2), { //
        status: result.success ? 200 : 502, //
        headers: {
          "Content-Type": "application/json", //
          "Access-Control-Allow-Origin": "*" //
        }
      });
    } else if (path.toLowerCase() === '/resolve') { //
      if (!url.searchParams.has('token') || (url.searchParams.get('token') !== 临时TOKEN) && (url.searchParams.get('token') !== 永久TOKEN)) { //
        return new Response(JSON.stringify({
          status: "error",
          message: `域名查询失败: 无效的TOKEN`, //
          timestamp: new Date().toISOString()
        }, null, 4), {
          status: 403,
          headers: {
            "content-type": "application/json; charset=UTF-8", //
            'Access-Control-Allow-Origin': '*' //
          }
        });
      }
      if (!url.searchParams.has('domain')) return new Response('Missing domain parameter', { status: 400 }); //
      const domain = url.searchParams.get('domain'); //

      try {
        const ips = await resolveDomain(domain); //
        return new Response(JSON.stringify({ success: true, domain, ips }), { //
          headers: {
            "Content-Type": "application/json", //
            "Access-Control-Allow-Origin": "*" //
          }
        });
      } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), { //
          status: 500,
          headers: {
            "Content-Type": "application/json", //
            "Access-Control-Allow-Origin": "*" //
          }
        });
      }
    } else if (path.toLowerCase() === '/ip-info') { //
      if (!url.searchParams.has('token') || (url.searchParams.get('token') !== 临时TOKEN) && (url.searchParams.get('token') !== 永久TOKEN)) { //
        return new Response(JSON.stringify({
          status: "error",
          message: `IP查询失败: 无效的TOKEN`, //
          timestamp: new Date().toISOString()
        }, null, 4), {
          status: 403,
          headers: {
            "content-type": "application/json; charset=UTF-8", //
            'Access-Control-Allow-Origin': '*' //
          }
        });
      }
      let ip = url.searchParams.get('ip') || request.headers.get('CF-Connecting-IP'); //
      if (!ip) { //
        return new Response(JSON.stringify({
          status: "error",
          message: "IP参数未提供", //
          code: "MISSING_PARAMETER", //
          timestamp: new Date().toISOString()
        }, null, 4), {
          status: 400,
          headers: {
            "content-type": "application/json; charset=UTF-8", //
            'Access-Control-Allow-Origin': '*' //
          }
        });
      }

      if (ip.includes('[')) { //
        ip = ip.replace('[', '').replace(']', ''); //
      }

      try {
        const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`); //

        if (!response.ok) { //
          throw new Error(`HTTP error: ${response.status}`); //
        }

        const data = await response.json(); //
        data.timestamp = new Date().toISOString(); //

        return new Response(JSON.stringify(data, null, 4), { //
          headers: {
            "content-type": "application/json; charset=UTF-8", //
            'Access-Control-Allow-Origin': '*' //
          }
        });

      } catch (error) { //
        console.error("IP查询失败:", error); //
        return new Response(JSON.stringify({
          status: "error",
          message: `IP查询失败: ${error.message}`, //
          code: "API_REQUEST_FAILED", //
          query: ip, //
          timestamp: new Date().toISOString(), //
          details: { //
            errorType: error.name, //
            stack: error.stack ? error.stack.split('\n')[0] : null //
          }
        }, null, 4), {
          status: 500,
          headers: {
            "content-type": "application/json; charset=UTF-8", //
            'Access-Control-Allow-Origin': '*' //
          }
        });
      }
    } else {
      const envKey = env.URL302 ? 'URL302' : (env.URL ? 'URL' : null); //
      if (envKey) { //
        const URLs = await 整理(env[envKey]); //
        const URL = URLs[Math.floor(Math.random() * URLs.length)]; //
        return envKey === 'URL302' ? Response.redirect(URL, 302) : fetch(new Request(URL, request)); //
      } else if (env.TOKEN) { //
        return new Response(await nginx(), { //
          headers: {
            'Content-Type': 'text/html; charset=UTF-8', //
          },
        });
      } else if (path.toLowerCase() === '/favicon.ico') { //
        return Response.redirect(网站图标, 302); //
      }
      return await HTML(hostname, 网站图标, 临时TOKEN); // Pass 临时TOKEN
    }
  }
};

async function resolveDomain(domain) { //
  domain = domain.includes(':') ? domain.split(':')[0] : domain; //
  try {
    const [ipv4Response, ipv6Response] = await Promise.all([ //
      fetch(`https://1.1.1.1/dns-query?name=${domain}&type=A`, { //
        headers: { 'Accept': 'application/dns-json' } //
      }),
      fetch(`https://1.1.1.1/dns-query?name=${domain}&type=AAAA`, { //
        headers: { 'Accept': 'application/dns-json' } //
      })
    ]);

    const [ipv4Data, ipv6Data] = await Promise.all([ //
      ipv4Response.json(), //
      ipv6Response.json() //
    ]);

    const ips = []; //
    if (ipv4Data.Answer) { //
      const ipv4Addresses = ipv4Data.Answer //
        .filter(record => record.type === 1) // A记录
        .map(record => record.data); //
      ips.push(...ipv4Addresses); //
    }
    if (ipv6Data.Answer) { //
      const ipv6Addresses = ipv6Data.Answer //
        .filter(record => record.type === 28) // AAAA记录
        .map(record => `[${record.data}]`); // IPv6地址用方括号包围
      ips.push(...ipv6Addresses); //
    }
    if (ips.length === 0) { //
      throw new Error('No A or AAAA records found'); //
    }
    return ips; //
  } catch (error) {
    throw new Error(`DNS resolution failed: ${error.message}`); //
  }
}

async function CheckProxyIP(proxyIP) { //
  let portRemote = 443; //
  let hostToCheck = proxyIP;

  if (proxyIP.includes('.tp')) { //
    const portMatch = proxyIP.match(/\.tp(\d+)\./); //
    if (portMatch) portRemote = parseInt(portMatch[1]); //
     hostToCheck = proxyIP.split('.tp')[0];
  } else if (proxyIP.includes('[') && proxyIP.includes(']:')) { //
    portRemote = parseInt(proxyIP.split(']:')[1]); //
    hostToCheck = proxyIP.split(']:')[0] + ']'; //
  } else if (proxyIP.includes(':') && !proxyIP.startsWith('[')) { //
    const parts = proxyIP.split(':');
    if (parts.length === 2 && parts[0].includes('.')) {
        hostToCheck = parts[0];
        portRemote = parseInt(parts[1]) || 443;
    }
  }

  const tcpSocket = connect({ //
    hostname: hostToCheck,
    port: portRemote,
  });

  try {
    const httpRequest = //
      "GET /cdn-cgi/trace HTTP/1.1\r\n" +
      "Host: speed.cloudflare.com\r\n" +
      "User-Agent: CheckProxyIP/cmliu\r\n" +
      "Connection: close\r\n\r\n";

    const writer = tcpSocket.writable.getWriter(); //
    await writer.write(new TextEncoder().encode(httpRequest)); //
    writer.releaseLock(); //

    const reader = tcpSocket.readable.getReader(); //
    let responseData = new Uint8Array(0); //

    while (true) { //
      const { value, done } = await Promise.race([ //
        reader.read(), //
        new Promise(resolve => setTimeout(() => resolve({ done: true }), 5000)) // 5秒超时
      ]);

      if (done) break; //
      if (value) { //
        const newData = new Uint8Array(responseData.length + value.length); //
        newData.set(responseData); //
        newData.set(value, responseData.length); //
        responseData = newData; //
        const responseText = new TextDecoder().decode(responseData); //
        if (responseText.includes("\r\n\r\n") && //
          (responseText.includes("Connection: close") || responseText.includes("content-length"))) { //
          break; //
        }
      }
    }
    reader.releaseLock(); //

    const responseText = new TextDecoder().decode(responseData); //
    const statusMatch = responseText.match(/^HTTP\/\d\.\d\s+(\d+)/i); //
    const statusCode = statusMatch ? parseInt(statusMatch[1]) : null; //

    function isValidProxyResponse(responseText, responseData) { //
      const statusMatch = responseText.match(/^HTTP\/\d\.\d\s+(\d+)/i); //
      const statusCode = statusMatch ? parseInt(statusMatch[1]) : null; //
      const looksLikeCloudflare = responseText.includes("cloudflare"); //
      const isExpectedError = responseText.includes("plain HTTP request") || responseText.includes("400 Bad Request"); //
      const hasBody = responseData.length > 100; //
      return statusCode !== null && looksLikeCloudflare && isExpectedError && hasBody; //
    }
    const isSuccessful = isValidProxyResponse(responseText, responseData); //

    const jsonResponse = { //
      success: isSuccessful, //
      proxyIP: hostToCheck, //
      portRemote: portRemote, //
      statusCode: statusCode || null, //
      responseSize: responseData.length, //
      timestamp: new Date().toISOString(), //
    };
    await tcpSocket.close(); //
    return jsonResponse; //
  } catch (error) {
    return { //
      success: false, //
      proxyIP: hostToCheck, // changed from -1 to hostToCheck for clarity
      portRemote: portRemote, // changed from -1
      timestamp: new Date().toISOString(), //
      error: error.message || error.toString() //
    };
  }
}

async function 整理(内容) { //
  var 替换后的内容 = 内容.replace(/[\r\n]+/g, '|').replace(/\|+/g, '|'); //
  const 地址数组 = 替换后的内容.split('|'); //
  const 整理数组 = 地址数组.filter((item, index) => { //
    return item !== '' && 地址数组.indexOf(item) === index; //
  });
  return 整理数组; //
}

async function 双重哈希(文本) { //
  const 编码器 = new TextEncoder(); //
  const 第一次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(文本)); //
  const 第一次哈希数组 = Array.from(new Uint8Array(第一次哈希)); //
  const 第一次十六进制 = 第一次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join(''); //
  const 第二次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(第一次十六进制.slice(7, 27))); //
  const 第二次哈希数组 = Array.from(new Uint8Array(第二次哈希)); //
  const 第二次十六进制 = 第二次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join(''); //
  return 第二次十六进制.toLowerCase(); //
}

async function nginx() { //
  const text = `
    <!DOCTYPE html>
    <html>
    <head>
    <title>Welcome to nginx!</title>
    <style>
        body {
            width: 35em;
            margin: 0 auto;
            font-family: Tahoma, Verdana, Arial, sans-serif;
        }
    </style>
    </head>
    <body>
    <h1>Welcome to nginx!</h1>
    <p>If you see this page, the nginx web server is successfully installed and
    working. Further configuration is required.</p>
    <p>For online documentation and support please refer to
    <a href="http://nginx.org/">nginx.org</a>.<br/>
    Commercial support is available at
    <a href="http://nginx.com/">nginx.com</a>.</p>
    <p><em>Thank you for using nginx.</em></p>
    </body>
    </html>
    ` //
  return text; //
}

async function HTML(hostname, 网站图标, token) { // Added token parameter
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Check ProxyIP - 代理IP检测服务</title>
  <link rel="icon" href="${网站图标}" type="image/x-icon">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script> <style>
    :root {
      --primary-color: #3498db; /* */
      --primary-dark: #2980b9; /* */
      --secondary-color: #1abc9c; /* */
      --success-color: #2ecc71; /* */
      --warning-color: #f39c12; /* */
      --error-color: #e74c3c; /* */
      --bg-primary: #ffffff; /* */
      --bg-secondary: #f8f9fa; /* */
      --text-primary: #2c3e50; /* */
      --border-color: #dee2e6; /* */
      --border-radius: 12px; /* */
      --border-radius-sm: 8px; /* */
    }
    body { font-family: 'Inter', sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: var(--text-primary); /* */ }
    .container { max-width: 1000px; margin: 0 auto; padding: 20px; } /* */
    .header { text-align: center; margin-bottom: 40px; } /* */
    .main-title { font-size: 3rem; font-weight: 700; background: linear-gradient(135deg, #ffffff 0%, #f0f0f0 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; } /* */
    .card { background: var(--bg-primary); border-radius: var(--border-radius); padding: 28px; box-shadow: 0 10px 25px rgba(0,0,0,0.1); margin-bottom: 28px; } /* */
    .form-label { display: block; font-weight: 600; margin-bottom: 10px; } /* */
    .input-group { display: flex; gap: 12px; align-items: flex-end; margin-bottom: 12px; } /* */
    .input-wrapper { flex: 1; } /* */
    .form-input { width: 100%; padding: 14px; border: 1px solid var(--border-color); border-radius: var(--border-radius-sm); font-size: 1rem; } /* */
    .btn-primary { background: linear-gradient(135deg, var(--primary-color), var(--primary-dark)); color: white; padding: 14px 28px; border: none; border-radius: var(--border-radius-sm); font-size: 1rem; font-weight: 600; cursor: pointer; } /* */
    .btn-primary:disabled { background: #bdc3c7; cursor: not-allowed; } /* */
    .loading-spinner { width: 18px; height: 18px; border: 2px solid rgba(255,255,255,0.3); border-top-color: white; border-radius: 50%; animation: spin 1s linear infinite; display: none; margin-left: 8px; } /* */
    @keyframes spin { to { transform: rotate(360deg); } } /* */
    .result-section { margin-top: 28px; } /* */
    .result-card { padding: 20px; border-radius: var(--border-radius-sm); margin-bottom: 12px; } /* */
    .result-success { background-color: #d4edda; border-left: 4px solid var(--success-color); color: #155724; } /* */
    .result-error { background-color: #f8d7da; border-left: 4px solid var(--error-color); color: #721c24; } /* */
    .result-warning { background-color: #fff3cd; border-left: 4px solid var(--warning-color); color: #856404;} /* */
    .copy-btn { background: var(--bg-secondary); border: 1px solid var(--border-color); padding: 4px 8px; border-radius: 4px; font-size: 0.9em; cursor: pointer; margin-left: 8px;} /* */
    .toast { position: fixed; bottom: 20px; right: 20px; background: #333; color: white; padding: 12px 20px; border-radius:var(--border-radius-sm); z-index:1000; opacity:0; transition: opacity 0.3s; } /* */
    .toast.show { opacity:1; } /* */
    #rangeResultChartContainer { margin-top: 20px; padding:15px; background-color: var(--bg-secondary); border-radius: var(--border-radius-sm); }
    .api-docs { margin-top: 40px; padding: 28px; background: var(--bg-primary); border-radius: var(--border-radius); } /* */
    .footer { text-align: center; padding: 20px; margin-top: 40px; color: rgba(255,255,255,0.8); font-size: 0.9em; border-top: 1px solid rgba(255,255,255,0.1); } /* */
    .flex-align-center { display: flex; align-items: center; }
  </style>
</head>
<body>
  <div class="container">
    <header class="header">
      <h1 class="main-title">Check ProxyIP</h1>
    </header>

    <div class="card">
      <div class="form-section">
        <label for="proxyip" class="form-label">🔍 输入 ProxyIP 地址或域名 (تک آی‌پی یا دامنه)</label>
        <div class="input-group">
          <div class="input-wrapper">
            <input type="text" id="proxyip" class="form-input" placeholder="例如: 1.2.3.4:443 或 example.com" autocomplete="off">
          </div>
        </div>
        
        <label for="proxyipRange" class="form-label" style="margin-top: 15px;">🎯 وارد کردن رنج آی‌پی (مثال: 1.2.3.0/24 یا 1.2.3.1-255)</label>
        <div class="input-group">
          <div class="input-wrapper">
            <input type="text" id="proxyipRange" class="form-input" placeholder="1.2.3.0/24 یا 1.2.3.1-255 (فقط آخرین بخش برای رنج ساده)" autocomplete="off">
          </div>
        </div>

        <button id="checkBtn" class="btn-primary" onclick="checkInputs()" style="margin-top: 20px;">
          <span class="flex-align-center">
            <span class="btn-text">بررسی (Check)</span>
            <span class="loading-spinner"></span>
          </span>
        </button>
      </div>
      
      <div id="result" class="result-section"></div>
      <div id="rangeResultCard" class="result-card result-section" style="display:none;">
         <h4>نتایج موفق تست رنج آی‌پی:</h4>
         <div id="rangeResultChartContainer" style="width:100%; max-width:800px; margin: 20px auto;">
            <canvas id="rangeSuccessChart"></canvas>
         </div>
         <div id="rangeResultSummary"></div>
      </div>
    </div>
    
    <div class="api-docs">
       <h2 style="margin-bottom:10px;">📚 API 文档</h2>
       <p><code>GET /check?proxyip=YOUR_PROXY_IP&token=YOUR_TOKEN_IF_SET</code></p>
       <p><code>GET /resolve?domain=YOUR_DOMAIN&token=YOUR_TOKEN_IF_SET</code></p>
       <p><code>GET /ip-info?ip=TARGET_IP&token=YOUR_TOKEN_IF_SET</code></p>
    </div>

    <footer class="footer">
      <p>© ${new Date().getFullYear()} Check ProxyIP - توسط <strong>cmliu</strong> | تغییرات توسط Gemini</p>
    </footer>
  </div>

  <div id="toast" class="toast"></div>

  <script>
    let isChecking = false; //
    const ipCheckResults = new Map(); //
    let pageLoadTimestamp; //
    const TEMP_TOKEN = "${token}"; // Use the token passed from the backend
    let rangeChartInstance = null;

    function calculateTimestamp() { //
      const currentDate = new Date(); //
      return Math.ceil(currentDate.getTime() / (1000 * 60 * 13)); // 每13分钟一个时间戳
    }
    
    document.addEventListener('DOMContentLoaded', function() { //
      pageLoadTimestamp = calculateTimestamp(); //
      const singleIpInput = document.getElementById('proxyip'); //
      const rangeIpInput = document.getElementById('proxyipRange');
      singleIpInput.focus(); //
      
      // Simplified auto-check from original code for single IP
      const urlParams = new URLSearchParams(window.location.search); //
      let autoCheckValue = urlParams.get('autocheck'); //
       if (!autoCheckValue) { //
          const currentPath = window.location.pathname; //
          if (currentPath.length > 1) { //
            const pathContent = decodeURIComponent(currentPath.substring(1)); //
            if (isValidProxyIPFormat(pathContent)) { //
                autoCheckValue = pathContent; //
            }
          }
       }

      if (autoCheckValue) { //
        singleIpInput.value = autoCheckValue; //
        const newUrl = new URL(window.location); //
        newUrl.searchParams.delete('autocheck'); //
        newUrl.pathname = '/'; //
        window.history.replaceState({}, '', newUrl); //
        setTimeout(() => { if (!isChecking) { checkInputs(); } }, 500); //
      } else {
        try { //
            const lastSearch = localStorage.getItem('lastProxyIP'); //
            if (lastSearch) singleIpInput.value = lastSearch; //
        } catch (e) { console.error('localStorage read error:', e); } //
      }
      
      singleIpInput.addEventListener('keypress', function(event) { if (event.key === 'Enter' && !isChecking) { checkInputs(); } }); //
      rangeIpInput.addEventListener('keypress', function(event) { if (event.key === 'Enter' && !isChecking) { checkInputs(); } });
      
      document.addEventListener('click', function(event) { //
        if (event.target.classList.contains('copy-btn')) { //
          const text = event.target.getAttribute('data-copy'); //
          if (text) copyToClipboard(text, event.target); //
        }
      });
    });

    function showToast(message, duration = 3000) { //
      const toast = document.getElementById('toast'); //
      toast.textContent = message; //
      toast.classList.add('show'); //
      setTimeout(() => { toast.classList.remove('show'); }, duration); //
    }

    function copyToClipboard(text, element) { //
      navigator.clipboard.writeText(text).then(() => { //
        const originalText = element.textContent; //
        element.textContent = 'کپی شد ✓'; //
        showToast('کپی موفقیت آمیز بود!'); //
        setTimeout(() => { element.textContent = originalText; }, 2000); //
      }).catch(err => { showToast('کپی نشد، لطفا دستی انجام دهید.'); }); //
    }
    
    function createCopyButton(text) { return \`<span class="copy-btn" data-copy="\${text}">\${text}</span>\`; } //

    function isValidProxyIPFormat(input) { //
        const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?)*$/; //
        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/; //
        const ipv6Regex = /^\\[?([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\\]?$/; //
        const withPortRegex = /^.+:\\d+$/; //
        const tpPortRegex = /^.+\\.tp\\d+\\./; //
        return domainRegex.test(input) || ipv4Regex.test(input) || ipv6Regex.test(input) || withPortRegex.test(input) || tpPortRegex.test(input); //
    }
     function isIPAddress(input) { //
      const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/; //
      const ipv6Regex = /^\\[?([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\\]?$/; //
      const ipv6WithPortRegex = /^\\[[0-9a-fA-F:]+\\]:\\d+$/; //
      const ipv4WithPortRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):\\d+$/; //
      return ipv4Regex.test(input) || ipv6Regex.test(input) || ipv6WithPortRegex.test(input) || ipv4WithPortRegex.test(input); //
    }

    function parseIPRange(rangeInput) {
        const ips = [];
        rangeInput = rangeInput.trim();
        // CIDR: x.x.x.0/24
        if (/^(\\d{1,3}\\.){3}\\d{1,3}\\/24$/.test(rangeInput)) {
            const baseIp = rangeInput.split('/')[0];
            const baseParts = baseIp.split('.');
            if (baseParts.length === 4 ) { // Ensures it's a valid start like x.x.x.0
                 // As requested, test all 255 (1 to 255)
                for (let i = 1; i <= 255; i++) {
                    ips.push(\`\${baseParts[0]}.\${baseParts[1]}.\${baseParts[2]}.\${i}\`);
                }
            } else {
                 showToast('فرمت CIDR نامعتبر است. باید x.x.x.0/24 باشد.');
            }
        } 
        // Simple range: x.x.x.A-B (e.g., 1.2.3.1-255)
        else if (/^(\\d{1,3}\\.){3}\\d{1,3}-\\d{1,3}$/.test(rangeInput)) {
            const parts = rangeInput.split('-');
            const baseIpWithLastOctet = parts[0];
            const endOctet = parseInt(parts[1]);
            
            const ipParts = baseIpWithLastOctet.split('.');
            if (ipParts.length === 4) {
                const startOctet = parseInt(ipParts[3]);
                const prefix = \`\${ipParts[0]}.\${ipParts[1]}.\${ipParts[2]}\`;
                if (!isNaN(startOctet) && !isNaN(endOctet) && startOctet <= endOctet && startOctet >= 0 && endOctet <= 255) {
                    for (let i = startOctet; i <= endOctet; i++) {
                        ips.push(\`\${prefix}.\${i}\`);
                    }
                } else {
                    showToast('رنج نامعتبر در فرمت x.x.x.A-B');
                }
            } else {
                 showToast('فرمت رنج x.x.x.A-B نامعتبر است.');
            }
        }
        return ips;
    }
    
    function preprocessInput(input) { //
      if (!input) return input; //
      let processed = input.trim(); //
      if (processed.includes(' ')) { //
        processed = processed.split(' ')[0]; //
      }
      return processed; //
    }

    async function checkInputs() {
      if (isChecking) return; //

      const singleIpInputEl = document.getElementById('proxyip'); //
      const rangeIpInputEl = document.getElementById('proxyipRange');
      const resultDiv = document.getElementById('result'); //
      const rangeResultCard = document.getElementById('rangeResultCard');
      const rangeResultSummary = document.getElementById('rangeResultSummary');

      const checkBtn = document.getElementById('checkBtn'); //
      const btnText = checkBtn.querySelector('.btn-text'); //
      const spinner = checkBtn.querySelector('.loading-spinner'); //
      
      const rawSingleInput = singleIpInputEl.value; //
      let singleIpToTest = preprocessInput(rawSingleInput); //
      
      const rawRangeInput = rangeIpInputEl.value;
      let rangeIpToTest = preprocessInput(rawRangeInput);

      if (singleIpToTest && singleIpToTest !== rawSingleInput) { //
        singleIpInputEl.value = singleIpToTest; //
        showToast('ورودی تکی آی‌پی اصلاح شد.'); //
      }
       if (rangeIpToTest && rangeIpToTest !== rawRangeInput) {
        rangeIpInputEl.value = rangeIpToTest;
        showToast('ورودی رنج آی‌پی اصلاح شد.');
      }

      if (!singleIpToTest && !rangeIpToTest) { //
        showToast('لطفا یک آی‌پی یا رنج آی‌پی وارد کنید.'); //
        singleIpInputEl.focus(); //
        return; //
      }
      
      const currentTimestamp = calculateTimestamp(); //
      if (currentTimestamp !== pageLoadTimestamp) { //
        const currentHost = window.location.host; //
        const currentProtocol = window.location.protocol; //
        let redirectPathVal = singleIpToTest || rangeIpToTest || ''; //
        const redirectUrl = \`\${currentProtocol}//\${currentHost}/\${encodeURIComponent(redirectPathVal)}\`; //
        showToast('TOKEN منقضی شده، در حال تازه‌سازی صفحه...'); //
        setTimeout(() => { window.location.href = redirectUrl; }, 1000); //
        return; //
      }

      if (singleIpToTest) { //
          try { localStorage.setItem('lastProxyIP', singleIpToTest); } catch (e) {} //
      }
      
      isChecking = true; //
      checkBtn.disabled = true; //
      btnText.style.display = 'none'; //
      spinner.style.display = 'inline-block'; //
      
      resultDiv.innerHTML = ''; //
      resultDiv.classList.remove('show'); //
      rangeResultCard.style.display = 'none';
      rangeResultSummary.innerHTML = '';
      if (rangeChartInstance) {
          rangeChartInstance.destroy();
          rangeChartInstance = null;
      }

      try {
        if (singleIpToTest) {
            if (isIPAddress(singleIpToTest)) { //
                await checkAndDisplaySingleIP(singleIpToTest, resultDiv); //
            } else { 
                await checkAndDisplayDomain(singleIpToTest, resultDiv); //
            }
        }

        if (rangeIpToTest) {
            const ipsInRange = parseIPRange(rangeIpToTest);
            if (ipsInRange.length > 0) {
                showToast(\`شروع تست \${ipsInRange.length} آی‌پی در رنج... این ممکن است زمان‌بر باشد.\`);
                rangeResultCard.style.display = 'block';
                const successfulIPsData = [];
                let successCount = 0;
                let checkedCount = 0;

                // Process in batches to avoid freezing browser and provide updates
                const batchSize = 10; 
                for (let i = 0; i < ipsInRange.length; i += batchSize) {
                    const batch = ipsInRange.slice(i, i + batchSize);
                    const batchPromises = batch.map(ip => 
                        fetchSingleIPCheck(ip + ':443') // Assuming port 443 for range test
                            .then(data => {
                                checkedCount++;
                                if (data.success) {
                                    successCount++;
                                    successfulIPsData.push({ip: data.proxyIP, port: data.portRemote, status: data.statusCode});
                                }
                                return data; // Propagate data for potential further use
                            })
                            .catch(err => {
                                checkedCount++; // Count as checked even if error
                                console.error("Error checking IP in range:", ip, err);
                                return {success: false, proxyIP: ip, error: err.message};
                            })
                    );
                    await Promise.all(batchPromises);
                    rangeResultSummary.innerHTML = \`تست شده: \${checkedCount}/\${ipsInRange.length} | موفق: \${successCount}\`;
                    
                    // Update chart incrementally or at the end
                    if (successfulIPsData.length > 0) {
                         updateRangeSuccessChart(successfulIPsData.map(d => d.ip));
                    }
                     // Small delay between batches
                    if (i + batchSize < ipsInRange.length) {
                        await new Promise(resolve => setTimeout(resolve, 200));
                    }
                }
                rangeResultSummary.innerHTML = \`تست رنج کامل شد. \${successCount} آی‌پی از \${ipsInRange.length} موفق بودند.\`;
                if (successfulIPsData.length === 0) {
                    showToast('هیچ آی‌پی موفقی در رنج پیدا نشد.');
                }
            } else if (rangeIpToTest) { 
                 showToast('فرمت رنج آی‌پی نامعتبر است یا رنج خالی است.');
            }
        }

      } catch (err) { //
        const errorMsg = \`<div class="result-card result-error"><h3>❌ خطای کلی</h3><p>\${err.message}</p></div>\`; //
        if(resultDiv.innerHTML === '') resultDiv.innerHTML = errorMsg; //
        else rangeResultSummary.innerHTML = \`<p style="color:var(--error-color)">خطا در تست رنج: \${err.message}</p>\`;
        if (resultDiv.innerHTML !== '') resultDiv.classList.add('show'); //
        if (rangeIpToTest) rangeResultCard.style.display = 'block';
      } finally {
        isChecking = false; //
        checkBtn.disabled = false; //
        btnText.style.display = 'inline-block'; //
        spinner.style.display = 'none'; //
      }
    }
    
    function updateRangeSuccessChart(successfulIPs) {
        const ctx = document.getElementById('rangeSuccessChart').getContext('2d');
        if (rangeChartInstance) {
            rangeChartInstance.destroy();
        }
        // Simple bar chart: one bar per successful IP. Height can be constant.
        // X-axis: IP address, Y-axis: just a marker of success (e.g., value 1)
        const labels = successfulIPs;
        const dataPoints = successfulIPs.map(() => 1); // All successful IPs get a bar of height 1

        rangeChartInstance = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'آی‌پی‌های موفق در رنج',
                    data: dataPoints,
                    backgroundColor: 'rgba(46, 204, 113, 0.5)', // --success-color with alpha
                    borderColor: 'rgba(46, 204, 113, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1, // Only show 0 and 1 on Y axis if data is just 0/1
                            callback: function(value) { if (value === 1) return 'موفق'; return ''; }
                        },
                        title: { display: false }
                    },
                    x: {
                         ticks: {
                             autoSkip: false, // Show all IP labels
                             maxRotation: 90,
                             minRotation: 70 
                         }
                    }
                },
                plugins: {
                    legend: {
                        display: true,
                        position: 'top',
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return \`IP: \${context.label} - وضعیت: موفق\`;
                            }
                        }
                    }
                }
            }
        });
    }

    async function fetchSingleIPCheck(proxyipWithOptionalPort) { //
        const requestUrl = \`./check?proxyip=\${encodeURIComponent(proxyipWithOptionalPort)}&token=\${TEMP_TOKEN}\`; //
        const response = await fetch(requestUrl); //
        return await response.json(); //
    }

    async function checkAndDisplaySingleIP(proxyip, resultDiv) { //
      const data = await fetchSingleIPCheck(proxyip); //
      
      if (data.success) { //
        const ipInfo = await getIPInfo(data.proxyIP); //
        const ipInfoHTML = formatIPInfo(ipInfo); //
        resultDiv.innerHTML = \` 
          <div class="result-card result-success">
            <h3>✅ ProxyIP معتبر</h3>
            <p><strong>🌐 آدرس ProxyIP:</strong> \${createCopyButton(data.proxyIP)} \${ipInfoHTML}</p>
            <p><strong>🔌 پورت:</strong> \${createCopyButton(data.portRemote.toString())}</p>
            <p><strong>🕒 زمان بررسی:</strong> \${new Date(data.timestamp).toLocaleString()}</p>
          </div>
        \`; //
      } else { //
        resultDiv.innerHTML = \`
          <div class="result-card result-error">
            <h3>❌ ProxyIP نامعتبر</h3>
            <p><strong>🌐 آدرس IP:</strong> \${createCopyButton(proxyip)}</p>
            \${data.error ? \`<p><strong>خطا:</strong> \${data.error}</p>\` : ''}
            <p><strong>🕒 زمان بررسی:</strong> \${new Date(data.timestamp).toLocaleString()}</p>
          </div>
        \`; //
      }
      resultDiv.classList.add('show'); //
    }

    async function checkAndDisplayDomain(domain, resultDiv) { //
      let portRemote = 443; //
      let cleanDomain = domain; //
      
      // Logic to parse domain and port from original code
      if (domain.includes('.tp')) {
        const portMatch = domain.match(/\\.tp(\\d+)\\./);
        if (portMatch) portRemote = parseInt(portMatch[1]);
        cleanDomain = domain.split('.tp')[0];
      } else if (domain.includes('[') && domain.includes(']:')) {
        portRemote = parseInt(domain.split(']:')[1]) || 443;
        cleanDomain = domain.split(']:')[0] + ']';
      } else if (domain.includes(':') && !domain.startsWith('[')) {
         const parts = domain.split(':');
         if (parts.length === 2) {
            cleanDomain = parts[0];
            const parsedPort = parseInt(parts[1]);
            if (!isNaN(parsedPort)) portRemote = parsedPort;
         }
      }
      
      const resolveResponse = await fetch(\`./resolve?domain=\${encodeURIComponent(cleanDomain)}&token=\${TEMP_TOKEN}\`); //
      const resolveData = await resolveResponse.json(); //
      
      if (!resolveData.success) { throw new Error(resolveData.error || 'خطا در تبدیل دامنه'); } //
      const ips = resolveData.ips; //
      if (!ips || ips.length === 0) { throw new Error('هیچ آی‌پی برای دامنه یافت نشد.'); } //
      
      ipCheckResults.clear(); //
      resultDiv.innerHTML = \`
        <div class="result-card result-warning">
          <h3>🔍 نتایج تبدیل دامنه</h3>
          <p><strong>🌐 دامنه:</strong> \${createCopyButton(cleanDomain)}</p>
          <p><strong>🔌 پورت پیش‌فرض برای تست:</strong> \${portRemote}</p>
          <p><strong>📋 آی‌پی‌های یافت شده:</strong> \${ips.length}</p>
          <div class="ip-grid" id="ip-grid" style="max-height: 200px; overflow-y: auto; margin-top:10px; border:1px solid #eee; padding:5px;">
            \${ips.map((ip, index) => \`
              <div class="ip-item" id="ip-item-\${index}" style="padding:5px; border-bottom:1px solid #f0f0f0; display:flex; justify-content:space-between; align-items:center;">
                <div>\${createCopyButton(ip)} <span id="ip-info-\${index}" style="font-size:0.8em; color:#555;"></span></div>
                <span class="status-icon" id="status-icon-\${index}" style="font-size:1.2em;">🔄</span>
              </div>
            \`).join('')}
          </div>
        </div>
      \`; //
      resultDiv.classList.add('show'); //
      
      const checkPromises = ips.map((ip, index) => checkDomainIPWithIndex(ip, portRemote, index)); //
      const ipInfoPromises = ips.map((ip, index) => getIPInfoWithIndex(ip, index)); //
      
      await Promise.all([...checkPromises, ...ipInfoPromises]); //
      // Update overall domain result card status if needed, similar to original
      const validCount = Array.from(ipCheckResults.values()).filter(r => r.success).length; //
      const resultCardHeader = resultDiv.querySelector('.result-card h3'); //
      if(resultCardHeader){
          if (validCount === ips.length) resultCardHeader.textContent = '✅ همه آی‌پی‌های دامنه معتبرند'; //
          else if (validCount === 0) resultCardHeader.textContent = '❌ همه آی‌پی‌های دامنه نامعتبرند'; //
          else resultCardHeader.textContent = \`⚠️ بعضی آی‌پی‌های دامنه معتبرند (\${validCount}/\${ips.length})\`; //
      }
    }

    async function checkDomainIPWithIndex(ip, port, index) { //
      try {
        // For domains, IPs might not have port. Append default port for testing.
        const ipToTest = ip.includes(':') || ip.includes(']:') ? ip : \`\${ip}:\${port}\`; //
        const result = await fetchSingleIPCheck(ipToTest); //
        ipCheckResults.set(ipToTest, result); //
        
        const statusIcon = document.getElementById(\`status-icon-\${index}\`); //
        if (statusIcon) statusIcon.textContent = result.success ? '✅' : '❌'; //
      } catch (error) {
        const statusIcon = document.getElementById(\`status-icon-\${index}\`); //
        if (statusIcon) statusIcon.textContent = '⚠️'; //
        ipCheckResults.set(ip, { success: false, error: error.message }); //
      }
    }
    
    async function getIPInfoWithIndex(ip, index) { //
      try {
        const ipInfo = await getIPInfo(ip.split(':')[0]); // Get IP part only for info
        const infoElement = document.getElementById(\`ip-info-\${index}\`); //
        if (infoElement) infoElement.innerHTML = formatIPInfo(ipInfo, true); //
      } catch (error) { /* Fail silently for individual info errors */ } //
    }

    async function getIPInfo(ip) { //
      try {
        const cleanIP = ip.replace(/[\\[\\]]/g, ''); //
        const response = await fetch(\`./ip-info?ip=\${encodeURIComponent(cleanIP)}&token=\${TEMP_TOKEN}\`); //
        return await response.json(); //
      } catch (error) { return null; } //
    }

    function formatIPInfo(ipInfo, isShort = false) { //
      if (!ipInfo || ipInfo.status !== 'success') { return ''; } //
      const country = ipInfo.country || 'N/A'; //
      const as = ipInfo.as || 'N/A'; //
      if(isShort) return \`(\${country} - \${as.substring(0,15)}...)\`;
      return \`<span style="font-size:0.85em; color:#555;">(\${country} - \${as})</span>\`; //
    }
  </script>
</body>
</html>
`; //

  return new Response(html, {
    headers: { "content-type": "text/html;charset=UTF-8" } //
  });
                       }
