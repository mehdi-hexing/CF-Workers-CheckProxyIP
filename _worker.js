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
    const timestamp = Math.ceil(currentDate.getTime() / (1000 * 60 * 31)); //
    临时TOKEN = await 双重哈希(url.hostname + timestamp + UA); //
    永久TOKEN = env.TOKEN || 临时TOKEN; //

    if (path.toLowerCase() === '/check') { //
      if (!url.searchParams.has('proxyip')) return new Response('Missing proxyip parameter', { status: 400 }); //
      if (url.searchParams.get('proxyip') === '') return new Response('Invalid proxyip parameter', { status: 400 }); //

      if (env.TOKEN) { //
        if (!url.searchParams.has('token') || url.searchParams.get('token') !== 永久TOKEN) { //
          return new Response(JSON.stringify({
            status: "error",
            message: `ProxyIP Check Failed: Invalid TOKEN`, //
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
          message: `Domain Resolve Failed: Invalid TOKEN`, //
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
          message: `IP Info Failed: Invalid TOKEN`, //
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
          message: "IP parameter not provided", //
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
        console.error("IP Info Fetch Error:", error); //
        return new Response(JSON.stringify({
          status: "error",
          message: `IP Info Fetch Error: ${error.message}`, //
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
        .filter(record => record.type === 1) //
        .map(record => record.data); //
      ips.push(...ipv4Addresses); //
    }
    if (ipv6Data.Answer) { //
      const ipv6Addresses = ipv6Data.Answer //
        .filter(record => record.type === 28) //
        .map(record => `[${record.data}]`); //
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
      "User-Agent: CheckProxyIP/mehdi-hexing\r\n" +
      "Connection: close\r\n\r\n";

    const writer = tcpSocket.writable.getWriter(); //
    await writer.write(new TextEncoder().encode(httpRequest)); //
    writer.releaseLock(); //

    const reader = tcpSocket.readable.getReader(); //
    let responseData = new Uint8Array(0); //

    while (true) { //
      const { value, done } = await Promise.race([ //
        reader.read(), //
        new Promise(resolve => setTimeout(() => resolve({ done: true }), 5000)) //
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
      proxyIP: hostToCheck, //
      portRemote: portRemote, //
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

async function HTML(hostname, 网站图标, token) {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Proxy IP Checker Service</title>
  <link rel="icon" href="${网站图标}" type="image/x-icon">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
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
      --text-light: #adb5bd; /* */
      --border-color: #dee2e6; /* */
      --border-radius: 12px; /* */
      --border-radius-sm: 8px; /* */
    }
    *, *::before, *::after { box-sizing: border-box; }
    body { 
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif, 'Apple Color Emoji', 'Segoe UI Emoji', 'Segoe UI Symbol';
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
      color: var(--text-primary); 
      line-height: 1.6; 
      margin:0; 
      padding:0; 
      min-height: 100vh; 
      display: flex; 
      flex-direction: column; 
      align-items: center; 
      overflow-x: hidden; /* Prevent horizontal scroll from GitHub corner or other elements */
    }
    .container { 
      max-width: 800px; 
      width: 90%; /* Responsive width */
      margin: 20px auto; 
      padding: 0; 
    }
    .header { text-align: center; margin-bottom: 30px; margin-top: 20px;}
    .main-title { 
      font-size: 2.5rem; 
      font-weight: 700; 
      background: linear-gradient(135deg, #ffffff 0%, #f0f0f0 100%); 
      -webkit-background-clip: text; 
      -webkit-text-fill-color: transparent; 
      color: transparent; 
    }
    .card { 
      background: var(--bg-primary); 
      border-radius: var(--border-radius); 
      padding: 25px; 
      box-shadow: 0 8px 20px rgba(0,0,0,0.1); 
      margin-bottom: 25px; 
    }
    .form-section { 
      display: flex; 
      flex-direction: column; 
      align-items: center; /* Center form elements */
    }
    .input-wrapper { 
      width: 100%; 
      max-width: 450px; /* Max width for inputs on desktop */
      margin-bottom: 18px; 
    }
    .form-label { 
      display: block; 
      font-weight: 500; 
      margin-bottom: 8px; 
      color: var(--text-primary); 
      width: 100%; 
      text-align: left;
    }
    .form-input { 
      width: 100%; 
      padding: 12px; 
      border: 1px solid var(--border-color); 
      border-radius: var(--border-radius-sm); 
      font-size: 0.95rem; 
    }
    .btn { 
      padding: 12px 25px;
      border: none;
      border-radius: var(--border-radius-sm);
      font-size: 1rem;
      font-weight: 500;
      cursor: pointer;
      text-align: center;
      display: inline-flex; 
      align-items: center;
      justify-content: center;
      transition: background-color 0.2s ease, transform 0.1s ease;
    }
    .btn:active {
        transform: translateY(1px);
    }
    .btn-primary { 
      background: linear-gradient(135deg, var(--primary-color), var(--primary-dark)); 
      color: white; 
      width: 100%; 
      max-width: 450px; /* Consistent max-width */
    }
    .btn-primary:disabled { background: #bdc3c7; cursor: not-allowed; transform: none; }
    .btn-secondary { 
      background-color: var(--bg-secondary); 
      color: var(--text-primary); 
      border: 1px solid var(--border-color); 
      margin-top: 15px; 
    }
    .btn-secondary:hover { background-color: #e9ecef; }

    .loading-spinner { 
      width: 16px; height: 16px; 
      border: 2px solid rgba(255,255,255,0.3); 
      border-top-color: white; 
      border-radius: 50%; 
      animation: spin 1s linear infinite; 
      display: none; 
      margin-left: 8px; 
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .result-section { margin-top: 25px; }
    .result-card { padding: 18px; border-radius: var(--border-radius-sm); margin-bottom: 12px; }
    .result-success { background-color: #d4edda; border-left: 4px solid var(--success-color); color: #155724; }
    .result-error { background-color: #f8d7da; border-left: 4px solid var(--error-color); color: #721c24; }
    .result-warning { background-color: #fff3cd; border-left: 4px solid var(--warning-color); color: #856404;}
    .copy-btn { 
      background: var(--bg-secondary); 
      border: 1px solid var(--border-color); 
      padding: 4px 8px; 
      border-radius: 4px; 
      font-size: 0.85em; 
      cursor: pointer; 
      margin-left: 8px;
      transition: background-color 0.2s ease;
    }
    .copy-btn:hover { background-color: #e9ecef; }
    .toast { 
      position: fixed; 
      bottom: 20px; right: 20px; 
      background: #333; color: white; 
      padding: 12px 20px; 
      border-radius:var(--border-radius-sm); 
      z-index:1000; opacity:0; 
      transition: opacity 0.3s ease; 
      box-shadow: 0 2px 10px rgba(0,0,0,0.2);
    }
    .toast.show { opacity:1; }
    #rangeResultChartContainer { 
      margin-top: 15px; padding:10px; 
      background-color: var(--bg-secondary); 
      border-radius: var(--border-radius-sm); 
      width:100%; 
      position: relative; /* For Chart.js responsiveness */
    }
    .api-docs { margin-top: 30px; padding: 25px; background: var(--bg-primary); border-radius: var(--border-radius); }
    .api-docs p { 
      word-wrap: break-word; /* For older browsers */
      overflow-wrap: break-word; /* Standard property */
      margin-bottom: 0.5em;
    }
    .api-docs code {
      background-color: #f0f0f0;
      padding: 0.2em 0.4em;
      border-radius: 3px;
      font-family: Consolas, Monaco, 'Andale Mono', 'Ubuntu Mono', monospace;
    }
    .footer { text-align: center; padding: 20px; margin-top: auto; color: rgba(255,255,255,0.8); font-size: 0.85em; width:100%; border-top: 1px solid rgba(255,255,255,0.1); }
    .flex-align-center { display: flex; align-items: center; justify-content: center; }
    
    /* GitHub Corner: fill with page background, color with primary theme color */
    .github-corner { position: fixed; top: 0; right: 0; border: 0; z-index: 1001; }
    .github-corner svg { fill: var(--bg-primary); color: var(--primary-color); width: 80px; height: 80px;}
    .github-corner .octo-arm{transform-origin:130px 106px}
    .github-corner:hover .octo-arm{animation:octocat-wave 560ms ease-in-out}
    @keyframes octocat-wave{0%,100%{transform:rotate(0)}20%,60%{transform:rotate(-25deg)}40%,80%{transform:rotate(10deg)}}

    @media (max-width: 768px) { /* Tablets and larger phones */
      .container { width: 95%; padding-left: 10px; padding-right: 10px; }
      .main-title { font-size: 2.1rem; }
      .input-wrapper, .btn-primary { max-width: 100%; } /* Allow full width within centered form */
      .github-corner svg { width: 60px; height: 60px; }
    }

    @media (max-width: 480px) { /* Smaller mobile phones */
      .main-title { font-size: 1.8rem; }
      .card { padding: 20px; }
      .form-input, .btn { font-size: 0.9rem; padding: 10px; }
      .api-docs { padding: 20px; font-size: 0.85rem; }
      .github-corner svg { width: 50px; height: 50px; }
      .github-corner:hover .octo-arm{animation:none} 
      .github-corner .octo-arm{animation:octocat-wave 560ms ease-in-out}
      #rangeResultChartContainer { max-height: 300px; }
    }
  </style>
</head>
<body>
  <a href="https://github.com/mehdi-hexing/CF-Workers-CheckProxyIP" target="_blank" class="github-corner" aria-label="View source on Github"><svg viewBox="0 0 250 250" aria-hidden="true"><path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path><path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" fill="currentColor" style="transform-origin: 130px 106px;" class="octo-arm"></path><path d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z" fill="currentColor" class="octo-body"></path></svg></a>
  <div class="container">
    <header class="header">
      <h1 class="main-title">Proxy IP Checker</h1>
    </header>

    <div class="card">
      <div class="form-section">
        <label for="proxyip" class="form-label">Enter Single Proxy IP or Domain:</label>
        <div class="input-wrapper">
          <input type="text" id="proxyip" class="form-input" placeholder="e.g., 1.2.3.4:443 or example.com" autocomplete="off">
        </div>
        
        <label for="proxyipRange" class="form-label">Enter IP Range (e.g., CIDR /8-/32 or Simple 1.2.3.1-255):</label>
        <div class="input-wrapper">
          <input type="text" id="proxyipRange" class="form-input" placeholder="e.g., 10.0.0.0/22 or 192.168.1.1-255" autocomplete="off">
        </div>

        <button id="checkBtn" class="btn btn-primary" onclick="checkInputs()">
          <span class="flex-align-center">
            <span class="btn-text">Check</span>
            <span class="loading-spinner"></span>
          </span>
        </button>
      </div>
      
      <div id="result" class="result-section"></div>
      <div id="rangeResultCard" class="result-card result-section" style="display:none; text-align: center;">
         <h4>Successful IPs in Range:</h4>
         <div id="rangeResultChartContainer">
            <canvas id="rangeSuccessChart"></canvas>
         </div>
         <div id="rangeResultSummary" style="margin-bottom: 10px;"></div>
         <button id="copyRangeBtn" class="btn btn-secondary" onclick="copySuccessfulRangeIPs()" style="display:none;">Copy Successful IPs</button>
      </div>
    </div>
    
    <div class="api-docs">
       <h3 style="margin-bottom:15px; text-align:center;">API Documentation</h3>
       <p><code>GET /check?proxyip=YOUR_PROXY_IP&token=YOUR_TOKEN_IF_SET</code></p>
       <p><code>GET /resolve?domain=YOUR_DOMAIN&token=YOUR_TOKEN_IF_SET</code></p>
       <p><code>GET /ip-info?ip=TARGET_IP&token=YOUR_TOKEN_IF_SET</code></p>
    </div>

    <footer class="footer">
      <p>© ${new Date().getFullYear()} Proxy IP Checker - By <strong>mehdi-hexing</strong> | Modified by Mehdi-hexing</p>
    </footer>
  </div>

  <div id="toast" class="toast"></div>

  <script>
    let isChecking = false; //
    const ipCheckResults = new Map(); //
    let pageLoadTimestamp; //
    const TEMP_TOKEN = "${token}"; 
    let rangeChartInstance = null;
    let currentSuccessfulRangeIPs = [];

    function calculateTimestamp() { //
      const currentDate = new Date(); //
      return Math.ceil(currentDate.getTime() / (1000 * 60 * 13)); //
    }
    
    document.addEventListener('DOMContentLoaded', function() { //
      pageLoadTimestamp = calculateTimestamp(); //
      const singleIpInput = document.getElementById('proxyip'); //
      const rangeIpInput = document.getElementById('proxyipRange');
      singleIpInput.focus(); //
      
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
          if (text) copyToClipboard(text, event.target, "Copied!"); //
        }
      });
    });

    function showToast(message, duration = 3000) { //
      const toast = document.getElementById('toast'); //
      toast.textContent = message; //
      toast.classList.add('show'); //
      setTimeout(() => { toast.classList.remove('show'); }, duration); //
    }

    function copyToClipboard(text, element, successMessage = "Copied!") { //
      navigator.clipboard.writeText(text).then(() => { //
        const originalText = element ? element.textContent : ''; //
        if(element && element.classList.contains('btn')) { 
             element.textContent = 'Copied ✓';
        } else if (element && element.classList.contains('copy-btn')) { 
             element.textContent = '✓';
        }
        showToast(successMessage); //
        if(element && originalText) setTimeout(() => { element.textContent = originalText; }, 2000); //
      }).catch(err => { showToast('Copy failed. Please copy manually.'); }); //
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

    function ipToLong(ip) {
        let ipl = 0;
        ip.split('.').forEach(function(octet) {
            ipl <<= 8;
            ipl += parseInt(octet);
        });
        return(ipl >>> 0);
    }

    function longToIp(ipl) {
        return ( (ipl >>> 24) +'.' +
                 (ipl >> 16 & 255) +'.' +
                 (ipl >> 8 & 255) +'.' +
                 (ipl & 255) );
    }

    function parseIPRange(rangeInput) {
        const ips = [];
        rangeInput = rangeInput.trim();
        // Increased for broader CIDR support, but client-side processing of very large ranges is still dangerous.
        // A practical limit (e.g. /20 or /22) should be enforced before calling fetch for each IP.
        const MAX_IPS_TO_GENERATE_CLIENT_SIDE = 262144; // Roughly /14, still very large for client.
                                                        // User was warned about /8 etc. This is a parsing limit, not a "safe to test" limit.

        const cidrMatch = rangeInput.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/);
        if (cidrMatch) {
            const baseIpStr = cidrMatch[1];
            const prefixSize = parseInt(cidrMatch[2]);

            if (prefixSize < 8 || prefixSize > 32) { 
                showToast('CIDR prefix size must be between 8 and 32.');
                return [];
            }

            try {
                const baseIpLong = ipToLong(baseIpStr);
                // Calculate network and broadcast addresses correctly for the given base IP and prefix
                const mask = (0xFFFFFFFF << (32 - prefixSize)) >>> 0;
                const networkAddress = (baseIpLong & mask) >>> 0; // Ensure the base IP is actually the network address for iteration start
                
                const numAddresses = Math.pow(2, 32 - prefixSize);

                if (numAddresses > MAX_IPS_TO_GENERATE_CLIENT_SIDE) {
                    showToast(\`Range too large to parse/generate on client (\${numAddresses} IPs > \${MAX_IPS_TO_GENERATE_CLIENT_SIDE}). Please use a smaller range.\`);
                    return [];
                }
                
                // Generate all IPs in the CIDR block
                for (let i = 0; i < numAddresses; i++) {
                     if (ips.length >= MAX_IPS_TO_GENERATE_CLIENT_SIDE) break; 
                     const currentIpLong = (networkAddress + i) >>> 0;
                     ips.push(longToIp(currentIpLong));
                }
            } catch (e) {
                showToast('Error parsing CIDR IP address.');
                console.error("CIDR parsing error:", e);
                return [];
            }
        }
        else if (/^(\\d{1,3}\\.){3}\\d{1,3}-\\d{1,3}$/.test(rangeInput)) {
            // ... (simple range parsing remains the same)
            const parts = rangeInput.split('-');
            const baseIpWithLastOctet = parts[0];
            const endOctet = parseInt(parts[1]);
            
            const ipParts = baseIpWithLastOctet.split('.');
            if (ipParts.length === 4) {
                const startOctet = parseInt(ipParts[3]);
                const prefix = \`\${ipParts[0]}.\${ipParts[1]}.\${ipParts[2]}\`;
                if (!isNaN(startOctet) && !isNaN(endOctet) && startOctet <= endOctet && startOctet >= 0 && endOctet <= 255) {
                    for (let i = startOctet; i <= endOctet; i++) {
                        if (ips.length >= MAX_IPS_TO_GENERATE_CLIENT_SIDE) break;
                        ips.push(\`\${prefix}.\${i}\`);
                    }
                } else {
                    showToast('Invalid range in x.x.x.A-B format.');
                }
            } else {
                 showToast('Invalid x.x.x.A-B range format.');
            }
        }
        if (ips.length === 0 && rangeInput) {
            showToast('Could not parse IP range or invalid format provided.');
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
      const copyRangeBtn = document.getElementById('copyRangeBtn');

      const checkBtn = document.getElementById('checkBtn'); //
      const btnText = checkBtn.querySelector('.btn-text'); //
      const spinner = checkBtn.querySelector('.loading-spinner'); //
      
      const rawSingleInput = singleIpInputEl.value; //
      let singleIpToTest = preprocessInput(rawSingleInput); //
      
      const rawRangeInput = rangeIpInputEl.value;
      let rangeIpToTest = preprocessInput(rawRangeInput);

      if (singleIpToTest && singleIpToTest !== rawSingleInput) { //
        singleIpInputEl.value = singleIpToTest; //
        showToast('Single IP input auto-corrected.'); //
      }
       if (rangeIpToTest && rangeIpToTest !== rawRangeInput) {
        rangeIpInputEl.value = rangeIpToTest;
        showToast('IP Range input auto-corrected.');
      }

      if (!singleIpToTest && !rangeIpToTest) { //
        showToast('Please enter a single IP/Domain or an IP Range.'); //
        singleIpInputEl.focus(); //
        return; //
      }
      
      const currentTimestamp = calculateTimestamp(); //
      if (currentTimestamp !== pageLoadTimestamp) { //
        const currentHost = window.location.host; //
        const currentProtocol = window.location.protocol; //
        let redirectPathVal = singleIpToTest || rangeIpToTest || ''; //
        const redirectUrl = \`\${currentProtocol}//\${currentHost}/\${encodeURIComponent(redirectPathVal)}\`; //
        showToast('TOKEN expired, refreshing page...'); //
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
      copyRangeBtn.style.display = 'none';
      currentSuccessfulRangeIPs = [];
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
            // Practical limit for client-side batch testing (e.g., /20 has ~4k, /22 has ~1k)
            // Testing more than a few thousand IPs client-side is extremely slow and resource-intensive.
            const PRACTICAL_TEST_LIMIT = 4096; // Example: Max for /20

            if (ipsInRange.length === 0 && rangeIpToTest) {
                // parseIPRange would have shown a toast for invalid format or too large to parse
                // No further action needed here if ipsInRange is empty due to parsing issues.
            } else if (ipsInRange.length > PRACTICAL_TEST_LIMIT) {
                 showToast(\`Cannot test: Range too large (\${ipsInRange.length} IPs). Please use a range with up to \${PRACTICAL_TEST_LIMIT} IPs for client-side testing.\`);
                 rangeResultCard.style.display = 'none';
            } else if (ipsInRange.length > 0) {
                showToast(\`Starting test for \${ipsInRange.length} IPs in range... This may take a while.\`);
                rangeResultCard.style.display = 'block';
                
                let successCount = 0;
                let checkedCount = 0;
                currentSuccessfulRangeIPs = [];

                const batchSize = 20; // Increased batch size slightly
                for (let i = 0; i < ipsInRange.length; i += batchSize) {
                    const batch = ipsInRange.slice(i, i + batchSize);
                    const batchPromises = batch.map(ip => 
                        fetchSingleIPCheck(ip + ':443') // Assuming port 443 for range test
                            .then(data => {
                                checkedCount++;
                                if (data.success) {
                                    successCount++;
                                    currentSuccessfulRangeIPs.push(data.proxyIP);
                                }
                                return data; 
                            })
                            .catch(err => {
                                checkedCount++; 
                                console.error("Error checking IP in range:", ip, err);
                                return {success: false, proxyIP: ip, error: err.message};
                            })
                    );
                    await Promise.all(batchPromises);
                    rangeResultSummary.innerHTML = \`Tested: \${checkedCount}/\${ipsInRange.length} | Successful: \${successCount}\`;
                    
                    if (currentSuccessfulRangeIPs.length > 0) {
                         updateRangeSuccessChart(currentSuccessfulRangeIPs);
                         copyRangeBtn.style.display = 'inline-block';
                    } else {
                         copyRangeBtn.style.display = 'none';
                    }
                    if (i + batchSize < ipsInRange.length) {
                        // Only add delay if not the last batch to avoid unnecessary wait
                        await new Promise(resolve => setTimeout(resolve, 250)); // Slightly longer delay
                    }
                }
                rangeResultSummary.innerHTML = \`Range test complete. \${successCount} of \${ipsInRange.length} IPs were successful.\`;
                if (currentSuccessfulRangeIPs.length === 0 && ipsInRange.length > 0) {
                    showToast('No successful IPs found in the range.');
                }
            }
        }

      } catch (err) { //
        const errorMsg = \`<div class="result-card result-error"><h3>❌ General Error</h3><p>\${err.message}</p></div>\`; //
        if(resultDiv.innerHTML === '') resultDiv.innerHTML = errorMsg; //
        else rangeResultSummary.innerHTML = \`<p style="color:var(--error-color)">Error during range test: \${err.message}</p>\`;
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
        
        const labels = successfulIPs;
        const dataPoints = successfulIPs.map(() => 1); 

        rangeChartInstance = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Successful IPs',
                    data: dataPoints,
                    backgroundColor: 'rgba(46, 204, 113, 0.6)', 
                    borderColor: 'rgba(46, 204, 113, 1)',
                    borderWidth: 1,
                    barPercentage: 0.8, 
                    categoryPercentage: 0.7 
                }]
            },
            options: {
                indexAxis: 'y', 
                responsive: true,
                maintainAspectRatio: false, // Important for custom height
                scales: {
                    x: { 
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1,
                             callback: function(value) { if (value === 1) return 'Success'; return ''; }
                        },
                        title: { display: false }
                    },
                    y: { 
                         ticks: {
                             autoSkip: false, 
                             font: { size: 10 } 
                         },
                         title: {
                             display: false,
                         }
                    }
                },
                plugins: {
                    legend: {
                        display: false, 
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) { 
                                return \`IP: \${context.label} - Status: Successful\`;
                            },
                             title: function() {
                                return ''; 
                            }
                        }
                    }
                }
            }
        });
        const canvas = document.getElementById('rangeSuccessChart');
        const chartContainer = document.getElementById('rangeResultChartContainer');
        const barHeight = 30; 
        // Calculate height based on number of bars, but limit to a max reasonable height
        const calculatedHeight = Math.max(150, labels.length * barHeight);
        const maxHeight = 600; // Max height for the chart area
        const newHeight = Math.min(calculatedHeight, maxHeight); 
        
        canvas.style.height = \`\${newHeight}px\`;
        // The container's height might also need to be managed if it restricts the canvas
        chartContainer.style.height = \`\${newHeight + 20}px\`; // +20 for padding in container

        if(rangeChartInstance) {
             setTimeout(() => { if (rangeChartInstance) rangeChartInstance.resize(); }, 0);
        }
    }
    
    function copySuccessfulRangeIPs() {
        if (currentSuccessfulRangeIPs.length > 0) {
            const textToCopy = currentSuccessfulRangeIPs.join('\\n');
            copyToClipboard(textToCopy, document.getElementById('copyRangeBtn'), "All successful IPs copied!");
        } else {
            showToast("No successful IPs to copy.");
        }
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
            <h3>✅ ProxyIP Valid</h3>
            <p><strong>🌐 ProxyIP Address:</strong> \${createCopyButton(data.proxyIP)} \${ipInfoHTML}</p>
            <p><strong>🔌 Port:</strong> \${createCopyButton(data.portRemote.toString())}</p>
            <p><strong>🕒 Check Time:</strong> \${new Date(data.timestamp).toLocaleString()}</p>
          </div>
        \`; //
      } else { //
        resultDiv.innerHTML = \`
          <div class="result-card result-error">
            <h3>❌ ProxyIP Invalid</h3>
            <p><strong>🌐 IP Address:</strong> \${createCopyButton(proxyip)}</p>
            \${data.error ? \`<p><strong>Error:</strong> \${data.error}</p>\` : ''}
            <p><strong>🕒 Check Time:</strong> \${new Date(data.timestamp).toLocaleString()}</p>
          </div>
        \`; //
      }
      resultDiv.classList.add('show'); //
    }

    async function checkAndDisplayDomain(domain, resultDiv) { //
      let portRemote = 443; //
      let cleanDomain = domain; //
      
      if (domain.includes('.tp')) { //
        const portMatch = domain.match(/\\.tp(\\d+)\\./); //
        if (portMatch) portRemote = parseInt(portMatch[1]); //
        cleanDomain = domain.split('.tp')[0]; //
      } else if (domain.includes('[') && domain.includes(']:')) { //
        portRemote = parseInt(domain.split(']:')[1]) || 443; //
        cleanDomain = domain.split(']:')[0] + ']'; //
      } else if (domain.includes(':') && !domain.startsWith('[')) { //
         const parts = domain.split(':'); //
         if (parts.length === 2) { //
            cleanDomain = parts[0]; //
            const parsedPort = parseInt(parts[1]); //
            if (!isNaN(parsedPort)) portRemote = parsedPort; //
         }
      }
      
      const resolveResponse = await fetch(\`./resolve?domain=\${encodeURIComponent(cleanDomain)}&token=\${TEMP_TOKEN}\`); //
      const resolveData = await resolveResponse.json(); //
      
      if (!resolveData.success) { throw new Error(resolveData.error || 'Domain resolution failed'); } //
      const ips = resolveData.ips; //
      if (!ips || ips.length === 0) { throw new Error('No IPs found for the domain.'); } //
      
      ipCheckResults.clear(); //
      resultDiv.innerHTML = \`
        <div class="result-card result-warning">
          <h3>🔍 Domain Resolution Results</h3>
          <p><strong>🌐 Domain:</strong> \${createCopyButton(cleanDomain)}</p>
          <p><strong>🔌 Default Port for Test:</strong> \${portRemote}</p>
          <p><strong>📋 IPs Found:</strong> \${ips.length}</p>
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
      const validCount = Array.from(ipCheckResults.values()).filter(r => r.success).length; //
      const resultCardHeader = resultDiv.querySelector('.result-card h3'); //
      if(resultCardHeader){ //
          if (validCount === ips.length) resultCardHeader.textContent = '✅ All Domain IPs Valid'; //
          else if (validCount === 0) resultCardHeader.textContent = '❌ All Domain IPs Invalid'; //
          else resultCardHeader.textContent = \`⚠️ Some Domain IPs Valid (\${validCount}/\${ips.length})\`; //
      }
    }

    async function checkDomainIPWithIndex(ip, port, index) { //
      try {
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
        const ipInfo = await getIPInfo(ip.split(':')[0]); //
        const infoElement = document.getElementById(\`ip-info-\${index}\`); //
        if (infoElement) infoElement.innerHTML = formatIPInfo(ipInfo, true); //
      } catch (error) { /* Fail silently */ } //
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
