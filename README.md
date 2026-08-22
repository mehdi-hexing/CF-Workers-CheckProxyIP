# Proxy IP Checker - Cloudflare Worker

A powerful and comprehensive tool for validating IP proxies, running as a serverless Cloudflare Worker. This application allows you to check single IPs, domains, lists of IPs from a file URL, or entire IP ranges. It provides detailed results, including latency, geographic information, and a fraud risk score from the Scamalytics API — with automatic fallbacks so the tool keeps working even if a backend service is unavailable.

---

## 📖 Table of Contents

- [Architecture Overview](#-architecture-overview)
- [Key Features](#-key-features)
- [Prerequisites](#-prerequisites)
- [🚀 Installation and Deployment Guide](#-installation-and-deployment-guide)
  - [Step 1: Deploy the Backend API](#step-1-deploy-the-backend-api)
    - [Option A: Deploy to Vercel (Serverless)](#option-a-deploy-to-vercel-serverless)
    - [Option B: Self-Host on a VPS](#option-b-self-host-on-a-vps)
  - [Step 2: Obtain Scamalytics API Keys (Optional)](#step-2-obtain-scamalytics-api-keys-optional)
  - [Step 3: Configure and Deploy the Cloudflare Worker](#step-3-configure-and-deploy-the-cloudflare-worker)
    - [3.1: Configure the Worker Script](#31-configure-the-worker-script)
    - [3.2: Deploy to Cloudflare Pages](#32-deploy-to-cloudflare-pages)
    - [3.3: Set Environment Variables](#33-set-environment-variables)
- [Step 4: Verify and Use Your Application](#step-4-verify-and-use-your-application)
- [Resumable Scanning & Caching](#-resumable-scanning--caching)
- [IPv6 Support](#-ipv6-support)
- [Troubleshooting](#-troubleshooting)

---

## 🏗️ Architecture Overview

The system consists of three main components that work together:

1.  **Frontend UI:** A static web page served by Cloudflare Pages/Workers. This is where you interact with the application, enter the IPs or domains to check, and see the results. It ships with a glassmorphism-style UI, a GitHub-inspired light/dark color theme, and a mobile-friendly layout.
2.  **Cloudflare Worker:** The core logic of the application. It handles incoming requests from the frontend, manages the user interface, resolves domains (IPv4 **and** IPv6), and communicates with the backend services for complex tasks.
3.  **Backend API:** An external service responsible for performing the actual TCP connection test to the proxy IPs. This is crucial because Cloudflare Workers have limitations on making arbitrary outbound TCP connections. This API can be deployed on Vercel or a personal server.

**Workflow:**
`User` ↔️ `Frontend UI (Cloudflare Pages/Workers)` ↔️ `Cloudflare Worker` ➡️ `Backend API` & `Scamalytics API` (with automatic fallbacks for both)

---

## ✨ Key Features

-   **Multiple Input Formats:** Check a single IP, a list of IPs/domains, an IP range (CIDR or hyphenated), or a URL to a raw text/csv file.
-   **IPv4 & IPv6 Support:** Accepts bare IPv6 (`2001:db8::1`), bracketed IPv6 (`[2001:db8::1]`), and bracketed IPv6 with a port (`[2001:db8::1]:8443`), in every input format — single/multi IP, domain resolution (A **and** AAAA records), and file-based lists.
-   **Fraud Risk Analysis with Automatic Fallback:** Integrates with the Scamalytics API to provide a risk score (`low`, `medium`, `high`) for each IP. If the official API isn't configured, is rate-limited, or is temporarily unavailable, the Worker automatically falls back to a public Scamalytics mirror so you keep getting risk data (and basic geo data) without interruption — **the `SCAMALYTICS_USERNAME`/`SCAMALYTICS_API_KEY` variables are now optional**, not required.
-   **Resilient `/api/check` Endpoint:** If the external backend API fails unexpectedly for any reason, the Worker itself performs a direct TCP check as a last resort before giving up, so a single flaky request never surfaces a raw error to the user.
-   **Failed-IP Visibility:** Every check page (domain, multi-IP/range/file, and the in-place checks on the main page) now shows which IPs *failed* — not just the successful ones — each with its error reason, a per-item remove (×) button, and a "Clear All" action, so you can quickly spot and discard dead entries (e.g. when checking the IPs behind a domain).
-   **Resumable Scanning:** Results are cached incrementally (per IP, not just per batch) and force-saved right before the tab closes or refreshes. Interrupting a large scan (e.g. a big free-proxy range or file list) and reloading the page **resumes from where it left off** instead of re-testing everything from scratch.
-   **Detailed Information:** Get latency (ping), country, ASN/organization, and risk score for every successful proxy.
-   **Modern, Responsive, Glassmorphism UI:** A clean interface with soft "squircle" rounded corners and frosted-glass cards/badges, a GitHub-style light/dark theme (with a subtle glow around the title in dark mode and a soft shadow in light mode), and a mobile layout where IP tags and their detail badges wrap cleanly instead of colliding or running together.
-   **High Availability:** Uses a fallback mechanism, allowing you to specify multiple backend API endpoints for redundancy, on top of the Scamalytics and geo-lookup fallbacks described above.
-   **Fully Serverless:** The entire stack can be run on serverless platforms (Cloudflare and Vercel) for scalability and low maintenance.

---

## ✅ Prerequisites

Before you begin, ensure you have the following:

-   A **Cloudflare account**.
-   A **GitHub account**.
-   A **Vercel account** (if you choose Option A for the backend).
-   A **VPS/Server** with Python and Pip installed (if you choose Option B for the backend).
-   A **Scamalytics account** — *optional*. Without it, risk scoring automatically uses the public fallback mirror instead.

---

## 🚀 Installation and Deployment Guide

Follow these steps carefully to get your proxy checker up and running.

### Step 1: Deploy the Backend API

The Cloudflare Worker needs a backend service to check proxies. Choose one of the following two options.

#### Option A: Deploy to Vercel (Serverless)

This is the easiest method and requires no server management.

1.  **Go to the Backend API Repository:** Navigate to [ProxyIP-Checker-vercel-API](https://github.com/mehdi-hexing/ProxyIP-Checker-vercel-API).
2.  **Deploy the Project:** Click the **"Deploy"** button on the repository's README. Vercel will guide you to create a copy of the project and deploy it automatically.
3.  **Get Your URL:** Once the deployment is complete, Vercel will assign a production URL to your project (e.g., `https://my-proxy-api.vercel.app`).
4.  **Save this URL!** You will need it in Step 3.

#### Option B: Self-Host on a VPS

Use this option if you have your own server and want full control.

1.  **SSH into your server** and clone the repository:
    ```bash
    git clone https://github.com/mehdi-hexing/ProxyIP-Checker-API.git
    cd ProxyIP-Checker-API
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the API inside a `screen` session.** This ensures the API keeps running even after you disconnect from the server. `screen -S my_api_session` creates a new session.
    ```bash
    screen -S proxy-api
    python main.py --port 8080
    ```
    *(You can use any port you like. Just make sure it is open in your server's firewall.)*

4.  **Detach from the screen session** by pressing `Ctrl+A`, then `D`. The API is now running in the background.

5.  **Get Your URL:** Your API endpoint will be `http://<YOUR_SERVER_IP>:8080`.

6.  **Verify it's working** by running this command from your local machine or another terminal — for an IPv4 target:
    ```bash
    curl http://<YOUR_SERVER_IP>:8080/api/v1/check?proxyip=1.1.1.1
    ```
    and for an IPv6 target (the API accepts bare or bracketed IPv6, with or without a port):
    ```bash
    curl "http://<YOUR_SERVER_IP>:8080/api/v1/check?proxyip=[2606:4700:4700::1111]:443"
    ```
    You should receive a JSON response in both cases. **Save this URL!**

### Step 2: Obtain Scamalytics API Keys (Optional)

For the fraud risk score feature, you can optionally use your own Scamalytics API key for higher accuracy and your own quota. **This step can be skipped** — if you don't configure a key, the Worker automatically uses a public Scamalytics fallback mirror to keep providing risk scores and basic geo data.

1.  **Register:** Go to [Scamalytics.com](https://scamalytics.com/) and sign up for a **Free** account. The free plan provides 5,000 queries per month.
2.  **Confirm Your Email:** You will receive a confirmation email. Click the link inside to verify your account.
3.  **Justify API Usage:** You may be asked to provide a reason for needing API access. A simple explanation like "For a personal project to check proxy IP security" is sufficient.
4.  **Wait for Approval:** API key activation is a manual process and can take up to **24 hours**.
5.  **Get Your Credentials:** Once approved, log in to your Scamalytics dashboard and find your **Username** and **API Key**. Save these for the next step.

> **Note:** Even if you *do* configure your own key, the Worker will still transparently fall back to the public mirror if your account ever runs out of quota or the official API is briefly unreachable — you don't need to do anything extra to benefit from this.

### Step 3: Configure and Deploy the Cloudflare Worker

Now you will connect your backend API (and, optionally, your Scamalytics keys) to the main worker code and deploy it.

#### 3.1: Configure the Worker Script

1.  **Open the `_worker.js` file** in a text editor.
2.  **Find the `apiUrls` array** inside the `checkProxyIP` function.
3.  **Replace the placeholder URLs** with the URL(s) of the backend API you deployed in Step 1. You can add more than one URL for fallback redundancy.

    **Before:**
    ```javascript
    const apiUrls = [
        `http://proxy-ip-checker-vercel-api.vercel.app/api/v1/check?proxyip=${encodeURIComponent(proxyIPInput)}`,
        `http://23.27.249.18:9782/api/v1/check?proxyip=${encodeURIComponent(proxyIPInput)}`
    ];
    ```

    **After (Example using your own URLs):**
    ```javascript
    const apiUrls = [
        `https://my-proxy-api.vercel.app/api/v1/check?proxyip=${encodeURIComponent(proxyIPInput)}`, // Your Vercel URL
        `http://198.51.100.10:8080/api/v1/check?proxyip=${encodeURIComponent(proxyIPInput)}`     // Your Self-hosted URL
    ];
    ```

    If every URL in this list fails or times out, the Worker automatically performs a direct TCP check itself before giving up, so a single backend outage won't take the whole tool down.

#### 3.2: Deploy to Cloudflare Pages

1.  **Create a ZIP file:** Compress the project folder containing your modified `_worker.js` file into a single `.zip` archive.
2.  **Navigate to Cloudflare:** Log in to your Cloudflare dashboard.
3.  **Go to Pages:** In the sidebar, go to `Workers & Pages`.
4.  **Create a New Application:** Click on `Create application`, then select the `Pages` tab, and finally click `Upload assets`.
5.  **Upload:** Give your project a name and drag-and-drop your `.zip` file into the upload box.
6.  **Deploy:** Click `Deploy site`.

#### 3.3: Set Environment Variables

1.  After the deployment is initiated, go to your new project's **Settings** tab.
2.  Select **Environment variables** from the settings menu.
3.  Add the following variables using the credentials you saved from Step 2 — **all of them are optional**; skip them entirely to rely on the built-in fallback mirror.

| Variable Name              | Value                             | Required |
| :-----------------------   | :-------------------------------- | :------- |
| `SCAMALYTICS_USERNAME`     | Your Scamalytics username         | No       |
| `SCAMALYTICS_API_KEY`      | Your Scamalytics API key          | No       |
| `SCAMALYTICS_API_BASE_URL` | Your Scamalytics Base URL         | No       |

4.  After adding the variables, go to the **Deployments** tab and **re-deploy** the latest version to apply the new settings.

---

### Step 4: Verify and Use Your Application

Your proxy checker should now be live!

1.  **Visit the URL:** Go to the URL provided by Cloudflare Pages (e.g., `https://your-project-name.pages.dev`).
2.  **Test It:** Try checking a known proxy IP like `1.1.1.1` (or an input like `127.0.0.1:1234` or a domain like `di.nscl.ir`, as shown in the placeholder text) to see if you get a result.
3.  **Use Different Paths:** You can also test different functionalities directly via URL paths — IPv6 is supported everywhere IPv4 is:
    -   **Multiple IPs:** `https://your-project.pages.dev/proxyip/1.1.1.1,8.8.8.8,[2606:4700:4700::1111]:443`
    -   **IP Range:** `https://your-project.pages.dev/iprange/1.1.1.0/24`
    -   **File URL:** `https://your-project.pages.dev/file/https://raw.githubusercontent.com/user/repo/main/ips.txt`
    -   **Domain:** `https://your-project.pages.dev/domain/google.com` (resolves both A and AAAA records)

---

## 🔄 Resumable Scanning & Caching

Large scans (a big IP range, a long file-based proxy list, or many domains at once) can take a while. To make sure that time is never wasted:

-   Every result is written to the browser's local storage **as soon as that individual IP finishes checking** (throttled slightly to avoid excessive writes), rather than only after an entire batch completes.
-   A save is also **force-flushed immediately** whenever the tab is refreshed, closed, or hidden (`beforeunload` / `pagehide` / `visibilitychange`), so nothing that has already completed is ever lost.
-   On reload, the page reads back whatever was cached for that exact input (keyed by URL path or, on the main page, by a hash of the input list) and **only re-tests IPs that haven't been checked yet** — already-successful and already-failed IPs are shown immediately without re-querying anything.
-   Starting a scan with a genuinely different input (a different domain, a different IP list, a different range) always gets its own separate cache key, so old and new results never mix.

---

## 🌐 IPv6 Support

IPv6 addresses are supported throughout the stack:

-   **Input formats accepted:** bare (`2001:db8::1`), bracketed (`[2001:db8::1]`), and bracketed with a port (`[2001:db8::1]:8443`) — in the single/multi-IP box, the IP-range box (bracket form only; CIDR ranges remain IPv4-only), file-based lists, and domain resolution.
-   **Domain resolution:** looks up both `A` and `AAAA` records, so a domain that only has IPv6 proxy IPs behind it will still be found.
-   **Geo & risk lookups:** both the primary (`ip-api.com`) and fallback (Scamalytics mirror) geo lookups work transparently with IPv6 addresses.
-   **Backend API:** the companion [ProxyIP-Checker-API](https://github.com/mehdi-hexing/ProxyIP-Checker-API) also parses all of the input forms above correctly (it previously mis-parsed IPv6 addresses because a naive `rsplit(":", 1)` port-split doesn't work when the address itself contains colons) and passes IPv6 literals to `curl`'s `--resolve` option correctly bracketed, as libcurl requires.

---

## 🤕 Troubleshooting

If you encounter issues, check the following common problems:

-   **"API check failed" Error:**
    -   This should now be rare: if every URL in `apiUrls` fails, the Worker performs a direct TCP check itself before giving up. If you still see this, verify that your backend API (Vercel or self-hosted) is running and accessible, and check its logs for errors.
    -   If self-hosting, ensure the port is open in your server's firewall.
    -   Double-check that you correctly replaced the URLs in the `_worker.js` file.

-   **Risk Score is "N/A" or shows an error:**
    -   This should also be rare now, since risk scoring automatically falls back to a public Scamalytics mirror when the official API isn't configured or is unavailable.
    -   If you *are* using your own Scamalytics account and still see issues, go to your Cloudflare project's settings and ensure the `SCAMALYTICS_USERNAME` and `SCAMALYTICS_API_KEY` environment variables are set correctly (no typos or extra spaces), and confirm your API key has been approved and activated on the Scamalytics dashboard.

-   **A scan seems to restart from the beginning after a refresh:**
    -   Make sure you reloaded the *exact same* input (same URL / same pasted IP list, domain, or range) — a different input intentionally gets a fresh cache.
    -   Clearing your browser's local storage for the site will also reset all cached progress.

-   **Cloudflare Worker Errors (e.g., 500 Internal Server Error):**
    -   This often happens if environment variables are missing. Redeploy your project after ensuring all required variables are set.
    -   Check the logs for your worker in the Cloudflare dashboard for more specific error details.
