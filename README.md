# Proxy IP Checker - Cloudflare Worker

A powerful and comprehensive tool for validating IP proxies, running as a serverless Cloudflare Worker. This application allows you to check single IPs, domains, lists of IPs from a file URL, or entire IP ranges. It provides detailed results, including latency, geographic information, and a fraud risk score from the Scamalytics API.

---

## 📖 Table of Contents

- [Architecture Overview](#-architecture-overview)
- [Key Features](#-key-features)
- [Prerequisites](#-prerequisites)
- [🚀 Installation and Deployment Guide](#-installation-and-deployment-guide)
  - [Step 1: Deploy the Backend API](#step-1-deploy-the-backend-api)
    - [Option A: Deploy to Vercel (Serverless)](#option-a-deploy-to-vercel-serverless)
    - [Option B: Self-Host on a VPS](#option-b-self-host-on-a-vps)
  - [Step 2: Obtain Scamalytics API Keys](#step-2-obtain-scamalytics-api-keys)
  - [Step 3: Configure and Deploy the Cloudflare Worker](#step-3-configure-and-deploy-the-cloudflare-worker)
    - [3.1: Configure the Worker Script](#31-configure-the-worker-script)
    - [3.2: Deploy to Cloudflare Pages](#32-deploy-to-cloudflare-pages)
    - [3.3: Set Environment Variables](#33-set-environment-variables)
- [Step 4: Verify and Use Your Application](#step-4-verify-and-use-your-application)
- [Troubleshooting](#-troubleshooting)

---

## 🏗️ Architecture Overview

The system consists of three main components that work together:

1.  **Frontend UI:** A static web page served by Cloudflare Pages. This is where you interact with the application, enter the IPs or domains to check, and see the results.
2.  **Cloudflare Worker:** The core logic of the application. It handles incoming requests from the frontend, manages the user interface, and communicates with the backend services for complex tasks.
3.  **Backend API:** An external service responsible for performing the actual TCP connection test to the proxy IPs. This is crucial because Cloudflare Workers have limitations on making arbitrary outbound TCP connections. This API can be deployed on Vercel or a personal server.

**Workflow:**
`User` ↔️ `Frontend UI (Cloudflare Pages)` ↔️ `Cloudflare Worker` ➡️ `Backend API` & `Scamalytics API`

---

## ✨ Key Features

-   **Multiple Input Formats:** Check a single IP, a list of IPs/domains, an IP range (CIDR or hyphenated), or a URL to a raw text/csv file.
-   **Fraud Risk Analysis:** Integrates with the Scamalytics API to provide a risk score (`low`, `medium`, `high`) for each IP.
-   **Detailed Information:** Get latency (ping), country, and ASN (organization) for every successful proxy.
-   **Modern & Responsive UI:** A clean, user-friendly interface with dark mode support.
-   **High Availability:** Uses a fallback mechanism, allowing you to specify multiple backend API endpoints for redundancy.
-   **Fully Serverless:** The entire stack can be run on serverless platforms (Cloudflare and Vercel) for scalability and low maintenance.

---

## ✅ Prerequisites

Before you begin, ensure you have the following:

-   A **Cloudflare account**.
-   A **GitHub account**.
-   A **Vercel account** (if you choose Option A for the backend).
-   A **VPS/Server** with Python and Pip installed (if you choose Option B for the backend).

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
    git clone [https://github.com/mehdi-hexing/ProxyIP-Checker-API.git](https://github.com/mehdi-hexing/ProxyIP-Checker-API.git)
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

6.  **Verify it's working** by running this command from your local machine or another terminal:
    ```bash
    curl http://<YOUR_SERVER_IP>:8080/api/v1/check?proxyip=1.1.1.1
    ```
    You should receive a JSON response. **Save this URL!**

### Step 2: Obtain Scamalytics API Keys

For the fraud risk score feature, you need a free API key from Scamalytics.

1.  **Register:** Go to [Scamalytics.com](https://scamalytics.com/) and sign up for a **Free** account. The free plan provides 5,000 queries per month.
2.  **Confirm Your Email:** You will receive a confirmation email. Click the link inside to verify your account.
3.  **Justify API Usage:** You may be asked to provide a reason for needing API access. A simple explanation like "For a personal project to check proxy IP security" is sufficient.
4.  **Wait for Approval:** API key activation is a manual process and can take up to **24 hours**.
5.  **Get Your Credentials:** Once approved, log in to your Scamalytics dashboard and find your **Username** and **API Key**. Save these for the next step.

### Step 3: Configure and Deploy the Cloudflare Worker

Now you will connect your backend API and Scamalytics keys to the main worker code and deploy it.

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
3.  Add the following variables using the credentials you saved from Step 2.

| Variable Name              | Value                             | Required |
| :-----------------------   | :-------------------------------- | :------- |
| `SCAMALYTICS_USERNAME`     | Your Scamalytics username         | Yes      |
| `SCAMALYTICS_API_KEY`      | Your Scamalytics API key          | Yes      |
| `SCAMALYTICS_API_BASE_URL` | Your Scamalytics Base URL         | Yes      |

4.  After adding the variables, go to the **Deployments** tab and **re-deploy** the latest version to apply the new settings.

---

### Step 4: Verify and Use Your Application

Your proxy checker should now be live!

1.  **Visit the URL:** Go to the URL provided by Cloudflare Pages (e.g., `https://your-project-name.pages.dev`).
2.  **Test It:** Try checking a known proxy IP like `1.1.1.1` to see if you get a result.
3.  **Use Different Paths:** You can also test different functionalities directly via URL paths:
    -   **Multiple IPs:** `https://your-project.pages.dev/proxyip/1.1.1.1,8.8.8.8`
    -   **IP Range:** `https://your-project.pages.dev/iprange/1.1.1.0/24`
    -   **File URL:** `https://your-project.pages.dev/file/https://raw.githubusercontent.com/user/repo/main/ips.txt`
    -   **Domain:** `https://your-project.pages.dev/domain/google.com`

---

## 🤕 Troubleshooting

If you encounter issues, check the following common problems:

-   **"API check failed" Error:**
    -   Verify that your backend API (Vercel or self-hosted) is running and accessible. Check its logs for errors.
    -   If self-hosting, ensure the port is open in your server's firewall.
    -   Double-check that you correctly replaced the URLs in the `_worker.js` file.

-   **Risk Score is "N/A" or shows an error:**
    -   Go to your Cloudflare project's settings and ensure the `SCAMALYTICS_USERNAME` and `SCAMALYTICS_API_KEY` environment variables are set correctly (no typos or extra spaces).
    -   Log in to your Scamalytics account and confirm that your API key has been approved and activated.

-   **Cloudflare Worker Errors (e.g., 500 Internal Server Error):**
    -   This often happens if environment variables are missing. Redeploy your project after ensuring all required variables are set.
    -   Check the logs for your worker in the Cloudflare dashboard for more specific error details.
