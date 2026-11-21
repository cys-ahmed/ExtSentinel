# 🛡️ ExtSentinel

<div align="center">

**Browser Extension Threat Scanner & Real-Time Anti-Phishing Defense (Chrome Manifest V3)**

![Manifest V3](https://img.shields.io/badge/Chrome-Manifest_V3-blue?style=for-the-badge&logo=googlechrome)
![React](https://img.shields.io/badge/React-19-61DAFB?style=for-the-badge&logo=react)
![TypeScript](https://img.shields.io/badge/TypeScript-5.9-3178C6?style=for-the-badge&logo=typescript)
![Vite](https://img.shields.io/badge/Vite-7-646CFF?style=for-the-badge&logo=vite)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

</div>

---

## 📖 Overview

**ExtSentinel** is a defensive Chrome extension (Manifest V3) that audits installed browser extensions for high-risk permissions, supply chain tampering, and malicious indicators, while actively monitoring web pages for DOM-based phishing attacks. All analysis runs **100% locally** in your browser — no browsing data or extension metadata is sent to external servers.

### ✨ Key Features

- **Permission Risk Scoring** — Evaluates 40+ Chrome APIs and flags dangerous permission combinations (e.g., `cookies`, `scripting`, `webRequest`, `clipboardRead`, `debugger`).
- **Host Access Auditing** — Detects overly broad host permissions such as `<all_urls>` and `*://*/*`.
- **Real-Time DOM Integrity Monitoring** — Detects invisible login overlays, form action tampering, `form.submit()` hijacking, and prototype pollution (`XMLHttpRequest.prototype`).
- **Publisher & Supply Chain Checks** — Flags sideloaded extensions, suspicious names/impersonation, custom `update_url` channels, and permission escalations.
- **Automated Scanning & Alerts** — Scheduled background scans, install-time scanning, optional auto-disable for critical threats, and real-time browser notifications.

---

## 🚀 Installation & Usage Guide

### Prerequisites

- [Node.js](https://nodejs.org/) (v20+ recommended)
- Google Chrome (or any Chromium-based browser supporting Manifest V3)

### 1. Clone & Install Dependencies

```bash
git clone https://github.com/cys-ahmed/ExtSentinel.git
cd ExtSentinel/app
npm install
```

### 2. Build the Extension

```bash
npm run build
```

This outputs the production extension bundle into `app/dist/`.

### 3. Load into Chrome

1. Open Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select the `app/dist` folder.
4. Pin and click the **ExtSentinel** icon in the toolbar to run your first scan.

### 4. Using ExtSentinel

- **Overview & Extensions Tabs:** View your overall risk breakdown (`Critical`, `High`, `Medium`, `Low`, `Safe`), inspect per-extension findings with mapped technique IDs, and disable or uninstall risky extensions directly from the popup.
- **Alerts Tab:** Review real-time DOM tampering alerts and newly installed high-risk extension alerts.
- **Settings (Options Page):** Configure automatic scan intervals (`1h` to `Weekly`), install-time scanning, DOM & credential protection toggles, detection sensitivity (`Strict`, `Balanced`, `Permissive`), and optional auto-blocking of critical extensions.

---

## 🛡️ Threat Coverage Brief (BET Framework)

ExtSentinel's detection engine is modeled on a MITRE ATT&CK-style **Browser Extension Threat (BET)** framework covering the core browser extension kill chain:

| Threat Stage | What ExtSentinel Detects | Key Defensive Mitigations |
|---|---|---|
| **Initial Access & Supply Chain** (`BET.TA0001`) | Sideloaded extensions, impersonation/masquerading, external `update_url` hijacking | Enforce Chrome Enterprise `ExtensionInstallBlocklist` / `ExtensionInstallAllowlist`, publisher verification, and OAuth consent auditing |
| **Execution & Persistence** (`BET.TA0002`–`TA0004`) | Broad `<all_urls>` script injection, `debugger`/`scripting` abuse, permission escalation on updates | Least-privilege manifest auditing, update review windows, and strict CSP |
| **Credential Access & Collection** (`BET.TA0006`, `TA0009`) | Invisible phishing overlays, form `action`/`submit()` tampering, `cookies`/`clipboardRead` abuse | Real-time DOM integrity monitoring, FIDO2/WebAuthn, and `HttpOnly`/`Secure`/`SameSite` cookies |
| **Evasion, C2 & Exfiltration** (`BET.TA0005`, `TA0010`–`TA0011`) | Prototype tampering (`XMLHttpRequest`), suspicious host/network permissions | Runtime behavioral monitoring, DNS/network filtering, and browser DLP policies |

---

## 📁 Project Structure

```text
ExtSentinel/
├── README.md
├── LICENSE
└── app/
    ├── manifest.json              # Chrome Manifest V3 configuration
    ├── package.json               # Dependencies & scripts
    ├── popup.html / options.html / welcome.html
    ├── public/icons/              # Extension icons (16, 32, 48, 128px)
    └── src/
        ├── background/index.ts    # Service worker (scheduled scans, install hooks, alerts)
        ├── content/index.ts       # Real-time DOM, form & prototype protection
        ├── lib/
        │   ├── detectionEngine.ts # Risk scoring & BET-mapped rule engine
        │   └── storage.ts         # Local Chrome storage wrapper
        ├── popup/PopupApp.tsx     # Extension popup dashboard
        ├── options/OptionsApp.tsx # Settings & sensitivity configuration
        └── welcome/WelcomeApp.tsx # First-install onboarding page
```

### 🛠️ Tech Stack

- **Framework:** React 19, TypeScript, Vite 7
- **UI:** Tailwind CSS, Radix UI (shadcn/ui), Lucide React
- **Browser APIs:** Chrome Manifest V3 (`management`, `storage`, `tabs`, `webNavigation`, `scripting`, `alarms`, `notifications`, `activeTab`)

---

## ⚠️ Research Tool Notice

ExtSentinel is built for **defensive security research and educational use**. It requires the `management` permission solely to inspect installed extensions and performs all analysis locally without transmitting data to external servers.

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
