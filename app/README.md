# ExtSentinel - Browser Extension Security Scanner

ExtSentinel is a defensive security tool designed to identify potentially malicious browser extensions, monitor for phishing attempts, and protect your browser from supply chain attacks. It implements detection strategies from the Browser Extension Threat (BET) Matrix.

## 🛡️ Key Features

- **Permission Analysis**: Scores 40+ Chrome APIs by risk level.
- **Host Access Scanning**: Identifies broad host permissions (e.g., `<all_urls>`).
- **DOM Integrity Monitoring**: Real-time detection of overlays and form tampering.
- **Publisher Verification**: Flags sideloaded extensions and suspicious naming patterns.
- **Supply Chain Detection**: Monitors for permission escalations in updates.
- **Alert System**: Real-time notifications for critical findings.

---

## 🚀 How to Run

### 1. Prerequisites
Ensure you have [Node.js](https://nodejs.org/) installed on your system.

### 2. Install Dependencies
Navigate to the `app` directory and install the necessary packages:
```bash
cd app
npm install
```

### 3. Build the Extension
Generate the production bundle in the `dist` directory:
```bash
npm run build
```

### 4. Load into Chrome
1. Open Google Chrome.
2. Navigate to `chrome://extensions/`.
3. Enable **Developer mode** using the toggle in the top-right corner.
4. Click the **Load unpacked** button.
5. Select the `dist` folder located inside the `app` directory.

### 5. Start Scanning
Click the **ExtSentinel** icon in your browser toolbar to run your first security scan.

---

## 📝 Research Tool Notice
ExtSentinel is a defensive security research tool. It requires the `management` permission to analyze other installed extensions. All analysis is performed locally on your machine—no data is sent to external servers.

## 🛠️ Tech Stack
- **Framework**: React 19
- **Build Tool**: Vite 7
- **Styling**: Tailwind CSS
- **Icons**: Lucide React
- **Language**: TypeScript
