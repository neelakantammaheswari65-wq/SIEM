# SIEM Insider Threat Detection Platform

An enterprise Security Information and Event Management (SIEM) and Data Loss Prevention (DLP) platform engineered to detect, score, correlate, and respond to insider threats in real-time.

---

## 1. System Architecture

The platform follows a strict client-server architecture with server-authoritative state and persistent database storage:

```
┌────────────────────────────────────────────────────────┐
│               Frontend (React 19 + Vite)               │
│  - SOC Command Dashboard       - Alerts & Correlation  │
│  - User Risk Scoring (24h)     - ML Isolation Forest   │
│  - USB DLP Hardware Control    - Corporate Repository  │
└───────────────────────────┬────────────────────────────┘
                            │ REST API (Bearer JWT)
┌───────────────────────────▼────────────────────────────┐
│              Backend (Express + Node.js)               │
│  - RBAC Middleware             - SIEM Log Normalizer   │
│  - Real-Time Rule Engine       - Risk Score Calculator │
│  - ML Anomaly Engine           - USB Transfer Evaluator│
│  - Security Abuse Detection    - Audit Trail Logger    │
└───────────────────────────┬────────────────────────────┘
                            │ Read / Write Transactions
┌───────────────────────────▼────────────────────────────┐
│          Persistent Database Storage Layer             │
│  - Users & Credentials         - Cataloged Files       │
│  - Security Logs & Events      - Detection Rules       │
│  - Rule Findings & Alerts      - USB Devices & Quotas  │
│  - Security Abuse Records      - Audit Logs            │
└────────────────────────────────────────────────────────┘
```

---

## 2. Role-Based Access Control (RBAC)

The application enforces strict separation of duties across three roles:

| Capability / Section | `ADMIN` | `SECURITY_ANALYST` | `EMPLOYEE` / `VIEWER` |
| :--- | :---: | :---: | :---: |
| **SOC Command Dashboard** | Full Access | Full Access | *Hidden (403)* |
| **Security Alerts & Findings** | Full Access | Full Access | *Hidden (403)* |
| **User Risk Scores & Decay** | Full Access | Full Access | *Hidden (403)* |
| **ML Anomaly Detection** | Full Access | Full Access | *Hidden (403)* |
| **USB Device & Transfer Rules** | Full Access | Full Access | *Hidden (403)* |
| **Detection Rule Creation** | Full Access | Read-Only | *Hidden (403)* |
| **Attack Scenario Injection** | Full Access | *Hidden* | *Hidden (403)* |
| **Audit Compliance Logs** | Full Access | *Hidden* | *Hidden (403)* |
| **Corporate File Repository** | Full Access | Full Access | **Primary Workspace** |
| **Personal Access History** | Full Access | Full Access | **Available** |

---

## 3. Security & Abuse Detection Engine

The platform features built-in threshold and sliding-window abuse detection:

### A. Repeated Sign-up Velocity Monitoring
- **Mechanism**: Tracks registration requests by target identifier and source IP over a sliding window (`SIGNUP_WINDOW_SECONDS`, default 300s).
- **Threshold**: Exceeding `SIGNUP_ATTEMPT_THRESHOLD` (default 3 attempts) logs a `MULTIPLE_SIGNUP_ATTEMPTS` security event and creates a High/Critical severity SIEM alert.
- **Resilience**: Normal 1-2 attempts do not trigger false positive alerts.

### B. Multiple Failed Downloads Monitoring
- **Mechanism**: Tracks file download failures (missing documents, permissions violations, or egress anomalies) per user/IP over `FAILED_DOWNLOAD_WINDOW_SECONDS` (default 300s).
- **Threshold**: Exceeding `FAILED_DOWNLOAD_THRESHOLD` (default 3 failures) logs a `MULTIPLE_FAILED_DOWNLOADS` security event and generates an alert.

---

## 4. Environment Variables

Create a `.env` file in the root directory based on `.env.example`:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PORT` | `3000` | Port for the Express server and Vite reverse proxy |
| `NODE_ENV` | `development` | Runtime environment (`development`, `production`, `test`) |
| `JWT_SECRET` | *(Generated string)* | Secret key for signing and verifying JWT session tokens |
| `SIGNUP_ATTEMPT_THRESHOLD` | `3` | Maximum sign-up attempts before triggering an abuse alert |
| `SIGNUP_WINDOW_SECONDS` | `300` | Sliding window in seconds for sign-up velocity monitoring |
| `FAILED_DOWNLOAD_THRESHOLD` | `3` | Maximum failed downloads before generating an alert |
| `FAILED_DOWNLOAD_WINDOW_SECONDS` | `300` | Sliding window in seconds for download failure tracking |
| `USB_TRANSFER_THRESHOLD_MB` | `500` | DLP payload size quota in MB for USB transfers |
| `LARGE_FILE_THRESHOLD_MB` | `500` | Egress detection threshold for individual file downloads |
| `DATABASE_FILE_PATH` | `./data/siem_database.json` | Path to persistent database JSON file |

---

## 5. Local Installation & Quickstart

### Prerequisites
- Node.js 18+ (or Node.js 20+ recommended)
- npm 9+

### Setup Steps

1. **Clone the repository and install dependencies:**
   ```bash
   npm install
   ```

2. **Configure environment variables:**
   ```bash
   cp .env.example .env
   ```

3. **Start the development server:**
   ```bash
   npm run dev
   ```
   Open your browser at `http://localhost:3000`.

4. **Default Test Accounts:**

   | Role | Username | Password | Purpose |
   | :--- | :--- | :--- | :--- |
   | **Admin** | `admin` | `password123` | Full SOC & platform administration |
   | **Security Analyst** | `dkim` | `password123` | SOC incident investigation & alert triage |
   | **Employee** | `amercer` | `password123` | Corporate document repository & regular workflow |

---

## 6. Automated Testing

The codebase includes comprehensive automated tests spanning unit logic, database integration, API endpoints, abuse detection, and system smoke tests.

Run the test suite:
```bash
npm test
```

Expected output:
```
=============================================================
 SIEM INSIDER THREAT DETECTION PLATFORM - AUTOMATED TEST SUITE
=============================================================
[SUITE 1] Unit Tests: Cryptography, Rule Conditions & Risk Math
  ✔ PASS bcrypt password hashing and verification succeeds
  ✔ PASS bcrypt password verification rejects bad password
  ✔ PASS JWT tokens encode and verify user identity correctly
  ✔ PASS Risk score calculates bounded numeric value (0-100)
  ✔ PASS Risk level maps correctly to categorical enum
  ✔ PASS ML anomaly score computes within valid range (0-100)
  ✔ PASS ML anomaly provides diagnostic feature indicators

[SUITE 2] Integration Tests: Database Persistence & SIEM Engine
  ✔ PASS Database initialized with default user accounts (4 users found)
  ✔ PASS Admin user account exists with ADMIN role
  ✔ PASS Corporate file repository loaded 8 cataloged documents
  ✔ PASS Confidential data classification files exist in database
  ✔ PASS Log entry ingested with auto-increment ID
  ✔ PASS Normalized event successfully processed by rule engine
  ✔ PASS Rule engine flagged 1 findings for large file download
  ✔ PASS Authorized USB drive with small non-sensitive payload is ALLOWED
  ✔ PASS Unauthorized USB drive transfer is BLOCKED by DLP policy

[SUITE 3] Security & Abuse Detection: Sign-up Velocity & Failed Downloads
  ✔ PASS Single normal registration attempt does not trigger abuse alert
  ✔ PASS Rapid repeated sign-up attempts (>= threshold) trigger abuse detection
  ✔ PASS SecurityEvent record created in database for sign-up abuse
  ✔ PASS SecurityEvent type is MULTIPLE_SIGNUP_ATTEMPTS
  ✔ PASS Correlating Alert generated in SIEM alert registry for SOC visibility
  ✔ PASS Single download failure does not trigger abuse alert
  ✔ PASS Repeated failed downloads (>= threshold) trigger abuse detection
  ✔ PASS SecurityEvent type is MULTIPLE_FAILED_DOWNLOADS
  ✔ PASS SIEM Alert created with detailed diagnostic evidence
  ✔ PASS Abuse velocity is tracked independently per user/IP

[SUITE 4] Smoke Test: SOC Summary Aggregation & Audit Trail
  ✔ PASS Total events tracked in database: 3
  ✔ PASS Open SOC incidents tracked: 3
  ✔ PASS Active detection rules: 7
  ✔ PASS Audit compliance trail recorded 3 actions in database

=============================================================
 TEST EXECUTION SUMMARY: 30 PASSED | 0 FAILED
=============================================================
```

---

## 7. Production Build

To compile and package the application for production deployment:
```bash
npm run build
npm start
```
