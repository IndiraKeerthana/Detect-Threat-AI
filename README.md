# 🛡️ DetectThreatAI

### AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform

DetectThreatAI is an AI-assisted email forensic investigation platform that helps security analysts investigate suspicious emails, identify threats, analyze email infrastructure, correlate indicators, and generate AI-powered threat assessments.

Built for **Smart India Hackathon 2026 – SIH26106**.

---

## Problem

Email attacks such as phishing, Business Email Compromise (BEC), spoofing, and credential theft often require investigation across multiple sources.

Analysts need to examine:

- Email headers and SMTP relay paths
- SPF, DKIM and DMARC
- IP addresses, domains and URLs
- IP reputation and geolocation
- DNS and domain intelligence
- Related infrastructure and entities

DetectThreatAI brings these capabilities together into a **single investigation workflow**, reducing the need to switch between multiple tools.

---

# Key Features

### 📧 Email Forensics
- `.eml` email parsing
- Header and metadata analysis
- SMTP relay path analysis
- Originating IP extraction
- URL, domain and IOC extraction
- Attachment analysis

### 🔐 Email Authentication
- SPF header analysis
- Live SPF DNS policy
- DKIM MTA-reported results
- DMARC header analysis
- Live DMARC DNS policy
- Domain alignment analysis

### 🌐 Threat & Infrastructure Intelligence
- IP reputation
- IP geolocation
- ASN and network intelligence
- DNS intelligence
- RDAP/domain registration information
- VPN/cloud indicators
- Passive TOR exit-node intelligence

### 🧠 AI Investigation
AI analyzes the collected forensic evidence to provide:

- Threat classification
- Phishing/BEC assessment
- Key findings
- Confidence
- Reasoning
- Recommended actions

### 🔗 Investigation & Evidence
- Entity correlation
- Investigation graph
- Case and campaign management
- Original `.eml` SHA-256
- Attachment SHA-256
- Evidence provenance
- Forensic PDF reports
- Evidence retention support

---

# How It Works

```text
                Suspicious .EML
                       │
                       ▼
              Email Forensics
                       │
                       ▼
          Header & Authentication
             SPF / DKIM / DMARC
                       │
                       ▼
                IOC Extraction
             IP / Domain / URL
                       │
                       ▼
          Threat Intelligence
       Reputation / DNS / Geo / ASN
                       │
                       ▼
         Infrastructure Correlation
                       │
                       ▼
              AI Investigation
                       │
                       ▼
          Final Threat Assessment
                       │
                       ▼
             Analyst Dashboard
````

---

# Architecture

```text
┌──────────────────────────────┐
│       React + TypeScript     │
│          Frontend            │
└──────────────┬───────────────┘
               │ REST API
               ▼
┌──────────────────────────────┐
│           FastAPI            │
│           Backend            │
└──────────────┬───────────────┘
               │
      ┌────────┼────────┐
      ▼        ▼        ▼
  Forensics  Threat   Evidence
             Intel    & Cases
      │        │        │
      └────────┼────────┘
               ▼
        AI Investigation
               │
               ▼
       Threat Assessment
```

---

# Technology Stack

| Layer                       | Technologies                          |
| --------------------------- | ------------------------------------- |
| Frontend                    | React, TypeScript, Vite, Tailwind CSS |
| Backend                     | Python, FastAPI, Pydantic             |
| Database                    | PostgreSQL / Supabase, SQLite         |
| AI                          | Groq API                              |
| Visualization               | Leaflet, Cytoscape                    |
| Reporting                   | ReportLab                             |
| Threat Intelligence         | AbuseIPDB, VirusTotal, DNS, RDAP      |
| Infrastructure Intelligence | Geolocation, ASN, TOR                 |

---

# Project Structure

```text
Detect-Threat-AI/
│
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── schemas/
│   │   ├── services/
│   │   ├── config.py
│   │   └── main.py
│   ├── tests/
│   ├── requirements.txt
│   └── .env.example
│
├── frontend/
│   ├── src/
│   ├── public/
│   ├── package.json
│   └── vite.config.ts
│
└── README.md
```

---

# Local Setup

## 1. Clone

```bash
git clone https://github.com/IndiraKeerthana/Detect-Threat-AI.git
cd Detect-Threat-AI
```

## 2. Backend

```bash
cd backend

python -m venv venv
```

### Windows

```bash
venv\Scripts\activate
```

### Linux / macOS

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Create `.env` using `.env.example` and configure the required API keys and database settings.

Run:

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8001
```

Backend:

```text
http://localhost:8001
```

Health check:

```text
http://localhost:8001/api/health
```

---

# Frontend

Open a new terminal:

```bash
cd frontend
npm install
```

Create `.env`:

```env
VITE_API_URL=http://localhost:8001
```

Run:

```bash
npm run dev
```

Frontend:

```text
http://localhost:5173
```

---

# Testing

### Backend

```bash
cd backend
python -m pytest
```

### Frontend

```bash
cd frontend
npm run build
```

---

# Deployment

### Backend

The FastAPI backend can be deployed using **Render**.

Example start command:

```bash
uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

### Frontend

The React/Vite frontend can be deployed using **Vercel**.

Build command:

```bash
npm run build
```

Output directory:

```text
dist
```

Production API configuration:

```env
VITE_API_URL=https://your-backend-url
```

---

# Security & Evidence

DetectThreatAI includes mechanisms for preserving investigation evidence and maintaining integrity information.

The platform supports:

* Original `.eml` SHA-256
* Attachment SHA-256
* Evidence IDs
* Evidence provenance
* Case association
* Processing timestamps
* Evidence lifecycle/retention handling

API credentials remain on the backend and are not exposed to the frontend.

> Evidence provenance is intended for internal investigative support and does not by itself constitute court-admissible chain of custody.

---

# SIH26106 Alignment

| SIH26106 Requirement       | DetectThreatAI                             |
| -------------------------- | ------------------------------------------ |
| Fraudulent email detection | AI-assisted threat analysis                |
| Phishing & BEC             | Threat classification and content analysis |
| Header forensics           | Header and SMTP relay analysis             |
| SPF / DKIM / DMARC         | Authentication analysis                    |
| IOC extraction             | IP, domain, URL and attachment indicators  |
| Originating IP             | Email header analysis                      |
| Geolocation                | IP geolocation                             |
| Threat intelligence        | Reputation and infrastructure intelligence |
| VPN / TOR / Cloud          | Infrastructure indicators                  |
| Domain intelligence        | DNS + RDAP                                 |
| Entity correlation         | Investigation relationships                |
| Graph analysis             | Interactive investigation graph            |
| AI assessment              | AI-generated classification and reasoning  |
| Case management            | Cases and campaigns                        |
| Forensic reporting         | PDF reports                                |
| Evidence integrity         | SHA-256 + provenance                       |
| Evidence lifecycle         | Configurable retention                     |

---

# Current Limitations

DetectThreatAI is designed as an **investigative assistance platform**.

It does not claim:

* Definitive human attacker identification
* Physical attacker location
* Court-admissible chain of custody
* Native cryptographic DKIM verification
* Active TOR network scanning
* Active open-relay probing
* Definitive attribution of infrastructure ownership

The platform instead combines **forensic evidence, threat intelligence, infrastructure correlation, and AI-assisted assessment** to support analysts.

---

# Intended Users

* SOC Analysts
* Security Analysts
* Incident Response Teams
* Cybersecurity Teams
* Cybercrime/Fraud Investigation Teams
* Institutional IT/Security Administrators

---

# 🏆 Smart India Hackathon 2026

**Problem Statement:** SIH26106

**Title:** AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform

**Organization:** AICTE – Cyber Security Cell

**Category:** Software

**Theme:** Blockchain & Cybersecurity

---

## ⭐ DetectThreatAI

**Investigate the email. Trace the infrastructure. Understand the threat.**

---

```
