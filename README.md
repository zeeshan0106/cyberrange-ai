# CyberRange AI

> Practise detection and response before a real incident.

CyberRange AI is a cybersecurity training platform that generates phishing, ransomware, and multi-stage attack scenarios mapped to MITRE ATT&CK, with interactive quizzes and a progress dashboard. Scenarios are produced by a large language model (LLM), with a rule-based fallback and structured validation of the output. All content is simulated and intended for educational use only.

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Architecture](#architecture)
4. [Setup](#setup)
5. [Configuration](#configuration)
6. [Testing](#testing)
7. [Roadmap](#roadmap)
8. [Disclaimer](#disclaimer)

---

## Overview

CyberRange AI gives security students and practitioners hands-on exposure to how attacks are structured, detected, and contained — without touching real infrastructure. Each simulation is generated on demand by an LLM configured through environment variables. If the LLM is unavailable or produces invalid output, a rule-based fallback takes over so the platform always returns a usable result.

---

## Features

### Phishing Simulator
- Generates a realistic phishing email tailored to the chosen **target role**, **industry**, and **difficulty** (Easy / Medium / Hard).
- Output includes: sender name, sender address, reply-to address, recipient name, date sent, link display text, link URL.
- All domains in sender addresses and links use reserved TLDs (`.example` or `.test`). Real domains are rejected and retried.
- **Header analysis**: SPF, DKIM, and DMARC fields (`pass` / `fail` / `softfail` / `none`) consistent with the scenario.
- **Red flags** (structured): each flag includes the flag label, the exact evidence string from the email, and an explanation. Count is difficulty-gated (Easy: 4–5, Medium: 3–4, Hard: 2–3). At least one flag concerns the sender address or domain.
- **Psychological triggers**: list of persuasion techniques and where each appears in the email.
- **Safe response**: three short action steps.
- Full email-client UI with header-auth badges, collapsible sections, and plain-text link rendering (never clickable anchors).

### Ransomware Simulator
- Generates a ransomware infection chain based on the chosen **attack vector** (e.g. Email Attachment) and **organisation type** (e.g. Healthcare).
- Each infection step is a structured object with: step number, title, description specific to the inputs, ATT&CK tactic, technique ID, technique name, detection indicators, and containment actions.
- Technique IDs and names are validated against the official MITRE ATT&CK Enterprise dataset (858 techniques). Invalid IDs are corrected.
- Output also includes: a summary, a structured incident-response plan with phases, and impact/prevention guidance.
- `generation_source` (`"llm"` or `"fallback"`) and `fallback_reason` are returned on every response.

### Attack Scenario (Multi-Stage APT)
- Generates a kill-chain-ordered attack scenario for a given organisation type and security maturity level.
- Each stage maps to a MITRE ATT&CK technique, validated against the same 858-technique dataset.
- Includes detection and response guidance per stage.

### Training Mode
- Interactive quiz with questions across four categories: **Phishing**, **Ransomware**, **Incident Response**, **General Security**.
- Category is set by the backend from the request — the LLM cannot override it.
- Backend sanitisation before validation: strips leading option labels (`A)`, `A.`, `A:`, `(A)`), strips HTML tags, normalises `\n` sequences, trims whitespace.
- Option shuffle: correct answer is placed in a random position on every question to prevent positional bias.
- Options are length-balanced (no single option is more than 1.8× the mean length) to avoid the "longest option is always correct" pattern.
- **Skip** support: questions can be skipped; skips are recorded and shown in the feedback panel.
- Per-question feedback shows all option explanations, whether the question was skipped, and a running score.
- A fallback bank of 32 questions (8 per category) is used when the LLM is unavailable or produces invalid output. The bank cycles without repeating a question until all have been shown.

### Dashboard
- Five metric cards: Total Score, Questions Answered, Overall Accuracy, Current Streak, Weakest Area.
- Three Recharts charts:
  - **Simulations by Type** (bar chart) — counts of phishing, ransomware, and attack-scenario simulations run.
  - **Category Accuracy** (bar chart) — accuracy per training category.
  - **Score Over Time** (line chart) — cumulative score across answered questions.
- Weakest Area and Recommended Next cards surface actionable next steps.
- Score and metrics are computed from a single source of truth in the backend (`compute_training_metrics()`), so Training Mode and Dashboard always agree.

---

## Architecture

```
cyber-range-main/
├── backend/
│   ├── server.py          # All FastAPI models, endpoints, fallback generators (~4 400 lines)
│   ├── config.py          # Pydantic-settings: LLM_API_KEY, LLM_MODEL, timeouts, DB config
│   ├── llm_service.py     # execute_llm_with_validation() — retry-once-then-fallback pattern
│   ├── data/              # MITRE ATT&CK Enterprise lookup JSON (858 techniques)
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── pages/         # Dashboard, PhishingSimulator, RansomwareSimulator,
│   │   │                  # AttackScenario, TrainingMode, About, Home
│   │   └── components/    # Layout, Radix UI wrappers
│   └── package.json
├── tests/
│   ├── test_phishing.py        # 101 tests
│   ├── test_ransomware.py      # 58 tests
│   ├── test_attack_scenario.py # 22 tests
│   ├── test_llm_reliability.py # 9 tests
│   └── test_training.py        # 13 tests
└── README.md
```

### LLM Reliability Layer (applies to all modules)
Every generation endpoint follows the same pattern:
1. Call the LLM with a structured prompt requesting JSON output.
2. Parse and validate the response with Pydantic models (field-level validators).
3. On validation failure, retry **once** with the same prompt.
4. If the retry also fails, return a rule-based fallback result.
5. Every response includes `generation_source` (`"llm"` or `"fallback"`) and `fallback_reason` (populated only when falling back).

### Key Dependencies
| Layer | Technology |
|-------|-----------|
| Frontend framework | React 18 |
| Frontend styling | Tailwind CSS |
| Frontend charts | Recharts |
| Frontend animation | Framer Motion |
| Backend framework | FastAPI |
| Backend async server | Uvicorn |
| Database | MongoDB |
| Database driver | Motor (async) |
| LLM client | LiteLLM (`acompletion`) |
| Settings | pydantic-settings |
| Testing | pytest + anyio + httpx |

### MongoDB Collections
| Collection | Contents |
|-----------|---------|
| `phishing_simulations` | Generated phishing emails with all structured fields |
| `ransomware_simulations` | Infection chains with per-step MITRE mapping |
| `attack_scenarios` | Multi-stage APT scenarios |
| `training_questions` | Generated quiz questions |
| `training_scores` | Per-answer records (category, correct, skipped, score, timestamp) |

---

## Setup

### Prerequisites
- Python 3.8+
- Node.js 14+ and yarn
- A running MongoDB instance (local or cloud)
- An LLM API key (any provider supported by LiteLLM, e.g. Groq, OpenAI)

### Backend

```bash
# From the project root
cd backend

# Create and activate a virtual environment (recommended)
python -m venv venv
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy the example env file and fill in your values
copy .env.example .env   # Windows
# cp .env.example .env   # macOS/Linux

# Start the server
uvicorn server:app --reload --port 8000
```

The API will be available at `http://localhost:8000`.  
Interactive docs: `http://localhost:8000/docs`.

### Frontend

```bash
# From the project root
cd frontend

# Install dependencies
yarn install

# Start the development server
yarn start
```

The app will open at `http://localhost:3000`.

---

## Configuration

All backend configuration is read from `backend/.env`. **Never commit real secrets.** The `.env` file is listed in `.gitignore`.

Create `backend/.env` with the following variables (replace placeholder values):

```env
# LLM provider credentials (any LiteLLM-supported provider)
LLM_API_KEY=your_api_key_here
LLM_MODEL=groq/llama-3.1-70b-versatile

# LLM behaviour
LLM_TIMEOUT=30
LLM_MAX_RETRIES=1

# MongoDB
MONGO_URL=mongodb://localhost:27017
DB_NAME=cyberrange_db

# CORS (comma-separated list of allowed origins)
CORS_ORIGINS=http://localhost:3000
```

Frontend environment variable (set in `frontend/.env` or your CI environment):

```env
REACT_APP_BACKEND_URL=http://localhost:8000
```

A `backend/.env.example` file is included in the repository with all variable names and placeholder values. It does not contain any real credentials.

---

## Testing

Tests live in the `tests/` directory at the project root. Run them from the `backend/` directory:

```bash
cd backend
python -m pytest ../tests/ -v
```

To run a specific test file:

```bash
python -m pytest ../tests/test_phishing.py -v
python -m pytest ../tests/test_ransomware.py -v
python -m pytest ../tests/test_training.py -v
```

Current test counts:
- `test_phishing.py` — 101 tests
- `test_ransomware.py` — 58 tests
- `test_attack_scenario.py` — 22 tests
- `test_llm_reliability.py` — 9 tests
- `test_training.py` — 13 tests

All 203 tests pass.

---

## Roadmap

- **User accounts and roles** — per-user progress tracking and role-based access
- **SIEM-style log generation** — synthetic event logs to accompany each simulation
- **Pretrained phishing classifier** — a local model to score generated emails independently of the LLM
- **LMS integration** — export training results to a Learning Management System

---

## Disclaimer

All content generated by CyberRange AI is simulated and for educational use only. No real malware, live attack infrastructure, or working exploit code is used or generated. All sender addresses and link URLs in phishing simulations use reserved TLDs (`.example`, `.test`) and are never presented as clickable links.
