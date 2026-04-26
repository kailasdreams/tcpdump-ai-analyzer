# TCPDump AI Analyzer

A Flask web application that uploads a PCAP / tcpdump capture file, parses it, and sends the packet data to an AI model (Anthropic Claude or OpenAI GPT) for structured network-security analysis.

---

## Features

- **Upload any PCAP file** directly from the browser
- **Dual parser** — uses the system `tcpdump` binary when available; falls back to a pure-Python `dpkt` parser automatically
- **Multi-provider AI analysis** — supports Anthropic Claude and OpenAI GPT via a single unified engine
- **Structured AI report** covering Executive Summary, Observed Issues, Root Cause Analysis, Recommended Fixes, and Severity rating
- **Anomaly pre-scan** — highlights RST packet counts and missing SYN/SYN-ACK before the AI call
- **Top-conversations table** — shows the 10 highest-volume flows by byte count
- Raw dump preview (first 8 000 characters) shown alongside the AI output

---

## Project Structure

```
tcpdump-ai-analyzer/
├── app.py              # Flask routes and tcpdump/fallback orchestration
├── ai_engine.py        # Unified Anthropic + OpenAI API client
├── pcap_parser.py      # Pure-Python PCAP parser (dpkt-based fallback)
├── templates/
│   └── index.html      # Single-page UI
└── requirements.txt    # Python dependencies
```

---

## Requirements

- Python 3.10+
- `tcpdump` installed on the host *(optional — the app falls back to dpkt if absent)*

---

## Installation

```bash
# 1. Clone / extract the project
cd tcpdump-ai-analyzer

# 2. Create and activate a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

`requirements.txt` installs:

| Package | Purpose |
|---|---|
| `flask` | Web framework |
| `anthropic` | Anthropic Claude API client |
| `openai>=1.0.0` | OpenAI GPT API client |
| `dpkt` | Pure-Python PCAP parsing (fallback) |

---

## Running the App

```bash
python app.py
```

The dev server starts at `http://127.0.0.1:5000`.

For production, run behind a WSGI server such as Gunicorn:

```bash
gunicorn -w 2 app:app
```

> **Security note:** Set the `FLASK_SECRET` environment variable to a strong random string before deploying. The app defaults to `changeme-in-production`.

```bash
export FLASK_SECRET="your-random-secret-here"
```

---

## Usage

1. Open `http://127.0.0.1:5000` in your browser.
2. Paste your **API key** (Anthropic or OpenAI).
3. Select the **AI provider** and **model**.
4. Optionally adjust the **tcpdump flags** (default: `-nn -v`).
5. Upload a `.pcap`, `.pcapng`, or raw dump file.
6. Click **Analyze** — the AI report appears within seconds.

---

## How It Works

### Packet parsing (`app.py` → `pcap_parser.py`)

```
Upload PCAP
    │
    ▼
tcpdump installed? ──yes──► run tcpdump -r <file> <flags>
    │                               │
    │ no                  output contains error markers?
    │                               │ yes
    ▼                               ▼
dpkt fallback ◄─────────────────────┘
    │
    ▼
Human-readable packet log + summary header
```

The `dpkt` fallback handles Ethernet, raw-IP, and null/loopback link types and emits output in the same style as `tcpdump -nn -v`.

### AI analysis (`ai_engine.py`)

The packet log (capped at 30 000 characters) is sent to the chosen provider with a system prompt tuned for F5 BIG-IP / LTM environments, TCP/IP troubleshooting, SSL/TLS diagnosis, and firewall/load-balancer behavior.

Both Anthropic v1 SDK and OpenAI v1/v0 SDK variants are supported with automatic detection.

---

## Configuration Reference

| Parameter | Where set | Default | Notes |
|---|---|---|---|
| `FLASK_SECRET` | Environment variable | `changeme-in-production` | Change before deploying |
| Upload folder | `app.py` | `./uploads/` | Created automatically |
| AI token limit | `ai_engine.py` | `2048` | Increase for longer reports |
| Packet data cap | `ai_engine.py` | `30 000 chars` | Prevents oversized API payloads |
| Raw dump preview | `app.py` | `8 000 chars` | Shown in the UI only |

---

## Supported AI Models

**Anthropic**
- `claude-sonnet-4-20250514` *(default)*
- Any other Claude model string accepted by the Messages API

**OpenAI**
- `gpt-4o`, `gpt-4-turbo`, `gpt-3.5-turbo`, or any chat-completion model

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `dpkt not installed` error | Missing dependency | `pip install dpkt` |
| `Authentication failed` | Wrong API key | Double-check the key for the selected provider |
| `Cannot open PCAP` | Corrupt or unsupported file | Verify the file with `file <capture.pcap>` |
| Empty AI output | Model / token limit | Try a smaller capture or increase `max_tokens` in `ai_engine.py` |
| tcpdump not found | Binary absent | Install tcpdump, or rely on the dpkt fallback (no action needed) |

---

## License

MIT — see `LICENSE` for details.
