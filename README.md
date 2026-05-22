# M365 & Azure Security Analysis

A security-focused triage tool for Microsoft 365 Message Center and Azure Service Health/Updates. It uses local LLMs (Ollama) to analyze incoming changes against specific organizational security concerns.

## Features
- **M365 Message Center**: Fetches and triages messages via Microsoft Graph.
- **Azure Integration**: Fetches Service Health, Advisor Security recommendations, and Product Updates.
- **Hybrid Auth**: Uses Service Principal for Graph and Azure CLI (`az login`) for ARM/Azure resources.
- **Local LLM**: Fully local analysis using Ollama (e.g., Llama 3.2).
- **Security Triage**: Multi-pass analysis (Relevance -> Deep Analysis) with adversarial reasoning.
- **Persistence**: Supports Postgres (Neon/Local) for tracking analyzed messages.
- **Notifications**: Optional Telegram alerts for high/medium risk items.

## Setup

### 1. Prerequisites
- Python 3.10+
- [PostgreSQL](https://www.postgresql.org/) (Local or [Neon.tech](https://neon.tech/)) for analysis persistence.
- [Ollama](https://ollama.com/) with a capable model:
    - **Recommended**: `llama3.1:70b` or `gpt-oss:20b` (Requires 16GB+ VRAM/RAM for decent performance).
    - **Minimum**: `llama3.2:3b` (Fast, but prone to hallucinations in complex security logic).
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli)

### 2. Configuration
Copy `.env.example` to `.env` and fill in your details.
```bash
cp .env.example .env
```

### 3. Custom Guidance
Create a `guidance.json` file to define your specific security themes. See `guidance.json.example` for the format. This file is ignored by Git.

### 4. Authentication
Run the following to authenticate for Azure resource access:
```bash
az login
```

## Usage
Run the main script:
```bash
python3 msgcenter.py --count 5 --days 30
```

### Arguments
- `--count N`: Number of messages to process (0 for all).
- `--days N`: Lookback window in days.
- `--model NAME`: Specify Ollama model.
- `--force`: Re-analyze even if already in DB.
