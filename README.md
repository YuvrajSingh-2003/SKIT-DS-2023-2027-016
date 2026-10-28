# ChainShield

ChainShield detects phishing URLs and smishing (SMS phishing) messages. Each input is
checked against a blockchain threat registry (read-only lookup of a Keccak-256 hash), and
then assessed with heuristics and machine-learning models. Results are explained with the
evidence behind them, and a failure of any component is reported as inconclusive, never
as safe.

## How it works

1. A URL or message is submitted through the Chrome extension or the React dashboard.
   Nothing is sent until the user presses Scan.
2. The backend canonicalizes the input and looks up its Keccak-256 hash in the
   ThreatRegistry contract on Sepolia (view calls only). A threat match gives HIGH risk.
   A miss is not treated as proof of safety.
3. URLs: heuristic checks plus an advisory URL model (it can raise risk to MEDIUM, never
   to HIGH on its own). Messages: a three-class SMS model (legitimate, generic spam,
   smishing). If the registry is unavailable and nothing indicates a threat, a URL is
   reported as UNKNOWN, not SAFE.
4. URL scans and message-scan metadata (no message text) are stored and shown as history.

The backend never writes to the blockchain. Threat records are added only by the
contract owner through the separate seeder script (`src/blockchain/seed_registry.py`,
dry-run by default). There is no automatic submission and no community confirmation.
The dashboard shows scanners and history; it does not show aggregate statistics or
model accuracy (model evaluation results are in `models/sms_baseline/<run>/` and
`docs/SYSTEM.md`).

## Setup

```bash
git clone https://github.com/<owner>/SKIT-DS-2023-2027-016.git
cd SKIT-DS-2023-2027-016
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Folder structure

```
app/            FastAPI routes, schemas, services, database models (entry point app/server.py)
main.py         Original URL-only FastAPI app (imported by app/server.py)
src/            Data preparation, features, training, evaluation, blockchain utilities
models/         Trained model artifacts with metadata and checksums
data/           Datasets and prepared splits (raw downloads are gitignored)
contracts/      ThreatRegistry Solidity contract, ABI, deployment config and docs
frontend/       extension/ (Chrome MV3), dashboard/ (React + Vite), shared/ (API client)
tests/          Python tests; frontend/extension/tests/ holds the extension tests
configs/        Experiment configuration
reports/        EDA and historical reports (reports/full_report.md predates the
                current label scheme; see docs/datasets.md)
docs/           System guide, dataset provenance, release checklist, submission material
```

## Data

- URL model: PhiUSIIL Phishing URL dataset (UCI, CC BY 4.0).
- SMS model: Mishra & Soni SMS Phishing Dataset (Mendeley, CC BY 4.0), prepared with
  label-conflict exclusion and a near-duplicate-aware split.
- External evaluation only: IMC 2025 smishing dataset (CC BY 4.0).
Provenance, licenses and label mappings: [docs/datasets.md](docs/datasets.md).

## Full system (URL + SMS)

- Start the complete API (URL and message scanning): `.venv/bin/uvicorn app.server:app --host 127.0.0.1 --port 8000`
- Endpoints: `POST /scan`, `GET /scan/history`, `POST /message/scan`, `GET /message/history`
- Both models are loaded only after their pinned SHA-256 checksums verify; failures give
  `UNKNOWN`, never `SAFE`. The URL model is advisory (it cannot make a URL HIGH on its own).
- The SMS model is a research baseline: on an external dataset it caught about 70% of
  smishing and none of the "hey mum/dad" scams. Do not rely on it alone.
- Architecture, API examples, privacy policy, tests, the extension, and remaining manual
  steps: [docs/SYSTEM.md](docs/SYSTEM.md). Dataset provenance and licensing:
  [docs/datasets.md](docs/datasets.md).
