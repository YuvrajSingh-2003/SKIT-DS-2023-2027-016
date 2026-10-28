# ChainShield — Architecture

Drawn from the code as of 2026-10-28 (`app/server.py`, `main.py`, `app/routes/`,
`app/services/`, `app/database/`, `frontend/`). Diagrams use Mermaid.

## Components

```mermaid
flowchart LR
    subgraph Clients
        EXT["Chrome extension (MV3)<br/>frontend/extension<br/>URL + Message modes"]
        DASH["React dashboard (Vite)<br/>frontend/dashboard<br/>/scanner /messages /history"]
    end

    subgraph API["FastAPI — app.server:app (wraps main:app)"]
        SCAN["POST /scan<br/>GET /scan/history<br/>app/routes/scan.py"]
        MSG["POST /message/scan<br/>GET /message/history<br/>app/routes/message.py"]
    end

    subgraph URLP["URL pipeline"]
        HEUR["Heuristics<br/>security_checker.py"]
        URLML["URL model (XGBoost, advisory)<br/>ml_detector.py<br/>SHA-256 pinned before load"]
    end

    subgraph SMSP["SMS pipeline"]
        SMSML["SMS model (TF-IDF + LogReg)<br/>sms_detector.py<br/>legitimate / generic_spam / smishing<br/>SHA-256 pinned before load"]
        TXT["Text warning signs<br/>src/text_features.py"]
    end

    REG["blockchain_checker.py<br/>Keccak-256 of canonical input<br/>view calls only"]
    CHAIN[("ThreatRegistry<br/>Sepolia (chain 11155111)")]
    DB[("SQLite chainshield.db<br/>scans (URL scans, stores the URL)<br/>message_scans (metadata only)")]

    EXT -->|"user presses Scan"| SCAN
    EXT -->|"user presses Scan"| MSG
    DASH --> SCAN
    DASH --> MSG
    SCAN --> HEUR
    SCAN --> REG
    SCAN --> URLML
    MSG --> REG
    MSG --> SMSML
    MSG --> TXT
    REG -.->|"threatExists / getThreat"| CHAIN
    SCAN --> DB
    MSG --> DB
```

The backend never writes to the chain. Threat records are added only by the contract
owner with the separate seeder (`src/blockchain/seed_registry.py`, dry-run by default).

## URL decision (`app/routes/scan.py`)

```mermaid
flowchart TD
    A["Validated URL (pydantic HttpUrl; invalid → 422)"] --> H["Heuristic findings"]
    H --> R{"Registry status"}
    R -->|match_threat| HIGH["HIGH · decision blockchain · model not run"]
    R -->|"match_non_threat / no_match / unavailable"| M{"URL model"}
    M -->|unavailable or error| UNK1["UNKNOWN · ml_status error"]
    M -->|available| L["Level from heuristics:<br/>0 → SAFE, 1–2 → MEDIUM, 3+ → HIGH"]
    L --> P{"Model says phishing?"}
    P -->|yes| P2["SAFE raised to MEDIUM<br/>+ advisory finding"]
    P -->|no| Q{"Level SAFE and registry unavailable?"}
    Q -->|yes| UNK2["UNKNOWN · inconclusive, not safe"]
    Q -->|no| KEEP["Keep level"]
```

## Message decision (`app/routes/message.py`)

```mermaid
flowchart TD
    A["Text 1–2,000 chars, not blank (else 422)"] --> R{"Registry status<br/>(message hash)"}
    R -->|match_threat| H["smishing_registry_match · HIGH"]
    R -->|other| M{"SMS model"}
    M -->|smishing| S["likely_smishing · MEDIUM"]
    M -->|generic_spam| G["generic_spam · LOW"]
    M -->|legitimate| L["likely_legitimate · LOW"]
    M -->|unavailable| U["unavailable · UNKNOWN"]
```

A message result is never `SAFE`. Message text is used in memory only; history stores
verdict, model scores, registry status, length and a has-link flag.

## Registry statuses

| Status | Meaning | Shown as threat? |
|---|---|---|
| `match_threat` | hash registered with verdict 1 | yes |
| `match_non_threat` | hash registered with another verdict | no |
| `no_match` | registry reachable, hash absent | no (not proof of safety) |
| `unavailable` | RPC, chain ID, contract or call could not be verified | no (inconclusive) |
| `match_unclassified` | older history row: entry existed, verdict not recorded | no |
| `not_recorded` | older history row: no registry data saved | no |
