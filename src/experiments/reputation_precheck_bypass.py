"""Worst-case bypass bound for the reputation pre-check (offline, no network).

No licensed top-sites list is available locally, so false-positive reduction
cannot be measured. This bounds the other side: assume EVERY domain is on the
list (the worst case) and count how many known phishing URLs the pre-check
would still apply to, i.e. where it would withhold the model's advisory.

    python -m src.experiments.reputation_precheck_bypass
"""

import json
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd

from app.services import reputation_precheck as rp

SOURCES = {
    "openphish_20261028": Path("data/incoming/threat_feeds/openphish-community-20261028T152813Z.txt"),
    "phiusiil_validation_phishing": Path("data/processed/url_splits/stratified_validation.csv"),
}
OUTPUT = Path("reports/model_optimization/results/reputation_precheck_bypass.json")


def _urls(name, path):
    if name.startswith("openphish"):
        return [line.strip() for line in path.read_text().splitlines() if line.strip()]
    frame = pd.read_csv(path, usecols=["URL", "label"])
    return frame.loc[frame["label"] == 0, "URL"].astype(str).tolist()


def _all_listed(url):
    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    return frozenset({host[4:] if host.startswith("www.") else host})


def _registrable_listed(url):
    # Approximate registrable domain as the last two labels (no PSL library is
    # installed; multi-part suffixes such as co.uk are under-approximated).
    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    return frozenset({".".join(host.split(".")[-2:])})


SCENARIOS = {"full_host_listed": _all_listed, "registrable_domain_listed": _registrable_listed}


def main():
    out = {"applies": "the pre-check would withhold the model advisory for this phishing URL",
           "full_host_listed": "every exact host is on the list (worst case)",
           "registrable_domain_listed": "every URL's registrable domain (last two labels) is on the list"}
    for scenario, listed in SCENARIOS.items():
        for name, path in SOURCES.items():
            urls = _urls(name, path)
            results = [rp.evaluate(u, listed(u)) for u in urls]
            applied = [u for u, r in zip(urls, results) if r["applies"]]
            name = f"{scenario}:{name}"
            out[name] = {
                "rows": len(urls), "applies": len(applied), "applies_rate": len(applied) / len(urls),
                "reasons": dict(Counter(r["reason"] for r in results).most_common()),
                "applied_examples": applied[:10],
            }
            print(name, out[name]["rows"], out[name]["applies"], round(out[name]["applies_rate"], 4))
            print("  ", out[name]["reasons"])
    OUTPUT.write_text(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
