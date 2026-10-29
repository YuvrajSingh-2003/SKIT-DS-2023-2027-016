"""Experiment-only v2 URL features (src/experiments/url_lexical_v2.py).

Not used in production; these tests guard the properties the experiment relies on.
"""

import numpy as np
import pandas as pd
import pytest

from src.experiments import url_lexical_v2 as v2
from src.training import train_url_multisource as ms

HOSTS = ["example.com", "bbc.co.uk", "paypal.com.evil.tk", "login-secure-update.xyz",
         "a1b2c3.vercel.app", "xn--80ak6aa92e.com", "192.168.1.1", "deep.sub.domain.example.co.jp"]
MUTATIONS = ["https://{h}", "http://{h}", "https://www.{h}", "http://www.{h}/", "https://{h}/login/verify.php",
             "https://{h}/?next=/account&id=99", "https://{h}:8443/a/b/c?d=e#f", "https://user:pass@{h}/secure",
             "//{h}/path", "{h}", "{h}/deep/path?q=1", "HTTPS://WWW.{h}./"]


def _host_vector(url):
    return [v2.extract(url)[name] for name in v2.HOST_FEATURES]


@pytest.mark.parametrize("host", HOSTS)
def test_host_block_ignores_everything_outside_the_host(host):
    baseline = _host_vector(f"https://{host}")
    for template in MUTATIONS:
        assert _host_vector(template.format(h=host)) == baseline, template


def test_invariance_guard_can_fail():
    """Negative control: the full vector (path + scheme blocks) must change."""
    full = lambda u: [v2.extract(u)[n] for n in v2.ALL_FEATURES]
    assert full("https://example.com") != full("http://example.com/login/verify.php?id=1")


@pytest.mark.parametrize("url, expected", [
    ("https://www.Example.com:443/a/b?q=1#f", ("https", "example.com", "/a/b", "?q=1#f")),
    ("https://user@evil.tk/x", ("https", "evil.tk", "/x", "")),
    ("http://[::1]:8080/", ("http", "::1", "/", "")),
    ("example.org", ("", "example.org", "", "")),
    ("https://example.com./", ("https", "example.com", "/", "")),
])
def test_split_url(url, expected):
    assert v2.split_url(url) == expected


def test_feature_blocks_are_disjoint_and_ordered():
    assert v2.ALL_FEATURES == v2.HOST_FEATURES + v2.PATH_FEATURES + v2.SCHEME_FEATURES
    assert len(set(v2.ALL_FEATURES)) == len(v2.ALL_FEATURES)
    frame = v2.extract_dataframe(pd.Series(["https://example.com/a?b=1"]))
    assert list(frame.columns) == v2.ALL_FEATURES and frame.dtypes.eq(float).all()


def test_path_features():
    f = v2.extract("https://example.com/a/b/login.php?x=1&y=abcd#top")
    assert (f["path_depth"], f["query_params"], f["query_max_value_length"]) == (3, 2, 4)
    assert f["path_has_file_extension"] == 1 and f["path_keyword"] == 1 and f["has_fragment"] == 1
    assert v2.extract("https://user@example.com/")["url_has_userinfo"] == 1


def test_evaluate_probabilities_counts():
    frame = pd.DataFrame({"url": ["https://www.a.com/", "https://b.com/", "http://c.com/x", "https://d.com/"],
                          "phishing": [0, 0, 1, 1]})
    out = ms.evaluate_probabilities(np.array([0.1, 0.9, 0.8, 0.2]), frame, train_groups={"a.com"})
    assert out["overall"]["confusion"] == {"tn": 1, "fp": 1, "fn": 1, "tp": 1}
    assert out["off_template_legitimate"] == {"rows": 1, "flagged": 1, "fpr": 1.0, "ci95": ms.wilson(1, 1)}
    assert out["unseen_domains"]["rows"] == 3


# ── audit and learning-curve helpers ──────────────────────────────────

def test_univariate_auc_is_direction_free_and_guards_degenerate_input():
    from src.experiments.url_data_audit import univariate_auc

    y = np.array([0, 0, 1, 1])
    assert univariate_auc(pd.Series([1, 2, 3, 4]), y) == 1.0
    assert univariate_auc(pd.Series([4, 3, 2, 1]), y) == 1.0
    assert univariate_auc(pd.Series([1, 1, 1, 1]), y) is None
    assert univariate_auc(pd.Series([1, 2, 3, 4]), np.array([0, 0, 0, 0])) is None


def test_grouped_subsample_never_splits_a_domain_and_is_seeded():
    from src.experiments.url_learning_curve import grouped_subsample

    frame = pd.DataFrame({"group": ["a", "a", "b", "b", "c", "d"], "url": list("uvwxyz")})
    part = grouped_subsample(frame, 0.5, seed=1)
    assert part.equals(grouped_subsample(frame, 0.5, seed=1))
    for g in part["group"].unique():
        assert (frame["group"] == g).sum() == (part["group"] == g).sum()
    assert part["group"].nunique() == 2
