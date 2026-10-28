"""Stage 1.6 tests: near-duplicate grouping and the group-aware split.

Synthetic random-letter text only. No real data, no training, no printing of text.
"""

import inspect
import random

import pandas as pd
import pytest

from src.data import split_prepared as sp
from src.training import train_baseline as baseline

# A~P and B~P are 92.5 similar; A~B is 85 (a transitive chain).
TEXT_A = "ognlejzsfoasfxudbxenvjqygbctqsqrwnxiwkrd"
TEXT_B = "ogflejzyfoasfxgubxenvjqygbctqyqrwnxiwpro"
TEXT_P = "ognlejzsfoasfxudbxenvjqygbctqyqrwnxiwpro"


def _random_text(rng):
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz ") for _ in range(40))


def _prepared(n_per_class=40, extra=()):
    rng = random.Random(1)
    rows = [(label, _random_text(rng)) for _ in range(n_per_class)
            for label in ("legitimate", "generic_spam", "smishing")]
    rows += list(extra)
    return pd.DataFrame({
        "text": [t for _, t in rows], "label": [l for l, _ in rows],
        "source": "mishra_soni", "source_row": range(len(rows)),
    })


class TestGrouping:

    def test_transitive_chain_forms_one_group(self):
        groups = sp.near_duplicate_groups([TEXT_A, "unrelated text entirely here", TEXT_P, TEXT_B])

        assert groups[0] == groups[2] == groups[3]
        assert groups[1] != groups[0]

    def test_mixed_label_group_is_reported_and_kept_intact(self):
        audit = sp.audit_groups(pd.Series(["smishing", "generic_spam", "legitimate"]),
                                sp.near_duplicate_groups([TEXT_A, TEXT_P, "unrelated text entirely here"]))

        assert audit["mixed_label_groups"] == 1
        assert audit["mixed_label_class_counts"] == {"smishing": 1, "generic_spam": 1}
        assert audit["singleton_groups"] == 1

    def test_audit_contains_no_text(self):
        audit = sp.audit_groups(pd.Series(["smishing", "smishing"]), sp.near_duplicate_groups([TEXT_A, TEXT_P]))

        assert TEXT_A not in repr(audit) and TEXT_P not in repr(audit)


class TestGroupSplit:

    def test_chain_stays_in_one_split_and_verification_passes(self):
        chain = [("smishing", TEXT_A), ("smishing", TEXT_P), ("smishing", TEXT_B)]
        prepared = _prepared(extra=chain)

        splits = sp.split_prepared(prepared)
        report = sp.verify_split(prepared, splits)

        homes = {name for name, part in splits.items() for t in part["text"] if t in (TEXT_A, TEXT_B, TEXT_P)}
        assert len(homes) == 1
        assert report["near_duplicate_pairs_crossing_splits"] == 0

    def test_mixed_label_group_is_not_split_or_relabelled(self):
        prepared = _prepared(extra=[("smishing", TEXT_A), ("generic_spam", TEXT_P)])

        splits = sp.split_prepared(prepared)
        sp.verify_split(prepared, splits)

        found = pd.concat(splits.values()).set_index("text").loc[[TEXT_A, TEXT_P], "label"].tolist()
        assert found == ["smishing", "generic_spam"]

    def test_same_seed_gives_identical_assignments_and_seed_matters(self):
        prepared = _prepared()

        first, second = sp.split_prepared(prepared, seed=42), sp.split_prepared(prepared, seed=42)
        other = sp.split_prepared(prepared, seed=7)

        for name in first:
            pd.testing.assert_frame_equal(first[name], second[name])
        assert any(not first[n]["source_row"].equals(other[n]["source_row"]) for n in first)

    def test_proportions_and_class_balance_are_approximate(self):
        prepared = _prepared(n_per_class=100)

        report = sp.verify_split(prepared, sp.split_prepared(prepared))

        assert report["rows"] == {"train": 210, "val": 45, "test": 45}
        for counts in report["class_counts"].values():
            assert len(set(counts.values())) == 1   # equal classes stay equal

    def test_provenance_preserved_and_not_a_feature(self):
        prepared = _prepared()
        splits = sp.split_prepared(prepared)

        combined = pd.concat(splits.values()).sort_values("source_row")
        assert combined["source"].eq("mishra_soni").all()
        assert combined["source_row"].tolist() == list(range(len(prepared)))
        code = inspect.getsource(baseline)
        for column in ("source_row", "group_id", '"source"', "'source'"):
            assert column not in code

    def test_oversized_group_is_refused(self):
        rng = random.Random(2)
        base = _random_text(rng)
        near = [base[:-1] + c for c in "abcdefghijklm"]       # 13 rows, one group
        prepared = _prepared(n_per_class=10, extra=[("smishing", t) for t in near])

        with pytest.raises(ValueError, match="not feasible"):
            sp.split_prepared(prepared)

    def test_verifier_catches_leaks(self):
        prepared = _prepared(extra=[("smishing", TEXT_A), ("smishing", TEXT_P)])
        splits = sp.split_prepared(prepared)
        leaked = {k: v.copy() for k, v in splits.items()}
        home = next(n for n, p in leaked.items() if TEXT_A in set(p["text"]))
        away = next(n for n in leaked if n != home)
        moving = leaked[home][leaked[home]["text"] == TEXT_P]
        leaked[home] = leaked[home].drop(moving.index).reset_index(drop=True)
        leaked[away] = pd.concat([leaked[away], moving], ignore_index=True)

        with pytest.raises(AssertionError, match="more than one split"):
            sp.verify_split(prepared, leaked)

    def test_verifier_catches_changed_labels(self):
        prepared = _prepared()
        splits = sp.split_prepared(prepared)
        splits["train"].loc[0, "label"] = "smishing" if splits["train"].loc[0, "label"] != "smishing" else "legitimate"

        with pytest.raises(AssertionError, match="changed"):
            sp.verify_split(prepared, splits)
