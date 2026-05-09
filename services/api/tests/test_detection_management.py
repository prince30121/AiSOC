"""Tests for WS-B3 — Detection management UI backend.

These tests pin the contract the analyst console relies on for:

* ``GET /api/v1/detection/coverage``  — rule-centric MITRE heatmap
* ``POST /api/v1/detection/rules/bulk-toggle`` — bulk enable/disable
* ``GET /api/v1/detection/drift``     — rules that need attention

The HTTP wrappers are thin DB queries that defer all interesting logic to
``_build_coverage``, ``_build_drift``, and ``_coerce_uuid``. Testing the
pure helpers gives full coverage of the heuristics without needing
Postgres or the full FastAPI app, which keeps these tests fast and
trivially runnable in CI on every push.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest
from app.api.v1.endpoints.detection_compat import (
    DRIFT_FP_RATE_THRESHOLD,
    DRIFT_LOW_CONFIDENCE_THRESHOLD,
    DRIFT_STALE_DAYS,
    _build_coverage,
    _build_drift,
    _coerce_uuid,
    _primary_tactic,
)


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


@dataclass
class FakeRule:
    """Minimal stand-in for ``DetectionRule`` rows.

    The pure helpers only read attributes — they never persist — so a
    plain dataclass with the right field names is enough. We use this
    instead of ``DetectionRule`` directly so tests don't drag in the ORM
    machinery.
    """

    id: uuid.UUID = field(default_factory=uuid.uuid4)
    name: str = "Rule"
    severity: str = "medium"
    status: str = "active"  # "active" | "inactive" | "testing"
    confidence: int = 50
    fp_rate: float = 0.0
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    last_triggered: datetime | None = None


# ---------------------------------------------------------------------------
# _primary_tactic
# ---------------------------------------------------------------------------


class TestPrimaryTactic:
    """We deterministically pick the first declared tactic for plotting."""

    def test_picks_first_tactic(self):
        rule = FakeRule(mitre_tactics=["execution", "initial-access"])
        assert _primary_tactic(rule) == "execution"

    def test_returns_none_when_no_tactics(self):
        rule = FakeRule(mitre_tactics=[])
        assert _primary_tactic(rule) is None

    def test_handles_falsy_first_entry(self):
        rule = FakeRule(mitre_tactics=["", "execution"])
        assert _primary_tactic(rule) is None


# ---------------------------------------------------------------------------
# _build_coverage
# ---------------------------------------------------------------------------


class TestBuildCoverage:
    """Coverage heatmap should reflect the enabled-rule distribution."""

    def test_empty_library(self):
        cov = _build_coverage([])
        assert cov.tactics == []
        assert cov.cells == []
        assert cov.summary.totalRules == 0
        assert cov.summary.activeRules == 0
        assert cov.summary.coveredTechniques == 0

    def test_single_active_rule_one_technique(self):
        rule = FakeRule(
            status="active",
            mitre_tactics=["execution"],
            mitre_techniques=["T1059"],
        )
        cov = _build_coverage([rule])
        assert cov.tactics == ["execution"]
        assert len(cov.cells) == 1
        cell = cov.cells[0]
        assert cell.techniqueId == "T1059"
        assert cell.tactic == "execution"
        assert cell.activeRules == 1
        assert cell.inactiveRules == 0
        assert cell.totalRules == 1
        assert cov.summary.activeRules == 1
        assert cov.summary.coveredTechniques == 1

    def test_inactive_rule_does_not_count_as_covered(self):
        # A disabled rule shouldn't paint a technique as "covered" — that's
        # the whole point of the heatmap surfacing tuning gaps.
        rule = FakeRule(
            status="inactive",
            mitre_tactics=["execution"],
            mitre_techniques=["T1059"],
        )
        cov = _build_coverage([rule])
        assert len(cov.cells) == 1
        assert cov.cells[0].activeRules == 0
        assert cov.cells[0].inactiveRules == 1
        # The technique appears in the grid (so analysts can re-enable
        # it) but coveredTechniques is 0.
        assert cov.summary.coveredTechniques == 0
        assert cov.summary.techniques == 1

    def test_multiple_rules_same_technique_aggregate(self):
        rules = [
            FakeRule(status="active", mitre_techniques=["T1059"], mitre_tactics=["execution"]),
            FakeRule(status="active", mitre_techniques=["T1059"], mitre_tactics=["execution"]),
            FakeRule(status="inactive", mitre_techniques=["T1059"], mitre_tactics=["execution"]),
        ]
        cov = _build_coverage(rules)
        assert len(cov.cells) == 1
        cell = cov.cells[0]
        assert cell.activeRules == 2
        assert cell.inactiveRules == 1
        assert cell.totalRules == 3

    def test_unmapped_rules_count_in_summary_but_not_in_cells(self):
        # Rules without a technique mapping shouldn't appear on the
        # heatmap (we have nothing to plot), but they still count toward
        # totalRules so the analyst sees the right library size.
        rules = [
            FakeRule(status="active", mitre_techniques=[]),
            FakeRule(status="active", mitre_techniques=["T1059"], mitre_tactics=["execution"]),
        ]
        cov = _build_coverage(rules)
        assert cov.summary.totalRules == 2
        assert cov.summary.activeRules == 2
        assert len(cov.cells) == 1  # only the mapped technique
        assert cov.summary.techniques == 1

    def test_skips_blank_technique_strings(self):
        # JSONB columns occasionally contain stray empty strings; they
        # shouldn't end up as their own grid cell.
        rule = FakeRule(
            status="active",
            mitre_techniques=["", "T1059", "  "],
            mitre_tactics=["execution"],
        )
        cov = _build_coverage([rule])
        assert [c.techniqueId for c in cov.cells] == ["T1059"]

    def test_cells_sorted_for_stable_rendering(self):
        # Heatmap cells must be returned in a stable order so the UI
        # doesn't shuffle rows on every refresh.
        rules = [
            FakeRule(status="active", mitre_techniques=["T1059"], mitre_tactics=["execution"]),
            FakeRule(status="active", mitre_techniques=["T1003"], mitre_tactics=["credential-access"]),
            FakeRule(status="active", mitre_techniques=["T1566"], mitre_tactics=["initial-access"]),
        ]
        cov = _build_coverage(rules)
        # First by tactic alphabetical, then by technique id.
        tactics_in_order = [c.tactic for c in cov.cells]
        assert tactics_in_order == sorted(tactics_in_order)


# ---------------------------------------------------------------------------
# _build_drift
# ---------------------------------------------------------------------------


class TestBuildDrift:
    """Drift inbox surfaces rules that need analyst attention."""

    NOW = datetime(2026, 5, 9, tzinfo=UTC)

    def test_empty_library(self):
        out = _build_drift([], now=self.NOW)
        assert out.entries == []
        assert out.summary.total == 0

    def test_clean_rule_does_not_appear(self):
        # Active, low FP, recently triggered, decent confidence → nothing
        # to flag.
        rule = FakeRule(
            status="active",
            confidence=80,
            fp_rate=0.05,
            last_triggered=self.NOW - timedelta(days=1),
        )
        out = _build_drift([rule], now=self.NOW)
        assert out.entries == []
        assert out.summary.total == 0

    def test_high_fp_rate_flags_rule(self):
        rule = FakeRule(
            status="active",
            confidence=80,
            fp_rate=DRIFT_FP_RATE_THRESHOLD + 0.05,
            last_triggered=self.NOW - timedelta(hours=1),
        )
        out = _build_drift([rule], now=self.NOW)
        assert len(out.entries) == 1
        assert "high_fp_rate" in out.entries[0].issues
        assert out.summary.highFpRate == 1

    def test_low_confidence_flags_rule(self):
        rule = FakeRule(
            status="active",
            confidence=DRIFT_LOW_CONFIDENCE_THRESHOLD - 1,
            fp_rate=0.0,
            last_triggered=self.NOW - timedelta(hours=1),
        )
        out = _build_drift([rule], now=self.NOW)
        assert len(out.entries) == 1
        assert "low_confidence" in out.entries[0].issues
        assert out.summary.lowConfidence == 1

    def test_stale_active_rule_flags_rule(self):
        rule = FakeRule(
            status="active",
            confidence=80,
            fp_rate=0.0,
            last_triggered=self.NOW - timedelta(days=DRIFT_STALE_DAYS + 1),
        )
        out = _build_drift([rule], now=self.NOW)
        assert len(out.entries) == 1
        assert "stale" in out.entries[0].issues
        assert out.entries[0].daysSinceTriggered == DRIFT_STALE_DAYS + 1

    def test_active_rule_never_triggered_is_stale(self):
        # A rule that's been enabled long enough to expect a trigger but
        # has none recorded — likely broken or noisy syntax.
        rule = FakeRule(status="active", confidence=80, fp_rate=0.0, last_triggered=None)
        out = _build_drift([rule], now=self.NOW)
        assert len(out.entries) == 1
        assert "stale" in out.entries[0].issues
        assert out.entries[0].daysSinceTriggered is None

    def test_inactive_rule_is_never_stale(self):
        # A disabled rule with no recent triggers is *expected* — don't
        # nag analysts about it.
        rule = FakeRule(
            status="inactive",
            confidence=80,
            fp_rate=0.0,
            last_triggered=None,
        )
        out = _build_drift([rule], now=self.NOW)
        assert out.entries == []

    def test_inactive_rule_with_high_fp_still_flagged(self):
        # …but a disabled rule with a bad FP history still surfaces so
        # someone can clean it up rather than letting it rot in the DB.
        rule = FakeRule(
            status="inactive",
            confidence=80,
            fp_rate=DRIFT_FP_RATE_THRESHOLD + 0.1,
            last_triggered=None,
        )
        out = _build_drift([rule], now=self.NOW)
        assert len(out.entries) == 1
        assert "high_fp_rate" in out.entries[0].issues
        assert "stale" not in out.entries[0].issues
        assert out.entries[0].enabled is False

    def test_multiple_issues_aggregated(self):
        rule = FakeRule(
            status="active",
            confidence=10,
            fp_rate=0.5,
            last_triggered=self.NOW - timedelta(days=90),
        )
        out = _build_drift([rule], now=self.NOW)
        assert len(out.entries) == 1
        issues = set(out.entries[0].issues)
        assert issues == {"high_fp_rate", "low_confidence", "stale"}

    def test_entries_sorted_worst_first(self):
        # 3-issue rule beats 1-issue rule; within the same issue count,
        # higher severity wins.
        rule_a = FakeRule(
            name="aa",
            status="active",
            confidence=80,
            fp_rate=DRIFT_FP_RATE_THRESHOLD + 0.05,
            last_triggered=self.NOW - timedelta(hours=1),
        )
        rule_b = FakeRule(
            name="bb",
            status="active",
            confidence=10,
            fp_rate=0.5,
            last_triggered=self.NOW - timedelta(days=90),
            severity="critical",
        )
        rule_c = FakeRule(
            name="cc",
            status="active",
            confidence=10,
            fp_rate=0.5,
            last_triggered=self.NOW - timedelta(days=90),
            severity="medium",
        )
        out = _build_drift([rule_a, rule_b, rule_c], now=self.NOW)
        names_in_order = [e.name for e in out.entries]
        assert names_in_order == ["bb", "cc", "aa"]

    def test_summary_counts_each_issue_independently(self):
        # A rule with 2 issues contributes to 2 counters, not just 1.
        rule = FakeRule(
            status="active",
            confidence=10,
            fp_rate=0.5,
            last_triggered=self.NOW - timedelta(days=1),
        )
        out = _build_drift([rule], now=self.NOW)
        assert out.summary.total == 1  # one entry…
        assert out.summary.highFpRate == 1
        assert out.summary.lowConfidence == 1
        assert out.summary.stale == 0  # …recent trigger so not stale.

    def test_handles_naive_datetime(self):
        # Some DB drivers return naive datetimes — make sure we don't
        # blow up on tz-mixing.
        rule = FakeRule(
            status="active",
            confidence=80,
            fp_rate=0.0,
            last_triggered=datetime(2026, 5, 1),  # naive
        )
        out = _build_drift([rule], now=self.NOW)
        # 8 days ago → not stale at default threshold.
        assert out.entries == []


# ---------------------------------------------------------------------------
# _coerce_uuid
# ---------------------------------------------------------------------------


class TestCoerceUuid:
    """Bulk-toggle mustn't 422 on a single bad ID — bad IDs go to ``skipped``."""

    def test_valid_uuid_string(self):
        u = uuid.uuid4()
        assert _coerce_uuid(str(u)) == u

    def test_garbage_returns_none(self):
        assert _coerce_uuid("not-a-uuid") is None

    def test_empty_string_returns_none(self):
        assert _coerce_uuid("") is None

    def test_none_input_returns_none(self):
        # The frontend technically can't send ``None``, but defensive
        # coding because pydantic's coercion can produce surprises.
        assert _coerce_uuid(None) is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Threshold sanity (catches accidental regressions in product behavior)
# ---------------------------------------------------------------------------


def test_thresholds_are_documented_constants():
    """Catch accidental changes to the drift thresholds.

    Tuning the thresholds is a product decision; this test exists so that
    if someone tightens them they have to update this assertion *and*
    docs, not silently change the inbox volume.
    """
    assert DRIFT_FP_RATE_THRESHOLD == pytest.approx(0.2)
    assert DRIFT_LOW_CONFIDENCE_THRESHOLD == 40
    assert DRIFT_STALE_DAYS == 30
