"""
MABE Detector — LLM Narrative Enhancement
==========================================

Enhances the programmatically generated triage card narrative with a
richer, analyst-grade description using the Anthropic API.

ROLE IN THE PIPELINE
--------------------
The CorrelationAgent produces a programmatic plain_english field in the
TriageCard — a template-populated sentence like:

    "Account j.harrison showed: event rate 87x above baseline;
     23 distinct hosts contacted including 3 high-value node type(s);
     privilege escalated 2 level(s) within 12s of credential access
     between 2025-11-14T09:00:00.000Z and 2025-11-14T09:04:22.312Z."

This module enhances that into analyst-grade prose — something a
senior SOC analyst might write after reviewing the triage card:

    "Account j.harrison conducted what appears to be a machine-speed
     network enumeration sweep. The session contacted 23 distinct hosts
     at 87x the baseline event rate with sub-second timing consistent
     with autonomous tooling. Within 12 seconds of accessing a file
     server (a likely credential access indicator), the account
     successfully authenticated to 2 high-value infrastructure nodes
     requiring elevated privileges. The combination of velocity,
     breadth, and privilege escalation chaining is strongly indicative
     of AI-driven lateral movement."

DESIGN DECISIONS
----------------
1. Enhancement is ADDITIVE — if the API call fails, the original
   programmatic plain_english is used unchanged. Detection is never
   blocked by narrative generation.

2. Enhancement runs AFTER correlation — it takes the full CorrelationOutput
   and crafts narrative from the top signals and evidence summaries,
   not just the plain_english string.

3. Narratives are generated in BATCH — one API call per alerted session,
   called from main.py after the detection loop, not inside it.

4. The narrative replaces plain_english in the notable event via the
   narrative_override parameter in NotableEventFormatter.format().

PROMPT DESIGN
-------------
The prompt is structured to produce:
  - 2-3 sentences maximum
  - Analyst-grade language (not marketing language)
  - Specific observed values (rates, counts, times) not just labels
  - A clear attribution statement ("strongly/moderately/weakly indicative")
  - No hallucinated details beyond what the signals provide
"""

from __future__ import annotations

import logging
import os
from typing import Optional, Any

logger = logging.getLogger(__name__)

# Anthropic client — imported lazily so the module loads even if
# the anthropic package is not installed (narrative enhancement is optional)
_anthropic_client = None


def _get_client():
    """Lazily initialise and return the Anthropic client."""
    global _anthropic_client
    if _anthropic_client is None:
        try:
            import anthropic
            api_key = os.environ.get("ANTHROPIC_API_KEY")
            if not api_key:
                raise ValueError(
                    "ANTHROPIC_API_KEY environment variable not set."
                )
            _anthropic_client = anthropic.Anthropic(api_key=api_key)
        except ImportError:
            raise ImportError(
                "anthropic package not installed. "
                "Run: pip install anthropic>=0.40.0"
            )
    return _anthropic_client


# ---------------------------------------------------------------------------
# NarrativeEnhancer
# ---------------------------------------------------------------------------

class NarrativeEnhancer:
    """
    Generates analyst-grade narrative descriptions for alerted sessions.

    Parameters
    ----------
    model : str
        Anthropic model to use. Default: claude-sonnet-4-20250514
    max_tokens : int
        Maximum response tokens. Default: 200 (2-3 sentences is enough).
    enabled : bool
        If False, enhance() returns None immediately without API calls.
        Useful for testing or when ANTHROPIC_API_KEY is unavailable.
    """

    def __init__(
        self,
        model: str = "claude-sonnet-4-20250514",
        max_tokens: int = 200,
        enabled: bool = True,
    ) -> None:
        self._model      = model
        self._max_tokens = max_tokens
        self._enabled    = enabled

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def enhance(
        self,
        result,                          # CorrelationOutput
        fallback: Optional[str] = None,
    ) -> Optional[str]:
        """
        Generate an enhanced narrative for one alerted session.

        Parameters
        ----------
        result : CorrelationOutput
            The full correlation result for the session.
        fallback : str | None
            Value to return if enhancement fails or is disabled.
            If None, returns the triage card's plain_english.

        Returns
        -------
        str | None
            Enhanced narrative string, or fallback on failure.
        """
        if not self._enabled:
            return fallback or result.triage_card.plain_english

        prompt = _build_prompt(result)

        try:
            client = _get_client()
            response = client.messages.create(
                model=self._model,
                max_tokens=self._max_tokens,
                system=_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            narrative = response.content[0].text.strip()
            logger.debug(
                "Narrative generated for session %s (%d chars).",
                result.session_id, len(narrative)
            )
            return narrative

        except Exception as exc:
            logger.warning(
                "Narrative enhancement failed for session %s: %s. "
                "Using programmatic fallback.",
                result.session_id, exc
            )
            return fallback or result.triage_card.plain_english

    def enhance_batch(
        self,
        results: list,                   # list[CorrelationOutput]
    ) -> dict[str, str]:
        """
        Generate narratives for a list of alerted sessions.

        Only processes results where alert_triggered is True.

        Parameters
        ----------
        results : list[CorrelationOutput]

        Returns
        -------
        dict[str, str]
            session_id → narrative string.
            Non-alerted sessions are absent from the dict.
            Failed enhancements fall back to plain_english.
        """
        narratives: dict[str, str] = {}
        alerted = [r for r in results if r.alert_triggered]

        logger.info(
            "Generating narratives for %d alerted session(s)...",
            len(alerted)
        )

        for result in alerted:
            narrative = self.enhance(result)
            if narrative:
                narratives[result.session_id] = narrative

        logger.info(
            "Narrative generation complete. %d/%d succeeded.",
            len(narratives), len(alerted)
        )
        return narratives


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """You are a senior SOC analyst writing a concise triage note for a security alert.

Write 2-3 sentences maximum. Use specific observed values from the data provided (rates, counts, times, percentages). Do not invent or extrapolate details beyond what is given. End with a one-phrase confidence assessment: "strongly indicative", "moderately indicative", or "weakly indicative" of AI-driven attack behavior, followed by the specific pattern detected.

Write in plain, professional language. No bullet points, no headers, no markdown."""


def _build_prompt(result) -> str:         # result: CorrelationOutput
    """
    Build the user prompt for narrative generation from a CorrelationOutput.

    Extracts the key signal values from the triage card and evidence
    summaries and presents them in a structured format for the model.
    """
    tc = result.triage_card
    scores = tc.mechanism_scores

    lines: list[str] = [
        f"Account: {tc.account}",
        f"Session window: {tc.time_window.start} to {tc.time_window.end}",
        f"Overall confidence: {result.overall_confidence:.2f} "
        f"(threshold: {result.alert_threshold:.2f})",
        f"Mechanisms fired: {', '.join(result.mechanisms_fired) or 'none'}",
        "",
        "Programmatic summary:",
        tc.plain_english,
        "",
        "Signal details:",
    ]

    # Add top signals from each fired mechanism's evidence summary
    for summary in result.evidence_summary:
        lines.append(f"\n{summary.mechanism_id.upper()} (confidence: "
                     f"{scores.get(summary.mechanism_id, 0.0):.2f}):")
        lines.append(f"  {summary.headline}")
        for signal in (summary.top_signals or [])[:3]:
            lines.append(
                f"  - {signal.name}: observed={signal.observed:.4g}, "
                f"baseline={signal.baseline:.4g}, ratio={signal.ratio:.4g}"
            )

    lines.append(
        "\nWrite a 2-3 sentence analyst triage note based on the above."
    )
    return "\n".join(lines)
