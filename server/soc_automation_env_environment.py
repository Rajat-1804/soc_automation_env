"""
SOC Automation RL Environment — Production-grade implementation.

Key features:
- Real SQLite-backed investigation database per episode (not hardcoded strings)
- Query-dependent tool responses: agents must search for evidence dynamically
- Objective reward grading tied to evidence coverage and correct decisions
- Strict [0.01, 0.99] reward clamping for OpenEnv Phase 2 validation
- SUPPORTS_CONCURRENT_SESSIONS via per-instance state
- SocAutomationEnvironmentState extends openenv State for proper /state endpoint
"""
from __future__ import annotations

import logging
import uuid
from typing import Optional, List, Any, Set

from pydantic import Field, ConfigDict

from openenv.core.env_server import Environment
from openenv.core.env_server.types import State
from models import SocAutomationAction, SocAutomationObservation
from server.scenarios import get_curriculum_scenario, Scenario, DIFFICULTY_NAMES
from server.database import build_episode_db, EpisodeDatabase

logger = logging.getLogger(__name__)

# ─── Reward constants ────────────────────────────────────────────────────────
R_TRIAGE            = 0.40   # Sensible first step
R_MEANINGFUL_QUERY  = 0.50   # Found new evidence via DB query
R_PARTIAL_QUERY     = 0.38   # Query returned data but not key evidence
R_WASTED_QUERY      = 0.20   # Empty result — wasted budget
R_CONTAIN_REAL      = 0.90   # Correctly contained real threat
R_CONTAIN_SUBOPTIMAL= 0.45   # Wrong containment type but at least acted
R_DISMISS_REAL      = 0.05   # Catastrophic: missed real attack
R_DISMISS_FP        = 0.70   # Correctly dismissed false positive
R_CONTAIN_FP        = 0.08   # Contained a non-threat (disrupted production)
R_REPORT_CORRECT    = 0.65   # Correct MITRE ID in final report
R_REPORT_WRONG      = 0.10   # Wrong MITRE ID
R_INVALID           = 0.01   # Invalid schema / wrong phase


def clamp_reward(raw: float) -> float:
    """Clamp to strict (0.01, 0.99) open interval — required by OpenEnv Phase 2."""
    return max(0.01, min(0.99, raw))


def _scenario_to_db_seeds(scenario: Scenario):
    """
    Convert scenario data to DB seed records.
    Uses rich db_* fields if available, otherwise converts legacy dict data.
    """
    # --- LOGS ---
    if scenario.db_logs:
        logs = scenario.db_logs
    else:
        # Convert legacy dict → minimal log records
        logs = []
        for key, val in scenario.logs_data.items():
            is_ip = "." in key and key[0].isdigit()
            logs.append({
                "timestamp": "2026-04-12T08:00:00Z",
                "source_ip": key if is_ip else "10.0.0.99",
                "dest_ip": "10.0.0.1",
                "event_type": "SECURITY_ALERT",
                "message": f"[Entity: {key}] {val}",
                "severity": "HIGH",
                "username": "" if is_ip else key,
                "process": "",
                "port": 0,
            })

    # --- ASSETS ---
    if scenario.db_assets:
        assets = scenario.db_assets
    else:
        assets = []
        for key, val in scenario.asset_inventory_data.items():
            assets.append({
                "hostname": key,
                "ip": "10.0.0.99",
                "owner": "Unknown",
                "department": "Unknown",
                "criticality": "MEDIUM",
                "os": "Windows 10",
                "notes": val,
                "known_safe": False,
            })

    # --- THREAT INTEL ---
    if scenario.db_threat_intel:
        threat_intel = scenario.db_threat_intel
    else:
        threat_intel = []
        for key, val in scenario.threat_intel_data.items():
            rep = "MALICIOUS" if any(w in val.lower() for w in ["malicious", "attack", "risk", "threat", "suspicious"]) else "CLEAN"
            threat_intel.append({
                "indicator": key,
                "indicator_type": "ip" if "." in key and key[0].isdigit() else "domain",
                "reputation": rep,
                "confidence": 80,
                "context": val,
                "mitre_techniques": scenario.mitre_id or "",
            })

    return logs, assets, threat_intel


class SocAutomationEnvironmentState(State):
    """
    Per-episode mutable state for the SOC environment.

    Extends openenv.core.env_server.types.State so the HTTP /state endpoint
    can serialize it correctly and the framework can introspect step_count
    and episode_id.  arbitrary_types_allowed lets us store the Scenario
    dataclass and the in-memory EpisodeDatabase connection.
    """

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        extra="allow",
        validate_assignment=True,
    )

    # Inherited from State: episode_id, step_count
    scenario: Optional[Any] = None
    current_phase: str = "TRIAGE"
    remaining_budget: int = 5
    found_evidence_keys: Any = Field(default=None)  # Set[str]
    is_done: bool = False
    simulated_time_mins: int = 0
    isolated_entities: List[str] = Field(default_factory=list)
    last_actions: List[str] = Field(default_factory=list)
    db: Optional[Any] = None  # EpisodeDatabase (in-memory SQLite)

    def model_post_init(self, __context: Any) -> None:
        """Ensure found_evidence_keys is always a set after construction."""
        if self.found_evidence_keys is None:
            object.__setattr__(self, "found_evidence_keys", set())

    def close(self) -> None:
        if self.db:
            self.db.close()
            self.db = None


class SocAutomationEnvironment(
    Environment[SocAutomationAction, SocAutomationObservation, SocAutomationEnvironmentState]
):
    """
    OpenEnv-compatible SOC Automation environment.

    Real SQLite investigation backend: queries search actual indexed records.
    Each episode gets a fresh database seeded from scenario data + noise.
    """

    SUPPORTS_CONCURRENT_SESSIONS: bool = True

    def __init__(self, config=None):
        super().__init__()
        self.scenario: Optional[Scenario] = None
        self._state: Optional[SocAutomationEnvironmentState] = None

    @property
    def state(self) -> SocAutomationEnvironmentState:
        return self._state

    def reset(
        self,
        seed: Optional[int] = None,
        episode_id: Optional[str] = None,
        **kwargs,
    ) -> SocAutomationObservation:
        """Reset the environment, seed a fresh SQLite DB, return initial observation."""
        # Clean up previous episode DB
        if self._state:
            self._state.close()

        difficulty = kwargs.get("difficulty", 1)
        self.scenario = get_curriculum_scenario(difficulty, seed=seed)

        ep_id = episode_id or str(uuid.uuid4())
        self._state = SocAutomationEnvironmentState(
            scenario=self.scenario,
            episode_id=ep_id,
        )

        # Build the real SQLite investigation database for this episode
        logs, assets, threat_intel = _scenario_to_db_seeds(self.scenario)
        self._state.db = build_episode_db(logs, assets, threat_intel)

        diff_name = DIFFICULTY_NAMES.get(difficulty, "UNKNOWN")
        return SocAutomationObservation(
            current_phase=self._state.current_phase,
            alert_data=self.scenario.alert_text,
            investigation_results=(
                "No investigation performed yet. "
                "Use 'investigate' action with tool_name=logs|threat_intel|asset_inventory "
                "and tool_query=<entity> to search the investigation database."
            ),
            remaining_budget=self._state.remaining_budget,
            feedback=(
                f"[{diff_name}] TRIAGE phase. Budget: 5 queries. "
                f"Time limit: {self.scenario.time_limit_mins} mins. "
                "Start with 'triage' then investigate thoroughly before containing."
            ),
            difficulty_level=difficulty,
            investigation_quality=0.0,
            simulated_time_mins=0,
            isolated_entities=[],
            done=False,
            reward=clamp_reward(0.05),
        )

    def step(self, action: SocAutomationAction, timeout_s: Optional[float] = None, **kwargs) -> SocAutomationObservation:  # type: ignore[override]
        if self.scenario is None or self._state is None:
            return SocAutomationObservation(
                current_phase="TRIAGE",
                alert_data="",
                investigation_results="",
                remaining_budget=0,
                feedback="ERROR: Call reset() before step().",
                difficulty_level=1,
                investigation_quality=0.0,
                simulated_time_mins=0,
                isolated_entities=[],
                done=True,
                reward=clamp_reward(R_INVALID),
            )

        # Duplicate detection
        action_sig = (
            f"{action.action_type}:"
            f"{getattr(action, 'tool_query', '')}:"
            f"{getattr(action, 'containment_action', '')}"
        )
        is_duplicate = action_sig in self._state.last_actions
        self._state.last_actions.append(action_sig)
        self._state.step_count += 1  # inherited from State

        reward = 0.0
        feedback = ""
        investigation_results = ""
        done = False
        phase = self._state.current_phase

        # ── TRIAGE phase ──────────────────────────────────────────────────────
        if phase == "TRIAGE":
            if action.action_type == "triage":
                self._state.current_phase = "INVESTIGATION"
                self._state.simulated_time_mins += 2
                feedback = (
                    "Triage complete (+2 mins). Hypothesis formed. "
                    "Now in INVESTIGATION phase. Use 'investigate' to query the database."
                )
                reward = R_TRIAGE

            elif action.action_type == "investigate":
                # Allow early investigation (skip triage step)
                self._state.current_phase = "INVESTIGATION"
                self._state.simulated_time_mins += 5
                self._state.remaining_budget -= 1
                investigation_results = self._run_db_query(action)
                reward = self._score_investigation(action, investigation_results)

            else:
                reward = R_INVALID
                feedback = "Invalid action for TRIAGE phase. Start with 'triage' or 'investigate'."

        # ── INVESTIGATION phase ───────────────────────────────────────────────
        elif phase == "INVESTIGATION":
            if action.action_type == "investigate":
                self._state.simulated_time_mins += 5

                if self._state.remaining_budget <= 0:
                    investigation_results = (
                        "BUDGET EXHAUSTED. No more queries available. "
                        "You must 'contain' or escalate now."
                    )
                    reward = R_INVALID
                elif self._state.isolated_entities:
                    investigation_results = (
                        "ERROR: Network isolation active. "
                        "Investigation tools cannot reach isolated entities."
                    )
                    reward = R_INVALID
                else:
                    self._state.remaining_budget -= 1
                    investigation_results = self._run_db_query(action)
                    reward = self._score_investigation(action, investigation_results)

            elif action.action_type == "contain":
                self._state.current_phase = "REPORTING"
                self._state.simulated_time_mins += 10
                self._state.isolated_entities.append("NETWORK_LOCKED")
                contain_reward = self._score_containment(action)
                # Bonus: reward scales with how much evidence was gathered first
                evidence_bonus = self._evidence_coverage_bonus()
                reward = contain_reward + evidence_bonus
                feedback = (
                    f"Containment action '{action.containment_action}' executed (+10 mins). "
                    f"Environment locked. Proceed to REPORTING with your final incident report."
                )

            else:
                reward = R_INVALID
                feedback = "Invalid action. In INVESTIGATION phase, use 'investigate' or 'contain'."

        # ── REPORTING phase ───────────────────────────────────────────────────
        elif phase == "REPORTING":
            if action.action_type == "report":
                self._state.simulated_time_mins += 5
                done = True
                self._state.is_done = True
                reward, feedback = self._score_report(action)
            else:
                reward = R_INVALID
                feedback = "Phase is REPORTING. Provide a final 'report' action."

        # ── Penalties ─────────────────────────────────────────────────────────
        if self._state.simulated_time_mins > self.scenario.time_limit_mins:
            if self.scenario.is_real_threat and not done:
                reward -= 0.10
                feedback += " ⚠ MTTR exceeded! Attacker is progressing unchecked."

        if is_duplicate:
            reward -= 0.10
            feedback += " [Duplicate action penalty applied]"

        reward = max(0.05, reward)

        quality = 0.0
        if self.scenario.key_evidence_keys:
            quality = len(self._state.found_evidence_keys) / len(self.scenario.key_evidence_keys)

        return SocAutomationObservation(
            current_phase=self._state.current_phase,
            alert_data=self.scenario.alert_text,
            investigation_results=investigation_results,
            remaining_budget=self._state.remaining_budget,
            feedback=feedback,
            difficulty_level=self.scenario.difficulty,
            investigation_quality=round(quality, 3),
            simulated_time_mins=self._state.simulated_time_mins,
            isolated_entities=self._state.isolated_entities,
            done=done,
            reward=clamp_reward(reward),
        )

    # ─── Real database investigation ─────────────────────────────────────────

    def _run_db_query(self, action: SocAutomationAction) -> str:
        """Execute a real SQL query against the episode's SQLite database."""
        tool = action.tool_name
        query = (action.tool_query or "").strip()

        if not query:
            return "Error: tool_query is required. Provide an entity (IP, hostname, username, domain, or base64 payload) to search."

        if not self._state.db:
            return "Error: Investigation database unavailable."

        if tool == "logs":
            return self._state.db.query_logs(query)
        elif tool == "threat_intel":
            return self._state.db.query_threat_intel(query)
        elif tool == "asset_inventory":
            return self._state.db.query_asset_inventory(query)
        elif tool == "sandbox":
            return self._run_sandbox(query)
        else:
            return (
                f"Error: Unknown tool '{tool}'. "
                "Available tools: logs | threat_intel | asset_inventory | sandbox"
            )

    def _run_sandbox(self, payload: str) -> str:
        """
        Simulate safe detonation of a suspicious payload (Base64 or URL).
        Returns simulated IOCs — forces multi-hop tool chaining.
        """
        import base64
        decoded = None
        try:
            decoded = base64.b64decode(payload + "==").decode("utf-8", errors="replace")
        except Exception:
            decoded = payload

        # Check if the decoded/raw payload matches any threat intel context
        if self._state.db:
            result = self._state.db.query_threat_intel(payload[:30])
            if "MALICIOUS" in result or "SUSPICIOUS" in result:
                return (
                    f"[SANDBOX] Payload detonated safely.\n"
                    f"  Decoded content: {decoded[:120]}\n"
                    f"  Behavior observed: Attempted outbound connection to C2 server.\n"
                    f"  Network IOC extracted: {payload[:20]}... resolves to known C2 infrastructure.\n"
                    f"  MITRE: T1059.003 (PowerShell), T1071.001 (Web Protocol C2)\n"
                    f"  Verdict: MALICIOUS — recommend immediate isolation."
                )

        # Might be a real base64 payload
        if len(payload) > 20 and decoded and decoded != payload:
            return (
                f"[SANDBOX] Payload detonated safely.\n"
                f"  Decoded content: {decoded[:120]}\n"
                f"  Behavior observed: No suspicious network activity. Payload appears benign.\n"
                f"  Verdict: CLEAN — no IOCs extracted."
            )

        return (
            f"[SANDBOX] Cannot detonate '{payload[:40]}'. "
            "Provide a Base64-encoded payload or known suspicious string."
        )

    def _score_investigation(self, action: SocAutomationAction, result: str) -> float:
        """
        Objective reward based on actual DB query result quality.
        - Found new key evidence → R_MEANINGFUL_QUERY
        - Got some data (not key evidence) → R_PARTIAL_QUERY
        - Empty result → R_WASTED_QUERY
        """
        query = (action.tool_query or "").strip().lower()

        # Check if this query found key evidence
        for key in self.scenario.key_evidence_keys:
            if key.lower() in query or query in key.lower():
                if key not in self._state.found_evidence_keys:
                    self._state.found_evidence_keys.add(key)
                    return R_MEANINGFUL_QUERY

        # Check if the DB returned any data at all
        if "No log entries found" in result or "No intelligence records" in result or "not found in CMDB" in result:
            return R_WASTED_QUERY

        # Got data but not the key evidence — partial reward
        return R_PARTIAL_QUERY

    def _evidence_coverage_bonus(self) -> float:
        """Bonus reward for gathering evidence before containing (0.0–0.15)."""
        if not self.scenario.key_evidence_keys:
            return 0.0
        coverage = len(self._state.found_evidence_keys) / len(self.scenario.key_evidence_keys)
        return round(coverage * 0.15, 3)

    def _score_containment(self, action: SocAutomationAction) -> float:
        """Objective terminal reward based on containment correctness."""
        chosen = action.containment_action
        optimal = self.scenario.optimal_containment

        if self.scenario.is_real_threat:
            if chosen == "dismiss":
                return R_DISMISS_REAL
            elif chosen == optimal:
                return R_CONTAIN_REAL
            else:
                return R_CONTAIN_SUBOPTIMAL
        else:
            # False positive scenario
            if chosen == "dismiss":
                return R_DISMISS_FP
            else:
                return R_CONTAIN_FP

    def _score_report(self, action: SocAutomationAction) -> tuple:
        """
        Score the final incident report.
        
        Checks:
        1. MITRE ID correctness
        2. Hallucination penalty: report must not mention entities never found in investigation
        
        Returns (reward, feedback_str).
        """
        expected_mitre = self.scenario.mitre_id
        report_text = (action.report_text or "").lower()

        # ── Hallucination check ────────────────────────────────────────────────
        # Extract all IPs mentioned in the report
        import re
        mentioned_ips = set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', report_text))
        # Check all key evidence keys that were actually queried
        queried_terms = {k.lower() for k in self._state.found_evidence_keys}
        # Any IP in the report that was never investigated = hallucination
        hallucinated = {ip for ip in mentioned_ips if ip not in report_text or not any(ip in q for q in queried_terms)}
        # Only penalize if the IP is real-looking AND was never successfully queried
        actually_hallucinated = {
            ip for ip in mentioned_ips
            if not any(ip in k.lower() for k in self._state.found_evidence_keys)
            and not any(ip in log_result for log_result in [])  # placeholder — checked via found_evidence_keys
        }
        hallucination_penalty = 0.0
        hallucination_note = ""
        if actually_hallucinated and self.scenario.is_real_threat:
            hallucination_penalty = 0.15
            hallucination_note = (
                f" ⚠ HALLUCINATION DETECTED: Report mentions "
                f"{list(actually_hallucinated)[:2]} which were never confirmed by investigation tools."
            )

        # ── MITRE ID grading ──────────────────────────────────────────────────
        if expected_mitre and expected_mitre != "None":
            if action.mitre_id == expected_mitre:
                reward = max(0.01, R_REPORT_CORRECT - hallucination_penalty)
                return reward, (
                    f"✓ Excellent final report. Correctly identified MITRE {action.mitre_id}.{hallucination_note}"
                )
            else:
                reward = max(0.01, R_REPORT_WRONG - hallucination_penalty)
                return reward, (
                    f"✗ Report submitted. Wrong MITRE ID. Expected: {expected_mitre}, Got: {action.mitre_id}.{hallucination_note}"
                )
        else:
            # False positive — should report None
            if action.mitre_id in [None, "None", ""]:
                return R_REPORT_CORRECT, "✓ Correctly identified this as a false positive (no MITRE ID)."
            else:
                return R_REPORT_WRONG, (
                    f"✗ This was a false positive, but report included MITRE ID: {action.mitre_id}."
                )
