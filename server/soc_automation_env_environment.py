import logging
from typing import Optional

from openenv.core.env_server import Environment
from models import SocAutomationAction, SocAutomationObservation
from server.scenarios import get_curriculum_scenario, Scenario, DIFFICULTY_NAMES

logger = logging.getLogger(__name__)

# --- REWARD SHAPING CONSTANTS ---
R_DISMISS_FALSE_POSIT = 0.6    # Correctly dismissed a false positive
R_CONTAIN_REAL_THREAT = 0.9    # Correctly contained a real threat (block_ip/isolate)
R_DISMISS_REAL_THREAT = 0.1    # Catastrophic: Dismissed a real attack
R_CONTAIN_FALSE_POSIT = 0.1    # Contained a false positive / broke prod
R_REPORT_SUCCESS = 0.6         # Correct report submitted
R_REPORT_FAILED = 0.1          # Incorrect report submitted (wrong MITRE)
R_MEANINGFUL_QUERY = 0.45      # Sweet spot for useful investigation
R_WASTED_QUERY = 0.35          # Wasted/failed query (-0.1 applied dynamically later)
R_INVALID_ACTION = 0.01        # Penalize invalid schema or wrong phase

def clamp_reward(raw_reward: float) -> float:
    """Map raw reward to the strict [0.01, 0.99] bounds to prevent Hackathon validator crashes."""
    return max(0.01, min(0.99, raw_reward))


class SocAutomationEnvironmentState:
    def __init__(self, scenario: Scenario):
        self.scenario = scenario
        self.current_phase = "TRIAGE"
        self.remaining_budget = 5
        self.step_count = 0
        self.found_evidence_keys = set()
        self.is_done = False
        self.simulated_time_mins = 0
        self.isolated_entities = []
        self.last_actions = []  # Track duplicates


class SocAutomationEnvironment(Environment[SocAutomationAction, SocAutomationObservation, SocAutomationEnvironmentState]):
    def __init__(self, config=None):
        super().__init__()
        self.scenario: Optional[Scenario] = None
        self._state: Optional[SocAutomationEnvironmentState] = None

    @property
    def state(self) -> SocAutomationEnvironmentState:
        return self._state


    def reset(self, **kwargs) -> SocAutomationObservation:
        # Default to level 1 for standard runs, or use provided kwargs
        difficulty = kwargs.get("difficulty", 1)
        self.scenario = get_curriculum_scenario(difficulty)
        self._state = SocAutomationEnvironmentState(self.scenario)

        diff_name = DIFFICULTY_NAMES.get(difficulty, "UNKNOWN")
        return SocAutomationObservation(
            current_phase=self._state.current_phase,
            alert_data=self.scenario.alert_text,
            investigation_results="No investigation performed yet.",
            remaining_budget=self._state.remaining_budget,
            feedback=f"[{diff_name}] Phase=TRIAGE. Form a hypothesis (0 mins), then 'investigate' (+5 mins). Budget: 5. Time Limit: {self.scenario.time_limit_mins} mins.",
            difficulty_level=difficulty,
            investigation_quality=0.0,
            simulated_time_mins=0,
            isolated_entities=[],
            done=False,
            reward=clamp_reward(0.05),
        )

    def step(self, action: SocAutomationAction) -> SocAutomationObservation:  # type: ignore[override]
        if self.scenario is None:
            # reset() must be called before step()
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
                reward=clamp_reward(R_INVALID_ACTION),
            )

        # Track duplicates to apply strict -0.1 penalty requested
        is_duplicate = False
        action_signature = f"{action.action_type}:{getattr(action, 'tool_query', '')}:{getattr(action, 'containment_action', '')}"
        if action_signature in self._state.last_actions:
            is_duplicate = True
        self._state.last_actions.append(action_signature)

        self._state.step_count += 1
        reward = 0.05
        feedback = ""
        investigation_results = ""
        done = False

        phase = self._state.current_phase

        if phase == "TRIAGE":
            if action.action_type == "triage":
                self._state.current_phase = "INVESTIGATION"
                self._state.simulated_time_mins += 2
                feedback = "Triage complete (+2 mins). Proceed to INVESTIGATION phase."
                reward += 0.4  # Solid action taken
            elif action.action_type == "investigate":
                self._state.current_phase = "INVESTIGATION"
                self._state.simulated_time_mins += 5
                investigation_results = self._handle_investigate(action)
                # Dense Reward Shaping
                reward += self._calculate_investigate_reward(action)
            else:
                reward += R_INVALID_ACTION
                feedback = "Invalid action for TRIAGE phase. You must 'triage' or 'investigate'."

        elif phase == "INVESTIGATION":
            if action.action_type == "investigate":
                self._state.simulated_time_mins += 5
                
                # Stateful action consequence
                target = action.tool_query or ""
                if any(iso in target for iso in self._state.isolated_entities) or len(self._state.isolated_entities) > 0:
                   investigation_results = "ERROR: Network isolation active. Tools cannot reliably reach requested entities."
                   reward += R_INVALID_ACTION
                elif self._state.remaining_budget > 0:
                    self._state.remaining_budget -= 1
                    investigation_results = self._handle_investigate(action)
                    reward += self._calculate_investigate_reward(action)
                else:
                    investigation_results = "Error: Budget exhausted! You must 'contain' or 'report' now."
            elif action.action_type == "contain":
                self._state.current_phase = "REPORTING"
                self._state.simulated_time_mins += 10
                feedback = "Containment action recorded (+10 mins). Environment ISOLATED. Proceed to REPORTING phase with final report."
                # We simulate locking down the environment
                self._state.isolated_entities.append("NETWORK_LOCKED")
                # Add terminal reward
                reward += self._calculate_containment_reward(action)
            else:
                reward += R_INVALID_ACTION
                feedback = "Invalid action. Choose 'investigate' or 'contain'."

        elif phase == "REPORTING":
            if action.action_type == "report":
                self._state.simulated_time_mins += 5
                done = True
                self._state.is_done = True
                
                # MITRE Grading (reward scaled to user expectation: 0.5 - 0.7 max)
                if self.scenario.mitre_id and self.scenario.mitre_id != "None":
                    if action.mitre_id == self.scenario.mitre_id:
                        reward += R_REPORT_SUCCESS
                        feedback = f"Final Report Received. Excellent work identifying MITRE {action.mitre_id}."
                    else:
                        reward += R_REPORT_FAILED
                        feedback = f"Final Report Received. Failed to identify correct MITRE Framework ID! Expected {self.scenario.mitre_id}."
                else:
                     if action.mitre_id in [None, "None", ""]:
                         reward += R_REPORT_SUCCESS
                         feedback = "Correctly identified no MITRE attack vector (False Positive)."
                     else:
                         reward += R_REPORT_FAILED
                         feedback = "Report included a MITRE ID for a False Positive. False alert."
            else:
                reward += R_INVALID_ACTION
                feedback = "Phase is REPORTING. You must provide a final 'report'."

        # MTTR (Mean Time To Respond) Penalties
        if self._state.simulated_time_mins > self.scenario.time_limit_mins:
            if self.scenario.is_real_threat and phase != "REPORTING":
                reward -= 0.1 # Absolute penalty directly clamped later
                feedback += f" WARNING: MTTR Target blown! Attacker is progressing."

        quality = 0.0
        if self.scenario.key_evidence_keys:
            quality = len(self._state.found_evidence_keys) / len(self.scenario.key_evidence_keys)

        # Apply Duplicate penalty
        if is_duplicate:
            reward -= 0.1

        # Prevent negative BEFORE clamp
        reward = max(0.05, reward)

        return SocAutomationObservation(
            current_phase=self._state.current_phase,
            alert_data=self.scenario.alert_text,
            investigation_results=investigation_results,
            remaining_budget=self._state.remaining_budget,
            feedback=feedback,
            difficulty_level=self.scenario.difficulty,
            investigation_quality=quality,
            simulated_time_mins=self._state.simulated_time_mins,
            isolated_entities=self._state.isolated_entities,
            done=done,
            reward=clamp_reward(reward),
        )

    def _handle_investigate(self, action: SocAutomationAction) -> str:
        tool = action.tool_name
        query = action.tool_query
        
        if not query:
            return "Error: no tool_query provided."

        if tool == "logs":
            return self.scenario.logs_data.get(query, f"No logs found for '{query}'")
        elif tool == "threat_intel":
            return self.scenario.threat_intel_data.get(query, f"No threat intel on '{query}'")
        elif tool == "asset_inventory":
            return self.scenario.asset_inventory_data.get(query, f"Asset '{query}' not found in inventory")
        else:
            return f"Error: Unknown tool '{tool}'"

    def _calculate_investigate_reward(self, action: SocAutomationAction) -> float:
        """Dense reward: +5 for finding new evidence, -1 for missing."""
        query = action.tool_query
        target_keys = self.scenario.key_evidence_keys

        if not query:
            return R_WASTED_QUERY

        # Check if they hit a useful key
        for key in target_keys:
            if key.lower() == query.lower():
                if key not in self._state.found_evidence_keys:
                    self._state.found_evidence_keys.add(key)
                    
                    return R_MEANINGFUL_QUERY
                else:
                    return R_WASTED_QUERY # Already found it
        
        return R_WASTED_QUERY

    def _calculate_containment_reward(self, action: SocAutomationAction) -> float:
        """Terminal reward calculation based on correctness of containment."""
        chosen = action.containment_action
        optimal = self.scenario.optimal_containment

        if self.scenario.is_real_threat:
            if chosen == "dismiss":
                return R_DISMISS_REAL_THREAT
            elif chosen == optimal:
                return R_CONTAIN_REAL_THREAT
            else:
                return 0.2 # Sub-optimal containment, neither great nor catastrophic
        else:
            # It's a false positive
            if chosen == "dismiss":
                return R_DISMISS_FALSE_POSIT
            else:
                # Contained a machine when nothing was wrong
                return R_CONTAIN_FALSE_POSIT
