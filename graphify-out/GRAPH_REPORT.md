# Graph Report - .  (2026-04-12)

## Corpus Check
- 11 files · ~17,056 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 126 nodes · 215 edges · 18 communities detected
- Extraction: 65% EXTRACTED · 35% INFERRED · 0% AMBIGUOUS · INFERRED: 76 edges (avg confidence: 0.5)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 17|Community 17]]

## God Nodes (most connected - your core abstractions)
1. `SocAutomationAction` - 38 edges
2. `SocAutomationEnv` - 31 edges
3. `SocAutomationObservation` - 14 edges
4. `SocAutomationEnvironment` - 11 edges
5. `improved_get_model_action()` - 7 edges
6. `main()` - 7 edges
7. `Scenario` - 7 edges
8. `extract_and_check_entities()` - 6 edges
9. `build_enhanced_user_prompt()` - 6 edges
10. `extract_and_check_entities()` - 6 edges

## Surprising Connections (you probably didn't know these)
- `SocAutomationEnv` --uses--> `SocAutomationObservation`  [INFERRED]
  client.py → models.py
- `Inference Script — SOC Automation Environment (CORRECTED VERSION) ==============` --uses--> `SocAutomationEnv`  [INFERRED]
  inference.py → client.py
- `Check if IP is in the safe list` --uses--> `SocAutomationEnv`  [INFERRED]
  inference.py → client.py
- `Check if process is in the safe list` --uses--> `SocAutomationEnv`  [INFERRED]
  inference.py → client.py
- `Check if hostname is in the safe list` --uses--> `SocAutomationEnv`  [INFERRED]
  inference.py → client.py

## Communities

### Community 0 - "Community 0"
Cohesion: 0.13
Nodes (25): Action, Parse server response into State object.          Args:             payload: JSO, Client for the Soc Automation Env Environment.      This client maintains a pers, Convert SocAutomationAction to JSON payload for step message.          Args:, Parse server response into StepResult[SocAutomationObservation].          Args:, SocAutomationEnv, ActionGuardrails, EvidenceAnalyzer (+17 more)

### Community 1 - "Community 1"
Cohesion: 0.15
Nodes (22): build_enhanced_user_prompt(), build_few_shot_section(), compute_confidence(), extract_and_check_entities(), _fallback_action(), improved_get_model_action(), is_likely_false_positive(), is_safe_hostname() (+14 more)

### Community 2 - "Community 2"
Cohesion: 0.13
Nodes (22): ActionGuardrails, build_enhanced_user_prompt(), build_few_shot_section(), compute_confidence(), EvidenceAnalyzer, extract_and_check_entities(), improved_get_model_action(), is_likely_false_positive() (+14 more)

### Community 3 - "Community 3"
Cohesion: 0.15
Nodes (12): main(), Entry point for direct execution via uv run or python -m.      This function ena, Observation from the Soc Automation Env environment., SocAutomationObservation, Observation, Scenario, clamp_reward(), Dense reward: +5 for finding new evidence, -1 for missing. (+4 more)

### Community 4 - "Community 4"
Cohesion: 0.39
Nodes (7): get_all_scenarios(), get_curriculum_scenario(), get_random_scenario(), get_scenarios_by_difficulty(), Return all scenarios at a given difficulty level., Curriculum learning: return a scenario of the specified difficulty.     Used to, Default random scenario. Maintains roughly 60% real threats, 40% false positives

### Community 5 - "Community 5"
Cohesion: 0.5
Nodes (4): evaluate(), evaluate.py — Multi-Episode Evaluation Harness for SOC Automation Environment  R, Run one episode and return episode statistics., run_episode()

### Community 6 - "Community 6"
Cohesion: 1.0
Nodes (0): 

### Community 7 - "Community 7"
Cohesion: 1.0
Nodes (0): 

### Community 8 - "Community 8"
Cohesion: 1.0
Nodes (1): Check if IP is in the safe list

### Community 9 - "Community 9"
Cohesion: 1.0
Nodes (1): Check if process is in the safe list

### Community 10 - "Community 10"
Cohesion: 1.0
Nodes (1): Check if hostname is in the safe list

### Community 11 - "Community 11"
Cohesion: 1.0
Nodes (1): Extract entities from alert and mark if they're safe.         Returns: {"entity"

### Community 12 - "Community 12"
Cohesion: 1.0
Nodes (1): Heuristic check: does alert match known false-positive patterns?

### Community 13 - "Community 13"
Cohesion: 1.0
Nodes (1): Validate action against guardrails.         Correct obviously wrong decisions.

### Community 14 - "Community 14"
Cohesion: 1.0
Nodes (1): Returns confidence score 0.0-1.0 of what's happening.         0.0 = no evidence

### Community 15 - "Community 15"
Cohesion: 1.0
Nodes (1): Determine if more investigation is needed.

### Community 16 - "Community 16"
Cohesion: 1.0
Nodes (1): Select temperature 0.1–0.8 based on alert and evidence.

### Community 17 - "Community 17"
Cohesion: 1.0
Nodes (0): 

## Knowledge Gaps
- **21 isolated node(s):** `Action for the Soc Automation Env environment.`, `Observation from the Soc Automation Env environment.`, `Centralized knowledge of entities that are ALWAYS safe/benign.     Prevents mode`, `Check if IP is in the safe list`, `Check if process is in the safe list` (+16 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Community 6`** (2 nodes): `solver.py`, `solve_triage()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 7`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 8`** (1 nodes): `Check if IP is in the safe list`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 9`** (1 nodes): `Check if process is in the safe list`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 10`** (1 nodes): `Check if hostname is in the safe list`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 11`** (1 nodes): `Extract entities from alert and mark if they're safe.         Returns: {"entity"`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 12`** (1 nodes): `Heuristic check: does alert match known false-positive patterns?`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 13`** (1 nodes): `Validate action against guardrails.         Correct obviously wrong decisions.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 14`** (1 nodes): `Returns confidence score 0.0-1.0 of what's happening.         0.0 = no evidence`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 15`** (1 nodes): `Determine if more investigation is needed.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 16`** (1 nodes): `Select temperature 0.1–0.8 based on alert and evidence.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 17`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `SocAutomationAction` connect `Community 0` to `Community 1`, `Community 3`, `Community 5`?**
  _High betweenness centrality (0.270) - this node is a cross-community bridge._
- **Why does `SocAutomationEnv` connect `Community 0` to `Community 1`, `Community 3`, `Community 5`?**
  _High betweenness centrality (0.097) - this node is a cross-community bridge._
- **Why does `Scenario` connect `Community 3` to `Community 4`?**
  _High betweenness centrality (0.084) - this node is a cross-community bridge._
- **Are the 35 inferred relationships involving `SocAutomationAction` (e.g. with `SocAutomationEnv` and `Client for the Soc Automation Env Environment.      This client maintains a pers`) actually correct?**
  _`SocAutomationAction` has 35 INFERRED edges - model-reasoned connections that need verification._
- **Are the 26 inferred relationships involving `SocAutomationEnv` (e.g. with `SocAutomationAction` and `SocAutomationObservation`) actually correct?**
  _`SocAutomationEnv` has 26 INFERRED edges - model-reasoned connections that need verification._
- **Are the 11 inferred relationships involving `SocAutomationObservation` (e.g. with `SocAutomationEnv` and `Client for the Soc Automation Env Environment.      This client maintains a pers`) actually correct?**
  _`SocAutomationObservation` has 11 INFERRED edges - model-reasoned connections that need verification._
- **Are the 4 inferred relationships involving `SocAutomationEnvironment` (e.g. with `SocAutomationAction` and `SocAutomationObservation`) actually correct?**
  _`SocAutomationEnvironment` has 4 INFERRED edges - model-reasoned connections that need verification._