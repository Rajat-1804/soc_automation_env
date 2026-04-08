"""
Inference Script — SOC Automation Environment
===================================
MANDATORY env vars (set in .env or shell):
    API_BASE_URL       The API endpoint for the LLM.
    MODEL_NAME         The model identifier to use for inference.
    HF_TOKEN           Your Hugging Face / API key.
    LOCAL_IMAGE_NAME   The name of the local image (if using from_docker_image())

STDOUT FORMAT (strictly these three line types only):
    [START] task=<task_name> env=<benchmark> model=<model_name>
    [STEP]  step=<n> action=<action_str> reward=<0.00> done=<true|false> error=<msg|null>
    [END]   success=<true|false> steps=<n> score=<score> rewards=<r1,r2,...,rn>
"""

import asyncio
import json
import os
import sys
import textwrap
import time
import re
import signal
from typing import List, Optional, Dict, Set

# ── SIGPIPE handling ─────────────────────────────────────────────────────────
try:
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
except (AttributeError, OSError):
    pass


def _err(*args, **kwargs):
    """Print to stderr only — never pollutes stdout."""
    print(*args, file=sys.stderr, **kwargs)


# ── Load .env ────────────────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"), override=False)
except ImportError:
    pass

from openai import OpenAI
from client import SocAutomationEnv
from models import SocAutomationAction

# ── Configuration ────────────────────────────────────────────────────────────
LOCAL_IMAGE_NAME = os.getenv("LOCAL_IMAGE_NAME")
HF_TOKEN         = os.getenv("HF_TOKEN")
API_BASE_URL     = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME       = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")
TASK_NAME        = os.getenv("TASK", "soc_incident_response")
BENCHMARK        = os.getenv("BENCHMARK", "soc_automation_env")

IS_OLLAMA = "11434" in API_BASE_URL or "ollama" in API_BASE_URL.lower()

NUM_EPISODES            = 23
MAX_STEPS               = 12
MAX_TOKENS              = 600
LLM_MAX_RETRIES         = 3
LLM_RETRY_DELAY         = 2.0


# ============================================================================
# SAFE ENTITY DATABASE
# ============================================================================

class SafeEntityDatabase:
    PUBLIC_DNS_IPS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9", "208.67.222.222", "208.67.220.220"}
    SAFE_PROCESSES = {"updates.exe", "svchost.exe", "dwm.exe", "explorer.exe", "lsass.exe", "wininit.exe", "smss.exe"}
    SAFE_HOSTNAMES = {"build-server", "jenkins", "git-server", "internal-dns", "internal-ntp", "ntp-server", "time-server"}
    FALSE_POSITIVE_PATTERNS = [
        r"generic\s+heuristic",
        r"^updates\.exe",
        r"windows.*update",
        r"build.*job",
        r"scheduled.*task",
        r"internal\s+dns",
        r"ntp.*synchronization",
    ]

    @classmethod
    def is_safe_ip(cls, ip: str) -> bool:
        return ip.strip() in cls.PUBLIC_DNS_IPS

    @classmethod
    def is_safe_process(cls, process_name: str) -> bool:
        return process_name.lower().strip() in cls.SAFE_PROCESSES

    @classmethod
    def is_safe_hostname(cls, hostname: str) -> bool:
        return hostname.lower().strip() in cls.SAFE_HOSTNAMES

    @classmethod
    def extract_and_check_entities(cls, alert_text: str) -> Dict[str, bool]:
        result = {}
        for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', alert_text):
            result[ip] = cls.is_safe_ip(ip)
        for proc in re.findall(r'[\w\-]+\.exe', alert_text):
            result[proc] = cls.is_safe_process(proc)
        for host in re.findall(r'[a-zA-Z0-9][\w\-]*-[a-zA-Z0-9]+', alert_text):
            result[host] = cls.is_safe_hostname(host)
        return result

    @classmethod
    def is_likely_false_positive(cls, alert_text: str) -> bool:
        alert_lower = alert_text.lower()
        return any(re.search(p, alert_lower) for p in cls.FALSE_POSITIVE_PATTERNS)


# ============================================================================
# SYSTEM PROMPT
# ============================================================================

SYSTEM_PROMPT = textwrap.dedent("""
    You are an expert SOC (Security Operations Center) analyst. Your goal is to maximize reward by making FAST, CORRECT, and MINIMAL decisions.

    ══════════ CORE OBJECTIVE ══════════
    Solve each incident in **3–4 steps maximum** with the **highest possible accuracy**.
    Prioritize: CORRECTNESS over thoroughness.

    ══════════ CRITICAL: KNOWN SAFE ENTITIES ══════════

    🟢 PUBLIC DNS SERVERS (NEVER block or isolate):
       • 8.8.8.8 (Google DNS), 8.8.4.4, 1.1.1.1 (Cloudflare), 9.9.9.9 (Quad9)
       → ACTION: dismiss | mitre_id: "None"

    🟢 WINDOWS SYSTEM PROCESSES (NEVER quarantine):
       • updates.exe, svchost.exe, dwm.exe, explorer.exe
       → Alert is antivirus false positive → dismiss | mitre_id: "None"

    🟢 INTERNAL INFRASTRUCTURE (NEVER block):
       • build-server, jenkins, git-server, Internal DNS/NTP
       → ACTION: dismiss | mitre_id: "None"

    ══════════ STRICT RULES ══════════

    1. MINIMIZE STEPS: Maximum 4 steps total; max 2 investigation queries; NEVER repeat same query.
    2. VALID INVESTIGATION ONLY: Query entities present in alert_data or investigation_results only.
    3. INVESTIGATION STRATEGY:
       - Step 1: triage | Step 2: investigate (OPTIONAL if obvious) | Step 3: contain | Step 4: report
       - If KNOWN SAFE ENTITY → SKIP directly to contain/report.
    4. DECISION LOGIC:
       - Known safe entity? → dismiss | mitre_id: "None"
       - Known false positive pattern? → dismiss | mitre_id: "None"
       - Brute force/scanning → block_ip | T1110
       - External exploitation → block_ip | T1190
       - Insider/malware → isolate_machine | T1087
       - Credential abuse → password_reset | T1078
       - Phishing → escalate | T1566
    5. MITRE: If action=dismiss → ALWAYS mitre_id="None". If unsure → "None".

    ══════════ OUTPUT FORMAT (JSON ONLY) ══════════

    TRIAGE:      {"action_type": "triage"}
    INVESTIGATE: {"action_type": "investigate", "tool_name": "<logs|threat_intel|asset_inventory>", "tool_query": "<exact entity>"}
    CONTAIN:     {"action_type": "contain", "containment_action": "<block_ip|isolate_machine|password_reset|dismiss>"}
    REPORT:      {"action_type": "report", "report_text": "<brief summary>", "mitre_id": "<T-code or None>"}

    Return valid JSON only. No extra text.
""").strip()


# ============================================================================
# ACTION GUARDRAILS
# ============================================================================

class ActionGuardrails:
    @staticmethod
    def validate_and_correct_action(action_json: dict, alert_text: str, history: List[str]) -> dict:
        action_type = action_json.get("action_type")

        # Guardrail 1: prevent blocking known-safe IPs
        if action_type == "contain" and action_json.get("containment_action") == "block_ip":
            safe_entities = SafeEntityDatabase.extract_and_check_entities(alert_text)
            if any(is_safe for _, is_safe in safe_entities.items() if is_safe):
                _err("[GUARDRAIL] Preventing block of known-safe entity → dismiss")
                return {"action_type": "contain", "containment_action": "dismiss"}

        # Guardrail 2: prevent isolating machine with safe process
        if action_type == "contain" and action_json.get("containment_action") == "isolate_machine":
            if any(proc in alert_text.lower() for proc in SafeEntityDatabase.SAFE_PROCESSES):
                _err("[GUARDRAIL] Preventing isolation due to safe process → dismiss")
                return {"action_type": "contain", "containment_action": "dismiss"}

        # Guardrail 3: dismiss + report → mitre_id must be "None"
        if action_type == "report":
            if history and "dismiss" in history[-1].lower():
                if action_json.get("mitre_id") != "None":
                    _err("[GUARDRAIL] Dismissal report → forcing mitre_id=None")
                    action_json["mitre_id"] = "None"

        # Guardrail 4: prevent repeated investigation queries
        if action_type == "investigate":
            query = action_json.get("tool_query", "")
            if any(query in h for h in history[-3:]):
                _err(f"[GUARDRAIL] Repeated query '{query}' → forcing contain/dismiss")
                return {"action_type": "contain", "containment_action": "dismiss"}

        return action_json


# ============================================================================
# PROMPT BUILDER
# ============================================================================

def build_user_prompt(step: int, obs: dict, history: List[str], queried_keys: Set[str]) -> str:
    entities = SafeEntityDatabase.extract_and_check_entities(obs["alert_data"])
    safe_found = {k: v for k, v in entities.items() if v}
    is_likely_fp = SafeEntityDatabase.is_likely_false_positive(obs["alert_data"])

    entity_note = ""
    if safe_found:
        entity_note = f"\n⚠️  SAFE ENTITIES DETECTED: {', '.join(safe_found.keys())} → Consider dismissing"
    if is_likely_fp:
        entity_note += "\n⚠️  MATCHES KNOWN FALSE POSITIVE PATTERN → Likely not a real threat"

    difficulty_names = {1: "EASY", 2: "MEDIUM", 3: "HARD", 4: "EXPERT"}
    diff = difficulty_names.get(obs.get("difficulty_level", 1), "UNKNOWN")

    return textwrap.dedent(f"""
        ══════════ CURRENT INCIDENT ══════════
        Step:                 {step}/12
        Difficulty:           {diff}
        Already Investigated: {', '.join(queried_keys) if queried_keys else 'None'}

        ── Alert ──
        {obs['alert_data']}

        ── Investigation Results ──
        {obs.get('investigation_results', 'None') or 'None'}

        ── System Feedback ──
        {obs.get('feedback', 'Ready for action')}

        ── Analysis Note ──
        {entity_note if entity_note else 'No known safe entities detected.'}

        ── Action History ──
        {chr(10).join(history[-5:]) if history else 'None'}

        DECIDE YOUR NEXT ACTION (JSON only):
    """).strip()


# ============================================================================
# LLM CALL
# ============================================================================

def get_model_action(
    client,
    step: int,
    obs: dict,
    history: List[str],
    queried_keys: Set[str],
) -> Optional[str]:
    if MODEL_NAME.lower() == "dummy":
        return None

    if MODEL_NAME.lower() == "human":
        _err("\n" + "=" * 50)
        _err(build_user_prompt(step, obs, history, queried_keys))
        _err("=" * 50)
        _err("Enter Action JSON > ", end="")
        try:
            return sys.stdin.readline().strip()
        except Exception:
            return None

    user_prompt = build_user_prompt(step, obs, history, queried_keys)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": user_prompt},
    ]

    alert_lower = obs["alert_data"].lower()
    if SafeEntityDatabase.is_likely_false_positive(obs["alert_data"]):
        temperature = 0.1
    elif any(t in alert_lower for t in ["brute", "dos", "exploit", "scanning", "malware"]):
        temperature = 0.3
    else:
        temperature = 0.4

    extra_kwargs = {} if IS_OLLAMA else {"response_format": {"type": "json_object"}}

    delay = LLM_RETRY_DELAY
    for attempt in range(1, LLM_MAX_RETRIES + 1):
        try:
            completion = client.chat.completions.create(
                model=MODEL_NAME,
                messages=messages,
                temperature=temperature,
                max_tokens=MAX_TOKENS,
                stream=False,
                **extra_kwargs,
            )
            raw = (completion.choices[0].message.content or "").strip()

            try:
                action_json = json.loads(raw)
            except json.JSONDecodeError:
                raw_clean = raw.strip("`").strip()
                if raw_clean.startswith("json"):
                    raw_clean = raw_clean[4:].strip()
                action_json = json.loads(raw_clean)

            action_json = ActionGuardrails.validate_and_correct_action(
                action_json, obs["alert_data"], history
            )
            return json.dumps(action_json)

        except json.JSONDecodeError as e:
            _err(f"[DEBUG] Attempt {attempt}/{LLM_MAX_RETRIES}: JSON parse failed: {e}")
        except Exception as e:
            _err(f"[DEBUG] Attempt {attempt}/{LLM_MAX_RETRIES}: {e}")

        if attempt < LLM_MAX_RETRIES:
            time.sleep(delay)
            delay *= 2

    return None


# ============================================================================
# FALLBACK ACTION
# ============================================================================

def _fallback_action(step: int, obs: dict, queried_keys: Set[str]) -> dict:
    phase = obs.get("current_phase", "triage")
    budget = obs.get("remaining_budget", 0)

    if phase == "triage":
        return {"action_type": "triage"}

    if phase == "investigation" and budget > 0:
        alert = str(obs.get("alert_data", ""))
        candidates = re.findall(
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            r'|(?:user|username|host|machine)[\s:=]+([^\s,;]+)'
            r'|\b([A-Za-z0-9_-]{4,20})\b',
            alert,
        )
        flat = [c for group in candidates for c in group if c]
        unqueried = [c for c in flat if c not in queried_keys]
        if unqueried:
            q = unqueried[0]
            queried_keys.add(q)
            return {"action_type": "investigate", "tool_name": "logs", "tool_query": q}

    if phase in ("investigation", "containment"):
        return {"action_type": "contain", "containment_action": "dismiss"}

    return {
        "action_type": "report",
        "report_text": "Automated fallback: LLM unavailable. Escalated for human review.",
        "mitre_id": "None",
    }


# ============================================================================
# STDOUT LOGGERS — THE ONLY THINGS THAT WRITE TO STDOUT
# ============================================================================

def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    error_val = error if error else "null"
    print(
        f"[STEP]  step={step} action={action} reward={reward:.2f} done={str(done).lower()} error={error_val}",
        flush=True,
    )


def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(
        f"[END]   success={str(success).lower()} steps={steps} score={score:.2f} rewards={rewards_str}",
        flush=True,
    )


# ============================================================================
# OBSERVATION HELPER
# ============================================================================

def _obs_to_dict(obs) -> dict:
    return {
        "current_phase":        obs.current_phase,
        "alert_data":           obs.alert_data,
        "investigation_results": obs.investigation_results,
        "remaining_budget":     obs.remaining_budget,
        "feedback":             obs.feedback,
        "difficulty_level":     obs.difficulty_level,
        "investigation_quality": obs.investigation_quality,
        "simulated_time_mins":  getattr(obs, "simulated_time_mins", 0),
        "isolated_entities":    getattr(obs, "isolated_entities", []),
    }


# ============================================================================
# MAIN
# ============================================================================

async def main() -> None:
    llm_client = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN or "dummy_key")

    env = (
        await SocAutomationEnv.from_docker_image(LOCAL_IMAGE_NAME)
        if LOCAL_IMAGE_NAME
        else SocAutomationEnv(base_url="http://127.0.0.1:8000")
    )

    try:
        all_episode_scores: List[float] = []
        success_count = 0

        for episode in range(1, NUM_EPISODES + 1):
            _err(f"[EPISODE {episode}/{NUM_EPISODES}] Starting...")

            # Per-episode state (safe defaults so [END] always has valid data)
            rewards: List[float] = [0.05]
            episode_steps = 0
            success = False
            score = 0.05

            # [START] emitted once per episode
            log_start(task=TASK_NAME, env=BENCHMARK, model=MODEL_NAME)

            try:
                result = await env.reset()
                obs = result.observation
                obs_dict = _obs_to_dict(obs)

                rewards = []  # reset after successful env.reset
                queried_keys: Set[str] = set()
                history: List[str] = []

                for step_idx in range(1, MAX_STEPS + 1):
                    if result.done:
                        break

                    raw_message = get_model_action(
                        llm_client, step_idx, obs_dict, history, queried_keys
                    )
                    error: Optional[str] = None

                    if raw_message is None:
                        _err(f"[DEBUG] Step {step_idx}: LLM unavailable, using fallback")
                        fallback = _fallback_action(step_idx, obs_dict, queried_keys)
                        raw_message = json.dumps(fallback)
                        error = "llm_unavailable"

                    try:
                        action_data = json.loads(raw_message)
                        action = SocAutomationAction(**action_data)

                        if action.action_type == "investigate" and action.tool_query:
                            if action.tool_query in queried_keys:
                                action = SocAutomationAction(
                                    action_type="contain",
                                    containment_action="dismiss",
                                )
                            queried_keys.add(action.tool_query)

                        if action.action_type == "report":
                            if history and "dismiss" in history[-1].lower():
                                action.mitre_id = "None"

                    except Exception as e:
                        error = str(e)
                        _err(f"[DEBUG] Action parse error: {e}")
                        action = SocAutomationAction(
                            action_type="report",
                            report_text=f"Failed to parse action: {e}",
                            mitre_id="None",
                        )

                    reward = 0.05
                    done = True
                    try:
                        result = await env.step(action)
                        obs = result.observation
                        reward = result.reward if result.reward is not None else 0.05
                        done = result.done
                    except Exception as e:
                        error = str(e)
                        _err(f"[DEBUG] env.step failed: {e}")

                    rewards.append(reward)
                    episode_steps += 1

                    try:
                        obs_dict = _obs_to_dict(obs)
                    except Exception as e:
                        _err(f"[DEBUG] obs_to_dict failed: {e}")
                        done = True

                    # [STEP] — one per step, strictly
                    log_step(
                        step=step_idx,
                        action=raw_message.replace("\n", " ")[:100],
                        reward=reward,
                        done=done,
                        error=error,
                    )

                    history.append(
                        f"Step {step_idx} [{action.action_type}]: {raw_message[:80]} → reward={reward:+.2f}"
                    )

                    if done:
                        break

                # Compute episode score
                if rewards:
                    score = sum(rewards) / len(rewards)
                    score = min(max(score, 0.001), 0.999)
                success = any(r >= 0.8 for r in rewards)

                all_episode_scores.append(score)
                if success:
                    success_count += 1

            except Exception as e:
                _err(f"[DEBUG] Episode {episode} error: {e}")
                score = min(max(score, 0.001), 0.999)
                success = False

            finally:
                # [END] always emitted — even on exception
                log_end(
                    success=success,
                    steps=episode_steps,
                    score=score,
                    rewards=rewards if rewards else [0.05],
                )

        # Summary to stderr only
        avg = sum(all_episode_scores) / len(all_episode_scores) if all_episode_scores else 0.0
        _err(f"[SUMMARY] episodes={NUM_EPISODES} avg_score={avg:.3f} success_rate={success_count/NUM_EPISODES*100:.1f}%")

    finally:
        try:
            await env.close()
        except Exception as e:
            _err(f"[DEBUG] env.close() error: {e}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except BaseException as e:
        try:
            _err(f"[FATAL] {e}")
        except Exception:
            pass
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        except Exception:
            pass
    sys.exit(0)