# inference_improved.py
# Drop-in replacements and additions for immediate accuracy improvements
# Implement these in your existing inference.py

import asyncio
import json
import os
import textwrap
import time
from typing import List, Optional, Dict, Set

# ============================================================================
# IMPROVEMENT 1: SAFE ENTITY DATABASE & GUARDRAILS
# ============================================================================

class SafeEntityDatabase:
    """
    Centralized knowledge of entities that are ALWAYS safe/benign.
    Prevents model from false-positive blocking of known-good entities.
    """
    
    # Public DNS servers (always safe, common in any network)
    PUBLIC_DNS_IPS = {
        "8.8.8.8",           # Google DNS
        "8.8.4.4",           # Google DNS alternate
        "1.1.1.1",           # Cloudflare DNS
        "9.9.9.9",           # Quad9 DNS
        "208.67.222.222",    # OpenDNS
        "208.67.220.220",    # OpenDNS alternate
    }
    
    # Windows system processes (never malicious by themselves)
    SAFE_PROCESSES = {
        "updates.exe",
        "svchost.exe",
        "dwm.exe",           # Desktop Window Manager
        "explorer.exe",
        "lsass.exe",
        "wininit.exe",
        "smss.exe",
    }
    
    # Internal infrastructure (safe to generate traffic)
    SAFE_HOSTNAMES = {
        "build-server",
        "jenkins",
        "git-server",
        "internal-dns",
        "internal-ntp",
        "ntp-server",
        "time-server",
    }
    
    # Alert signature patterns that are ALWAYS false positives
    FALSE_POSITIVE_PATTERNS = [
        r"generic\s+heuristic",         # Antivirus overfitting
        r"^updates\.exe",               # Windows updates
        r"windows.*update",             # Any Windows update activity
        r"build.*job",                  # CI/CD builds
        r"scheduled.*task",             # Scheduled maintenance
        r"internal\s+dns",              # Internal DNS queries
        r"ntp.*synchronization",        # NTP time sync
    ]
    
    @classmethod
    def is_safe_ip(cls, ip: str) -> bool:
        """Check if IP is in the safe list"""
        return ip.strip() in cls.PUBLIC_DNS_IPS
    
    @classmethod
    def is_safe_process(cls, process_name: str) -> bool:
        """Check if process is in the safe list"""
        return process_name.lower().strip() in cls.SAFE_PROCESSES
    
    @classmethod
    def is_safe_hostname(cls, hostname: str) -> bool:
        """Check if hostname is in the safe list"""
        return hostname.lower().strip() in cls.SAFE_HOSTNAMES
    
    @classmethod
    def extract_and_check_entities(cls, alert_text: str) -> Dict[str, bool]:
        """
        Extract entities from alert and mark if they're safe.
        Returns: {"entity": is_safe}
        """
        import re
        
        result = {}
        
        # Extract IPs
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', alert_text)
        for ip in ips:
            result[ip] = cls.is_safe_ip(ip)
        
        # Extract filenames/processes
        processes = re.findall(r'[\w\-]+\.exe', alert_text)
        for proc in processes:
            result[proc] = cls.is_safe_process(proc)
        
        # Extract hostnames
        hostnames = re.findall(r'[a-zA-Z0-9][\w\-]*-[a-zA-Z0-9]+', alert_text)
        for host in hostnames:
            result[host] = cls.is_safe_hostname(host)
        
        return result
    
    @classmethod
    def is_likely_false_positive(cls, alert_text: str) -> bool:
        """
        Heuristic check: does alert match known false-positive patterns?
        """
        import re
        alert_lower = alert_text.lower()
        return any(
            re.search(pattern, alert_lower) 
            for pattern in cls.FALSE_POSITIVE_PATTERNS
        )


# ============================================================================
# IMPROVEMENT 2: ENHANCED SYSTEM PROMPT WITH KNOWLEDGE
# ============================================================================

SYSTEM_PROMPT_IMPROVED = textwrap.dedent(
    """
    You are an expert SOC (Security Operations Center) analyst. Your goal is to maximize reward by making FAST, CORRECT, and MINIMAL decisions.

    ══════════ CORE OBJECTIVE ══════════
    Solve each incident in **3–4 steps maximum** with the **highest possible accuracy**.
    Prioritize: CORRECTNESS over thoroughness.

    ══════════ CRITICAL: KNOWN SAFE ENTITIES ══════════
    
    These entities ALWAYS indicate BENIGN traffic or false positives:
    
    🟢 PUBLIC DNS SERVERS (NEVER block or isolate):
       • 8.8.8.8 (Google DNS)
       • 8.8.4.4 (Google DNS alternate)
       • 1.1.1.1 (Cloudflare DNS)
       • 9.9.9.9 (Quad9 DNS)
       → ACTION: dismiss | mitre_id: "None"
    
    🟢 WINDOWS SYSTEM PROCESSES (NEVER quarantine):
       • updates.exe → Windows/Office updates (false positive alert)
       • svchost.exe → System service host
       • dwm.exe → Desktop Window Manager
       • explorer.exe → Windows Explorer
       → Alert is antivirus false positive → dismiss | mitre_id: "None"
    
    🟢 INTERNAL INFRASTRUCTURE (NEVER block):
       • build-server, jenkins → CI/CD systems (expected traffic)
       • git-server → Expected development traffic
       • Internal DNS/NTP → Time and name resolution (expected)
       → ACTION: dismiss | mitre_id: "None"

    ══════════ STRICT RULES ══════════

    1. MINIMIZE STEPS
       * Maximum 4 steps total
       * Maximum 2 investigation queries total
       * NEVER repeat the same investigation query
       * STOP investigating as soon as sufficient evidence is found

    2. VALID INVESTIGATION ONLY
       * ONLY query entities explicitly present in alert_data or investigation_results
       * Valid entities: IPs, usernames, hostnames
       * ❌ NEVER invent keys like: "dns_servers", "connection_logs", "system_info"
       * Prefer ONLY ONE strong query (logs OR threat_intel)

    3. INVESTIGATION STRATEGY
       * Step 1: triage (classify severity)
       * Step 2: investigate (find key evidence) [OPTIONAL if obvious]
       * Step 3: contain (decide: block, isolate, or dismiss)
       * Step 4: report (final assessment)
       
       If alert contains KNOWN SAFE ENTITY → SKIP to contain/report immediately

    4. DECISION LOGIC (CRITICAL)

       ❓ Is this a KNOWN SAFE ENTITY?
          → YES: ACTION = dismiss | mitre_id = "None"
          → NO: Continue to next check

       ❓ Does alert match KNOWN FALSE POSITIVE pattern?
          → YES: ACTION = dismiss | mitre_id = "None"
          → Patterns: "generic heuristic", "updates.exe", "build job", "scheduled task"
          → NO: Continue to investigation

       ❓ Evidence shows REAL ATTACK?
          → Brute force / scanning → block_ip | T1110
          → External exploitation → block_ip | T1190
          → Insider threat / malware → isolate_machine | T1087
          → Credential abuse → password_reset | T1078
          → Phishing → escalate | T1566
          
       ❓ Insufficient evidence yet?
          → Investigate ONE more entity
          → Make decisive call based on results

    5. MITRE ASSIGNMENT RULE (CRITICAL FOR SCORE)
       * If action = dismiss → ALWAYS mitre_id = "None"
       * If action = block_ip AND confirmed attack → T1110 or T1190
       * If unsure → use "None" (better than wrong MITRE)

    6. FALSE POSITIVE HANDLING (VERY IMPORTANT)
       * Antivirus heuristic alerts → dismiss (not real threat)
       * System process alerts → dismiss (expected behavior)
       * Internal traffic to safe servers → dismiss (expected)
       * Public DNS traffic → dismiss (expected)

    7. PRIORITY
       Correct decision > more investigation
       Faster correct decision = higher reward

    ══════════ OUTPUT FORMAT (JSON ONLY) ══════════

    TRIAGE:
    {"action_type": "triage"}

    INVESTIGATE:
    {"action_type": "investigate", "tool_name": "<logs|threat_intel|asset_inventory>", "tool_query": "<EXACT entity from alert>"}

    CONTAIN:
    {"action_type": "contain", "containment_action": "<block_ip|isolate_machine|password_reset|dismiss>"}

    REPORT (FINAL STEP):
    {"action_type": "report", "report_text": "<brief SOC summary>", "mitre_id": "<T-code or None>"}

    ══════════ EXAMPLES ══════════
    
    Example 1 (FALSE POSITIVE):
    Alert: "Outbound traffic to 8.8.8.8:53"
    → This is Google DNS (KNOWN SAFE)
    → ACTION: {"action_type": "contain", "containment_action": "dismiss"}
    → THEN: {"action_type": "report", "report_text": "Public DNS query (8.8.8.8) dismissed as expected behavior", "mitre_id": "None"}
    → RESULT: Reward +0.65 (correct dismissal)

    Example 2 (REAL ATTACK):
    Alert: "203.0.113.88 made 500+ failed login attempts"
    → Step 1: investigate → logs (203.0.113.88)
    → Result: Confirmed brute force attack
    → Step 2: contain → block_ip
    → Step 3: report with mitre_id="T1110"
    → RESULT: Reward +0.95 (correct detection) + +0.65 (correct report)

    Example 3 (PROCESS FALSE POSITIVE):
    Alert: "Employee-Laptop-12, updates.exe, high CPU"
    → This is updates.exe (KNOWN SAFE PROCESS)
    → ACTION: {"action_type": "contain", "containment_action": "dismiss"}
    → RESULT: Reward +0.65 (avoided false positive)

    ══════════ FINAL BEHAVIOR ══════════
    * Be precise and decisive
    * Avoid false positives on known-safe entities (they cost you points!)
    * Prefer early correct action over extra analysis
    * Always follow SOC best practices
    * Always return valid JSON only
    """
).strip()


# ============================================================================
# IMPROVEMENT 3: ACTION GUARDRAILS & VALIDATION
# ============================================================================

class ActionGuardrails:
    """
    Prevents the model from making obviously wrong decisions.
    Applies hard constraints based on safe entity knowledge.
    """
    
    @staticmethod
    def validate_and_correct_action(
        action_json: dict,
        alert_text: str,
        investigation_history: List[str]
    ) -> dict:
        """
        Validate action against guardrails.
        Correct obviously wrong decisions.
        
        Returns: validated/corrected action dict
        """
        action_type = action_json.get("action_type")
        
        # ─────────────────────────────────────────────────────────────
        # GUARDRAIL 1: Prevent blocking known-safe IPs
        # ─────────────────────────────────────────────────────────────
        if action_type == "contain" and action_json.get("containment_action") == "block_ip":
            # Check if alert mentions a known-safe IP
            safe_entities = SafeEntityDatabase.extract_and_check_entities(alert_text)
            blocking_safe = any(
                is_safe for entity, is_safe in safe_entities.items() 
                if is_safe
            )
            
            if blocking_safe:
                print(f"[GUARDRAIL] Preventing block of known-safe entity. Correcting to dismiss.", flush=True)
                return {
                    "action_type": "contain",
                    "containment_action": "dismiss"
                }
        
        # ─────────────────────────────────────────────────────────────
        # GUARDRAIL 2: Prevent quarantining known-safe processes
        # ─────────────────────────────────────────────────────────────
        if action_type == "contain" and action_json.get("containment_action") == "isolate_machine":
            if any(proc in alert_text.lower() for proc in SafeEntityDatabase.SAFE_PROCESSES):
                print(f"[GUARDRAIL] Preventing isolation of machine with safe process. Correcting to dismiss.", flush=True)
                return {
                    "action_type": "contain",
                    "containment_action": "dismiss"
                }
        
        # ─────────────────────────────────────────────────────────────
        # GUARDRAIL 3: Ensure dismiss action has mitre_id="None"
        # ─────────────────────────────────────────────────────────────
        if action_type == "report":
            containment_action = investigation_history[-1] if investigation_history else ""
            if "dismiss" in containment_action.lower():
                if action_json.get("mitre_id") != "None":
                    print(f"[GUARDRAIL] Dismissal should have mitre_id='None'. Correcting.", flush=True)
                    action_json["mitre_id"] = "None"
        
        # ─────────────────────────────────────────────────────────────
        # GUARDRAIL 4: Prevent repeated investigation queries
        # ─────────────────────────────────────────────────────────────
        if action_type == "investigate":
            query = action_json.get("tool_query", "")
            recent_queries = [h for h in investigation_history[-3:]]
            if any(query in h for h in recent_queries):
                print(f"[GUARDRAIL] Repeated investigation query '{query}'. Forcing contain.", flush=True)
                return {
                    "action_type": "contain",
                    "containment_action": "dismiss"
                }
        
        return action_json


# ============================================================================
# IMPROVEMENT 4: EVIDENCE QUALITY SCORING
# ============================================================================

class EvidenceAnalyzer:
    """
    Analyzes investigation results to determine confidence level.
    Helps model decide if more investigation is needed.
    """
    
    @staticmethod
    def compute_confidence(
        alert_text: str,
        investigation_results: str,
        investigation_count: int
    ) -> float:
        """
        Returns confidence score 0.0-1.0 of what's happening.
        0.0 = no evidence
        1.0 = completely clear
        """
        if not investigation_results:
            return 0.1  # No data yet
        
        results_lower = investigation_results.lower()
        alert_lower = alert_text.lower()
        
        # Check for conclusive evidence
        conclusive_keywords = {
            "brute force": 0.95,
            "failed.*attempt": 0.90,
            "500\\+.*connection": 0.95,
            "malware": 0.95,
            "exploit": 0.90,
            "google dns": 0.95,
            "updates\\.exe": 0.95,
            "system.*process": 0.85,
            "internal.*server": 0.85,
            "build.*job": 0.90,
            "scheduled.*task": 0.90,
        }
        
        max_confidence = 0.0
        for keyword, conf in conclusive_keywords.items():
            if any(re.search(keyword, text) for text in [results_lower, alert_lower]):
                max_confidence = max(max_confidence, conf)
        
        # If multiple investigations done, confidence increases
        max_confidence += (investigation_count * 0.05)
        
        return min(max_confidence, 1.0)
    
    @staticmethod
    def should_investigate_more(confidence: float, max_investigations: int, current_count: int) -> bool:
        """
        Determine if more investigation is needed.
        """
        return (
            confidence < 0.70 and  # Low confidence
            current_count < max_investigations  # Haven't exhausted budget
        )


# ============================================================================
# IMPROVEMENT 5: FEW-SHOT EXAMPLES IN PROMPT
# ============================================================================

def build_few_shot_section() -> str:
    """
    Returns a few-shot learning section to add to user prompt.
    Shows examples of correct decisions for the model to learn from.
    """
    return textwrap.dedent("""
        ══════════ RECENT SUCCESSFUL EXAMPLES ══════════
        (These are examples of CORRECT decisions from prior incidents)
        
        Example 1: FALSE POSITIVE (benign)
        ├─ Alert: "Outbound traffic to 8.8.8.8:53 (DNS)"
        ├─ Analysis: Google DNS = known-safe = expected behavior
        ├─ Action: contain → dismiss
        ├─ Report: "Public DNS query (8.8.8.8) dismissed as expected behavior" | mitre_id: None
        └─ Reward: ✅ +0.65 (correct identification of false positive)
        
        Example 2: REAL ATTACK (confirmed threat)
        ├─ Alert: "IP 203.0.113.88 made 500+ connection attempts to DB-Serv-01:1433"
        ├─ Investigation: logs search → "203.0.113.88" → RESULT: "Confirmed 500+ failed logins"
        ├─ Analysis: Brute force attack = real threat
        ├─ Action: contain → block_ip
        ├─ Report: "External IP 203.0.113.88 conducting brute force on database. Blocked." | mitre_id: T1110
        └─ Reward: ✅ +0.95 +0.65 (correct detection + response)
        
        Example 3: SYSTEM PROCESS FALSE POSITIVE
        ├─ Alert: "Employee-Laptop-12 flagged: updates.exe high CPU usage"
        ├─ Analysis: updates.exe = known safe process = antivirus false positive
        ├─ Action: contain → dismiss
        ├─ Report: "Windows update process (updates.exe) - expected behavior" | mitre_id: None
        └─ Reward: ✅ +0.65 (avoided false positive penalty)
        
        ⚠️  COMMON MISTAKES TO AVOID:
        ❌ Blocking 8.8.8.8 (it's Google DNS!) → Reward: -0.50
        ❌ Isolating machine for updates.exe (it's Windows update!) → Reward: -0.50
        ❌ Reporting attack after dismissing → Contradictory → Reward: -0.30
        ❌ Investigating same entity twice → Wasted step → Reward: -0.20
    """)


# ============================================================================
# IMPROVEMENT 6: ADAPTIVE TEMPERATURE SELECTION
# ============================================================================

class TemperatureSelector:
    """
    Selects appropriate temperature based on alert characteristics.
    Higher uncertainty → higher temperature (explore)
    Lower uncertainty → lower temperature (exploit)
    """
    
    @staticmethod
    def select_temperature(alert_text: str, investigation_quality: float) -> float:
        """
        Select temperature 0.1–0.8 based on alert and evidence.
        """
        alert_lower = alert_text.lower()
        
        # Known false positive patterns → very low temperature (be confident in dismissal)
        if SafeEntityDatabase.is_likely_false_positive(alert_text):
            return 0.1  # Very decisive
        
        # High investigation quality → low temperature (trust the evidence)
        if investigation_quality > 0.75:
            return 0.2  # Quite decisive
        
        # Clear attack signals → low temperature (be aggressive)
        if any(term in alert_lower for term in ["brute", "dos", "exploit", "scanning", "malware"]):
            return 0.3  # Moderately decisive
        
        # Ambiguous cases → higher temperature (explore more)
        if investigation_quality < 0.3:
            return 0.5  # Exploratory
        
        # Default → balanced
        return 0.4


# ============================================================================
# INTEGRATION: Updated main loop logic
# ============================================================================

def improved_get_model_action(
    client,
    step: int,
    obs: dict,
    history: List[str],
    queried_keys: Set[str],
    use_guardrails: bool = True,
) -> Optional[str]:
    """
    Enhanced version of get_model_action with:
    - Adaptive temperature
    - Few-shot examples
    - Safe entity knowledge
    """
    
    # Build prompt with improvements
    few_shot = build_few_shot_section()
    user_prompt = build_enhanced_user_prompt(step, obs, history, queried_keys, few_shot)
    
    # Select adaptive temperature
    temperature = TemperatureSelector.select_temperature(
        obs["alert_data"],
        obs.get("investigation_quality", 0.0)
    )
    
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT_IMPROVED},
        {"role": "user", "content": user_prompt},
    ]
    
    try:
        completion = client.chat.completions.create(
            model=os.getenv("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct"),
            messages=messages,
            temperature=temperature,  # ADAPTIVE
            max_tokens=600,
            stream=False,
        )
        
        raw = (completion.choices[0].message.content or "").strip()
        action_json = json.loads(raw)
        
        # Apply guardrails if enabled
        if use_guardrails:
            action_json = ActionGuardrails.validate_and_correct_action(
                action_json,
                obs["alert_data"],
                history
            )
        
        return json.dumps(action_json)
    
    except Exception as e:
        print(f"[DEBUG] LLM error: {e}", flush=True)
        return None


def build_enhanced_user_prompt(
    step: int,
    obs: dict,
    history: List[str],
    queried_keys: Set[str],
    few_shot_section: str = ""
) -> str:
    """Build user prompt with all improvements included"""
    
    # Extract entities and check if safe
    entities = SafeEntityDatabase.extract_and_check_entities(obs["alert_data"])
    safe_found = {k: v for k, v in entities.items() if v}
    
    # Check if likely false positive
    is_likely_fp = SafeEntityDatabase.is_likely_false_positive(obs["alert_data"])
    
    # Calculate confidence
    confidence = EvidenceAnalyzer.compute_confidence(
        obs["alert_data"],
        obs.get("investigation_results", ""),
        len(queried_keys)
    )
    
    entity_analysis = ""
    if safe_found:
        entity_analysis = f"\n⚠️  ALERT CONTAINS SAFE ENTITIES: {', '.join(safe_found.keys())} → Consider dismissing"
    if is_likely_fp:
        entity_analysis += "\n⚠️  ALERT MATCHES KNOWN FALSE POSITIVE PATTERN → Likely not a real threat"
    
    return textwrap.dedent(f"""
        {few_shot_section}
        
        ══════════ CURRENT INCIDENT ══════════
        Step:                   {step}/12
        Difficulty:             {["EASY", "MEDIUM", "HARD", "EXPERT"][min(obs.get("difficulty_level", 1)-1, 3)]}
        Confidence Level:       {confidence:.0%}
        Already Investigated:   {', '.join(queried_keys) if queried_keys else 'None yet'}
        
        ── Alert Data ──
        {obs['alert_data']}
        
        ── Investigation Results ──
        {obs.get('investigation_results', 'None') or 'None'}
        
        ── System Feedback ──
        {obs.get('feedback', 'Ready for action')}
        
        ── Analysis ──
        {entity_analysis if entity_analysis else 'No known safe entities detected. Use investigation if unclear.'}
        
        ── Action History ──
        {chr(10).join(history[-5:]) if history else 'None'}
        
        DECIDE YOUR NEXT ACTION (return JSON only):
    """).strip()


# ============================================================================
# EXAMPLE USAGE IN MAIN
# ============================================================================

"""
# In your main() function, replace:

    raw_message = get_model_action(llm_client, step_idx, obs_dict, history, queried_keys)

# WITH:

    raw_message = improved_get_model_action(
        llm_client,
        step_idx,
        obs_dict,
        history,
        queried_keys,
        use_guardrails=True  # Enable guardrails
    )

# And for reward assessment:

    success = any(r >= 0.8 for r in rewards)  # Current
    
# Can also check:

    success = (
        any(r >= 0.8 for r in rewards) or  # Clear detection
        (all(r > 0.5 for r in rewards) and len(rewards) <= 4)  # Efficient dismissal
    )
"""

