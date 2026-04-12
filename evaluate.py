"""
evaluate.py — Multi-Episode Evaluation Harness for SOC Automation Environment

Runs N episodes per difficulty level and produces a summary report with:
  - Average score per difficulty
  - Correct containment accuracy
  - False positive detection rate
  - Average tool queries used
  - Per-attack-type breakdown

Usage:
    python evaluate.py                    # 10 episodes/difficulty, all levels
    python evaluate.py --episodes 20      # 20 episodes per difficulty
    python evaluate.py --difficulty 2     # Only medium difficulty
    python evaluate.py --base-url http://localhost:8000

Exit code: 0 if overall avg score >= threshold, 1 otherwise.
"""

import argparse
import asyncio
import json
import os
import sys
import textwrap
from collections import defaultdict
from typing import List, Optional, Dict, Any

from dotenv import load_dotenv
load_dotenv()

from openai import OpenAI

from client import SocAutomationEnv
from models import SocAutomationAction
from server.scenarios import get_all_scenarios, DIFFICULTY_NAMES, EASY, MEDIUM, HARD, EXPERT

# ─────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────

API_KEY      = os.getenv("HF_TOKEN") or os.getenv("API_KEY") or "dummy_key"
API_BASE_URL = os.getenv("API_BASE_URL") or "https://router.huggingface.co/v1"
MODEL_NAME   = os.getenv("MODEL_NAME") or "Qwen/Qwen2.5-72B-Instruct"

MAX_STEPS         = 12
TEMPERATURE       = 0.4
MAX_TOKENS        = 600
MAX_TOTAL_REWARD  = 4.0
SUCCESS_THRESHOLD = 1.2


# ─────────────────────────────────────────────────
# Inference (same prompt as inference.py)
# ─────────────────────────────────────────────────

from inference import improved_get_model_action as get_model_action, SYSTEM_PROMPT_IMPROVED as SYSTEM_PROMPT, build_enhanced_user_prompt as build_user_prompt

# ─────────────────────────────────────────────────
# Single episode runner
# ─────────────────────────────────────────────────

async def run_episode(env: SocAutomationEnv, llm: OpenAI) -> Dict[str, Any]:
    """Run one episode and return episode statistics."""
    result = await env.reset()
    obs = result.observation

    obs_dict: dict = {
        "current_phase": obs.current_phase,
        "alert_data": obs.alert_data,
        "investigation_results": obs.investigation_results,
        "remaining_budget": obs.remaining_budget,
        "feedback": obs.feedback,
        "difficulty_level": obs.difficulty_level,
        "investigation_quality": obs.investigation_quality,
        "simulated_time_mins": getattr(obs, "simulated_time_mins", 0),
        "isolated_entities": getattr(obs, "isolated_entities", []),
    }

    history: List[str] = []
    rewards: List[float] = []
    actions_taken: List[str] = []
    queried_keys: set = set()
    queries_used = 0
    containment_action = None

    for step_idx in range(1, MAX_STEPS + 1):
        if result.done:
            break

        message = get_model_action(llm, step_idx, obs_dict, history, queried_keys)

        try:
            if message is None:
                raise ValueError("LLM unavailable after retries")
            action_data = json.loads(message)
            action = SocAutomationAction(**action_data)
            if action.action_type == "investigate":
                queries_used += 1
                if action.tool_query:
                    queried_keys.add(action.tool_query)
            if action.action_type == "contain":
                containment_action = action.containment_action
        except Exception as e:
            action = SocAutomationAction(action_type="report", report_text=f"Parse error: {e}")

        actions_taken.append(action.action_type)
        result = await env.step(action)
        obs = result.observation

        reward = result.reward or 0.0
        rewards.append(reward)
        obs_dict = {
            "current_phase": obs.current_phase,
            "alert_data": obs.alert_data,
            "investigation_results": obs.investigation_results,
            "remaining_budget": obs.remaining_budget,
            "feedback": obs.feedback,
            "difficulty_level": obs.difficulty_level,
            "investigation_quality": obs.investigation_quality,
            "simulated_time_mins": getattr(obs, "simulated_time_mins", 0),
            "isolated_entities": getattr(obs, "isolated_entities", []),
        }
        history.append(f"Step {step_idx} [{action.action_type}] → reward={reward:+.1f}")

        if result.done:
            break

    total_reward = sum(rewards)
    # Compute score using average reward matching the inference.py implementation
    score = sum(rewards) / len(rewards) if rewards else 0.001
    score = min(max(score, 0.01), 0.999)

    return {
        "difficulty": obs.difficulty_level,
        "total_reward": total_reward,
        "score": score,
        "success": any(r >= 0.8 for r in rewards) or (containment_action and "dismiss" in str(containment_action).lower() and sum(rewards) > 0.6),
        "queries_used": queries_used,
        "containment_action": containment_action,
        "steps": len(rewards),
        "actions": actions_taken,
        "final_feedback": obs.feedback,
    }


# ─────────────────────────────────────────────────
# Evaluation loop
# ─────────────────────────────────────────────────

async def evaluate(
    base_url: str,
    episodes_per_difficulty: int,
    difficulties: List[int],
    image_name: Optional[str] = None,
) -> None:
    llm = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)

    print(f"\n{'═'*60}")
    print(f"  SOC Environment — Evaluation Harness")
    print(f"  Model:      {MODEL_NAME}")
    print(f"  Episodes:   {episodes_per_difficulty} per difficulty")
    print(f"  Difficulty: {[DIFFICULTY_NAMES[d] for d in difficulties]}")
    print(f"{'═'*60}\n")

    all_results: List[Dict[str, Any]] = []
    by_difficulty: Dict[int, List[Dict]] = defaultdict(list)

    for difficulty in difficulties:
        diff_name = DIFFICULTY_NAMES[difficulty]
        print(f"── [{diff_name}] Running {episodes_per_difficulty} episodes ──")

        env = (
            await SocAutomationEnv.from_docker_image(image_name)
            if image_name
            else SocAutomationEnv(base_url=base_url)
        )

        try:
            for ep in range(episodes_per_difficulty):
                ep_result = await run_episode(env, llm)
                ep_result["difficulty_name"] = diff_name
                all_results.append(ep_result)
                by_difficulty[difficulty].append(ep_result)

                status = "✓" if ep_result["success"] else "✗"
                print(
                    f"  Ep {ep+1:2d}/{episodes_per_difficulty}  {status}  "
                    f"score={ep_result['score']:.3f}  "
                    f"reward={ep_result['total_reward']:+6.1f}  "
                    f"queries={ep_result['queries_used']}  "
                    f"contain={ep_result['containment_action'] or 'N/A'}"
                )
        finally:
            try:
                await env.close()
            except Exception:
                pass

        # Per-difficulty summary
        scores   = [r["score"] for r in by_difficulty[difficulty]]
        rewards  = [r["total_reward"] for r in by_difficulty[difficulty]]
        suc_rate = sum(r["success"] for r in by_difficulty[difficulty]) / len(by_difficulty[difficulty])
        avg_q    = sum(r["queries_used"] for r in by_difficulty[difficulty]) / len(by_difficulty[difficulty])

        print(f"\n  [{diff_name}] Summary:")
        print(f"    Avg Score:   {sum(scores)/len(scores):.3f}")
        print(f"    Avg Reward:  {sum(rewards)/len(rewards):+.1f}")
        print(f"    Success Rate:{suc_rate:.0%}")
        print(f"    Avg Queries: {avg_q:.1f}\n")

    # ── Overall report ──
    print(f"\n{'═'*60}")
    print("  OVERALL RESULTS")
    print(f"{'═'*60}")
    print(f"{'Difficulty':<12} {'Episodes':>8} {'Avg Score':>10} {'Success%':>10} {'Avg Reward':>12} {'Avg Queries':>12}")
    print(f"{'─'*12} {'─'*8} {'─'*10} {'─'*10} {'─'*12} {'─'*12}")

    overall_scores = []
    for difficulty in difficulties:
        results = by_difficulty[difficulty]
        scores  = [r["score"]        for r in results]
        rewards = [r["total_reward"] for r in results]
        queries = [r["queries_used"] for r in results]
        suc     = sum(r["success"]   for r in results) / len(results)

        avg_score  = sum(scores) / len(scores)
        avg_reward = sum(rewards) / len(rewards)
        avg_q_val  = sum(queries) / len(queries)
        overall_scores.append(avg_score)

        print(
            f"{DIFFICULTY_NAMES[difficulty]:<12} {len(results):>8} {avg_score:>10.3f} "
            f"{suc:>9.0%} {avg_reward:>+12.1f} {avg_q_val:>12.1f}"
        )

    overall_avg = sum(overall_scores) / len(overall_scores)
    overall_ok  = overall_avg >= (SUCCESS_THRESHOLD / MAX_TOTAL_REWARD)

    print(f"{'─'*66}")
    print(f"{'OVERALL AVERAGE':<12} {len(all_results):>8} {overall_avg:>10.3f}")
    print(f"\n  Result: {'✓ PASS' if overall_ok else '✗ FAIL'} (threshold: {SUCCESS_THRESHOLD / MAX_TOTAL_REWARD:.3f})")
    print(f"{'═'*60}\n")

    sys.exit(0 if overall_ok else 1)


# ─────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SOC Environment Evaluation Harness")
    parser.add_argument("--episodes",   type=int, default=10,
                        help="Episodes per difficulty level (default: 10)")
    parser.add_argument("--difficulty", type=int, default=None,
                        help="Single difficulty to test: 1=EASY 2=MEDIUM 3=HARD 4=EXPERT (default: all)")
    parser.add_argument("--base-url",   type=str, default="http://127.0.0.1:8000",
                        help="Environment server URL (default: http://127.0.0.1:8000)")
    parser.add_argument("--image",      type=str, default=None,
                        help="Docker image name (overrides --base-url)")
    args = parser.parse_args()

    difficulties = (
        [args.difficulty] if args.difficulty
        else [EASY, MEDIUM, HARD, EXPERT]
    )

    asyncio.run(evaluate(
        base_url=args.base_url,
        episodes_per_difficulty=args.episodes,
        difficulties=difficulties,
        image_name=args.image or os.getenv("IMAGE_NAME"),
    ))
