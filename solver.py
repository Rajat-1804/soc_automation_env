import asyncio
import json
from client import SocAutomationEnv
from models import SocAutomationAction

async def solve_triage():
    print("Connecting to OpenEnv...")
    env = SocAutomationEnv(base_url="http://127.0.0.1:8000")
    
    print("Resetting environment for Scenario 1...")
    result = await env.reset()
    obs = result.observation
    print("\n[ALERT DATA] ->", obs.alert_data)
    
    # 1. TRIAGE Phase
    triage_action = SocAutomationAction(action_type="triage")
    result = await env.step(triage_action)
    print("\n[TRIAGE SUCCESS] Feedback:", result.observation.feedback)
    
    # 2. INVESTIGATE Phase
    investigate_action = SocAutomationAction(
        action_type="investigate",
        tool_name="logs",
        tool_query="192.168.1.101" # Extracted from the default first payload
    )
    result = await env.step(investigate_action)
    print("\n[INVESTIGATION SUCCESS] Results:", result.observation.investigation_results)
    
    # 3. CONTAIN Phase
    contain_action = SocAutomationAction(
        action_type="contain",
        containment_action="block_ip"
    )
    result = await env.step(contain_action)
    print("\n[CONTAINMENT SUCCESS] Feedback:", result.observation.feedback)
    
    # 4. REPORT Phase
    report_action = SocAutomationAction(
        action_type="report",
        report_text="Successfully identified scanning behavior from 192.168.1.101. IP blocked to prevent lateral movement.",
        mitre_id="T1059"
    )
    result = await env.step(report_action)
    print("\n[INCIDENT CLOSED] Score:", result.reward, "| Done:", result.done)

    await env.close()

if __name__ == "__main__":
    asyncio.run(solve_triage())
