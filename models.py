# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
Data models for the Soc Automation Env Environment.
"""

from typing import Optional, Dict, List

from openenv.core.env_server.types import Action, Observation
from pydantic import Field, ConfigDict


class SocAutomationAction(Action):
    """Action for the Soc Automation Env environment."""
    
    model_config = ConfigDict(extra='ignore')

    action_type: str = Field(
        ...,
        description="The type of action: triage, investigate, contain, or report"
    )
    tool_name: Optional[str] = Field(
        default=None,
        description="Tool to use for investigation: 'logs', 'threat_intel', or 'asset_inventory'"
    )
    tool_query: Optional[str] = Field(
        default=None,
        description="Query string for the tool (e.g. an IP address, username, or hostname)"
    )
    containment_action: Optional[str] = Field(
        default=None,
        description="Action to take: block_ip, password_reset, isolate_machine, escalate, dismiss"
    )
    report_text: Optional[str] = Field(
        default=None,
        description="Final report summary (required for 'report' action)"
    )
    mitre_id: Optional[str] = Field(
        default=None,
        description="MITRE ATT&CK Technique ID suspected (e.g. T1110, T1059)"
    )


class SocAutomationObservation(Observation):
    """Observation from the Soc Automation Env environment."""

    model_config = ConfigDict(extra="ignore", validate_assignment=True, arbitrary_types_allowed=True)

    current_phase: str = Field(
        default="TRIAGE",
        description="Current phase: TRIAGE, INVESTIGATION, CONTAINMENT, REPORTING"
    )
    alert_data: str = Field(
        default="",
        description="The initial security alert text"
    )
    investigation_results: str = Field(
        default="",
        description="Results from the most recent tool query"
    )
    remaining_budget: int = Field(
        default=5,
        description="Remaining tool query budget"
    )
    feedback: str = Field(
        default="",
        description="System feedback, task instruction, or error messages"
    )
    difficulty_level: int = Field(
        default=1,
        description="Current scenario difficulty: 1=EASY, 2=MEDIUM, 3=HARD, 4=EXPERT"
    )
    investigation_quality: float = Field(
        default=0.0,
        description="Fraction of key evidence discovered so far (0.0 to 1.0)"
    )
    simulated_time_mins: int = Field(
        default=0,
        description="Simulated elapsed time in minutes since alert triggered"
    )
    isolated_entities: List[str] = Field(
        default_factory=list,
        description="List of entities currently unreachable due to isolation/containment"
    )
