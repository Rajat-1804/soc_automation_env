# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""Soc Automation Env Environment Client."""

from typing import Dict

from openenv.core import EnvClient
from openenv.core.client_types import StepResult
from openenv.core.env_server.types import State

from models import SocAutomationAction, SocAutomationObservation


class SocAutomationEnv(
    EnvClient[SocAutomationAction, SocAutomationObservation, State]
):
    """
    Client for the Soc Automation Env Environment.

    This client maintains a persistent WebSocket connection to the environment server,
    enabling efficient multi-step interactions with lower latency.
    Each client instance has its own dedicated environment session on the server.

    Example:
        >>> # Connect to a running server
        >>> with SocAutomationEnv(base_url="http://localhost:8000") as client:
        ...     result = client.reset()
        ...     print(result.observation.echoed_message)
        ...
        ...     result = client.step(SocAutomationAction(message="Hello!"))
        ...     print(result.observation.echoed_message)

    Example with Docker:
        >>> # Automatically start container and connect
        >>> client = SocAutomationEnv.from_docker_image("soc_automation_env-env:latest")
        >>> try:
        ...     result = client.reset()
        ...     result = client.step(SocAutomationAction(message="Test"))
        ... finally:
        ...     client.close()
    """

    def _step_payload(self, action: SocAutomationAction) -> Dict:
        """
        Convert SocAutomationAction to JSON payload for step message.

        Args:
            action: SocAutomationAction instance

        Returns:
            Dictionary representation suitable for JSON encoding
        """
        payload = {
            "action_type": action.action_type,
        }
        if action.tool_name is not None:
            payload["tool_name"] = action.tool_name
        if action.tool_query is not None:
            payload["tool_query"] = action.tool_query
        if action.containment_action is not None:
            payload["containment_action"] = action.containment_action
        if action.report_text is not None:
            payload["report_text"] = action.report_text
        if action.mitre_id is not None:
            payload["mitre_id"] = action.mitre_id

        return payload

    def _parse_result(self, payload: Dict) -> StepResult[SocAutomationObservation]:
        """
        Parse server response into StepResult[SocAutomationObservation].

        Args:
            payload: JSON response data from server

        Returns:
            StepResult with SocAutomationObservation
        """
        obs_data = payload.get("observation", {})
        observation = SocAutomationObservation(
            current_phase=obs_data.get("current_phase", "TRIAGE"),
            alert_data=obs_data.get("alert_data", ""),
            investigation_results=obs_data.get("investigation_results", ""),
            remaining_budget=obs_data.get("remaining_budget", 5),
            feedback=obs_data.get("feedback", ""),
            difficulty_level=obs_data.get("difficulty_level", 1),
            investigation_quality=obs_data.get("investigation_quality", 0.0),
            simulated_time_mins=obs_data.get("simulated_time_mins", 0),
            isolated_entities=obs_data.get("isolated_entities", []),
            done=payload.get("done", False),
            reward=payload.get("reward", 0.0),
            metadata=obs_data.get("metadata", {}),
        )

        return StepResult(
            observation=observation,
            reward=payload.get("reward", 0.0),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: Dict) -> State:
        """
        Parse server response into State object.

        Args:
            payload: JSON response from state request

        Returns:
            State object with episode_id and step_count
        """
        return State(
            episode_id=payload.get("episode_id"),
            step_count=payload.get("step_count", 0),
        )
