"""
Base agent interface for CloudGuard-Anomaly.

Defines the abstract interface that all agentic components implement.
This design allows easy replacement with real LLM-based agents.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseAgent(ABC):
    """
    Abstract base class for all agentic components.

    Agents take structured input and produce structured output with
    human-readable explanations. The current implementation uses
    deterministic logic, but the interface is designed to be compatible
    with LLM-based implementations.
    """

    def __init__(self, name: str):
        """
        Initialize the agent.

        Args:
            name: Agent name/identifier
        """
        self.name = name

    @abstractmethod
    def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process input and generate output.

        Args:
            input_data: Structured input data

        Returns:
            Structured output with explanations
        """
        pass

    def _format_prompt(self, input_data: Dict[str, Any]) -> str:
        """
        Format input data as a prompt for LLM (future use).

        Args:
            input_data: Structured input

        Returns:
            Formatted prompt string
        """
        # Placeholder for LLM integration
        # In a real implementation, this would format the input
        # as a prompt for an LLM
        return str(input_data)

    def _call_llm(self, prompt: str) -> str:
        """
        Call LLM API (placeholder for future implementation).

        Args:
            prompt: Formatted prompt

        Returns:
            LLM response
        """
        # Placeholder for LLM integration
        # In a real implementation, this would call an LLM API
        # (OpenAI, Anthropic Claude, etc.)
        raise NotImplementedError("LLM integration not yet implemented")
