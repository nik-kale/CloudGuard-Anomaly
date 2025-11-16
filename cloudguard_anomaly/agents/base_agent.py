"""
Base agent interface for CloudGuard-Anomaly.

Defines the abstract interface that all agentic components implement.
This design allows easy replacement with real LLM-based agents.
"""

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """
    Abstract base class for all agentic components.

    Agents take structured input and produce structured output with
    human-readable explanations. The current implementation uses
    deterministic logic, but the interface is designed to be compatible
    with LLM-based implementations.
    """

    def __init__(self, name: str, llm_provider: Optional[Any] = None):
        """
        Initialize the agent.

        Args:
            name: Agent name/identifier
            llm_provider: Optional LLM provider for intelligent processing
        """
        self.name = name
        self.llm_provider = llm_provider
        self.use_llm = llm_provider is not None

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

    def _call_llm(self, prompt: str, system: str = "", max_tokens: int = 2048) -> str:
        """
        Call LLM API using configured provider.

        Args:
            prompt: Formatted prompt
            system: System prompt (optional)
            max_tokens: Maximum tokens to generate

        Returns:
            LLM response

        Raises:
            NotImplementedError: If no LLM provider is configured
        """
        if not self.llm_provider:
            raise NotImplementedError("LLM provider not configured. Set llm_provider in constructor.")

        try:
            logger.debug(f"Calling LLM for agent '{self.name}'")
            response = self.llm_provider.generate(
                prompt=prompt,
                system=system,
                max_tokens=max_tokens
            )
            logger.debug(f"LLM response received for agent '{self.name}'")
            return response
        except Exception as e:
            logger.error(f"LLM call failed for agent '{self.name}': {e}")
            raise
