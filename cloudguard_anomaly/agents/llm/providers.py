"""
LLM provider implementations for CloudGuard-Anomaly.

Supports multiple LLM providers with a unified interface.
"""

import json
import logging
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    def generate(self, prompt: str, system: str = "", max_tokens: int = 2048) -> str:
        """
        Generate text from prompt.

        Args:
            prompt: User prompt
            system: System prompt
            max_tokens: Maximum tokens to generate

        Returns:
            Generated text
        """
        pass


class ClaudeLLMProvider(LLMProvider):
    """Anthropic Claude integration."""

    def __init__(self, api_key: str, model: str = "claude-3-5-sonnet-20241022"):
        """
        Initialize Claude provider.

        Args:
            api_key: Anthropic API key
            model: Model name
        """
        try:
            import anthropic
            self.client = anthropic.Anthropic(api_key=api_key)
            self.model = model
            logger.info(f"Initialized Claude LLM provider with model {model}")
        except ImportError:
            raise ImportError("anthropic package required. Install with: pip install anthropic")

    def generate(self, prompt: str, system: str = "", max_tokens: int = 2048) -> str:
        """Generate text using Claude."""
        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=system if system else "You are a cloud security expert.",
                messages=[{"role": "user", "content": prompt}],
            )

            return message.content[0].text

        except Exception as e:
            logger.error(f"Claude API error: {e}")
            raise


class OpenAIProvider(LLMProvider):
    """OpenAI GPT integration."""

    def __init__(self, api_key: str, model: str = "gpt-4-turbo-preview"):
        """
        Initialize OpenAI provider.

        Args:
            api_key: OpenAI API key
            model: Model name
        """
        try:
            import openai
            self.client = openai.OpenAI(api_key=api_key)
            self.model = model
            logger.info(f"Initialized OpenAI provider with model {model}")
        except ImportError:
            raise ImportError("openai package required. Install with: pip install openai")

    def generate(self, prompt: str, system: str = "", max_tokens: int = 2048) -> str:
        """Generate text using OpenAI."""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                max_tokens=max_tokens,
                messages=[
                    {"role": "system", "content": system or "You are a cloud security expert."},
                    {"role": "user", "content": prompt},
                ],
            )

            return response.choices[0].message.content

        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            raise


class LocalLLMProvider(LLMProvider):
    """Local LLM integration (Ollama, etc.)."""

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama2"):
        """
        Initialize local LLM provider.

        Args:
            base_url: Base URL for local LLM server
            model: Model name
        """
        self.base_url = base_url
        self.model = model
        logger.info(f"Initialized local LLM provider at {base_url}")

    def generate(self, prompt: str, system: str = "", max_tokens: int = 2048) -> str:
        """Generate text using local LLM."""
        try:
            import requests

            full_prompt = f"{system}\n\n{prompt}" if system else prompt

            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": full_prompt,
                    "stream": False,
                },
            )

            return response.json()["response"]

        except Exception as e:
            logger.error(f"Local LLM error: {e}")
            raise
