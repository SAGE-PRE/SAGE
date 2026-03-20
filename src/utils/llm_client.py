#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LLM Client Module

Unified LLM client configuration shared by single_agent and multi_view_moe.
Supports multiple LLM providers: Gemini, DeepSeek
"""

import json
import logging
import os
from typing import Dict, Any, Optional

# Try import Gemini API
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

# Try import OpenAI SDK (for DeepSeek)
try:
    from openai import OpenAI
    OPENAI_SDK_AVAILABLE = True
except ImportError:
    OPENAI_SDK_AVAILABLE = False


# ============================================================================
# Default Configuration
# ============================================================================

DEFAULT_MODEL_NAME = 'gemini-2.5-pro'
DEFAULT_TIMEOUT = 300  # 5 minutes

# DeepSeek Configuration
DEEPSEEK_BASE_URL = "https://api.deepseek.com"
DEEPSEEK_DEFAULT_MODEL = "deepseek-reasoner"  # DeepSeek-V3.2 reasoning mode (chain of thought)

# Provider Constants
PROVIDER_GEMINI = "gemini"
PROVIDER_DEEPSEEK = "deepseek"


def detect_provider(model_name: str) -> str:
    """Detect provider based on model name"""
    model_lower = model_name.lower()
    if model_lower.startswith("deepseek"):
        return PROVIDER_DEEPSEEK
    elif model_lower.startswith("gemini"):
        return PROVIDER_GEMINI
    else:
        # Default to Gemini
        return PROVIDER_GEMINI


class LLMClient:
    """Unified LLM client supporting multiple providers"""
    
    def __init__(
        self, 
        api_key: str = None, 
        model_name: str = DEFAULT_MODEL_NAME,
        timeout: int = DEFAULT_TIMEOUT,
        client_name: str = "LLMClient",
        provider: str = None
    ):
        """
        Initialize LLM client
        
        Args:
            api_key: API key, defaults from environment (GEMINI_API_KEY or DEEPSEEK_API_KEY)
            model_name: Model name, defaults to gemini-2.5-pro
            timeout: Request timeout in seconds, defaults to 300
            client_name: Client name for logging
            provider: Provider name (gemini/deepseek), auto-detect if not specified
        """
        self.model_name = model_name
        self.timeout = timeout
        self.client_name = client_name
        
        # Conversation history (for multi-turn dialogue)
        self.conversation_history = []
        self.chat_session = None  # Gemini chat session
        
        # Detect or use specified provider
        self.provider = provider or detect_provider(model_name)
        
        if self.provider == PROVIDER_DEEPSEEK:
            self._init_deepseek(api_key)
        else:
            self._init_gemini(api_key)
        
        logging.info(f"[{self.client_name}] Initialized with provider: {self.provider}, model: {model_name}, timeout: {timeout}s")
    
    def _init_gemini(self, api_key: str = None):
        """Initialize Gemini client"""
        self.api_key = api_key or os.getenv('GEMINI_API_KEY')
        if not self.api_key:
            raise ValueError("Gemini API key is required. Set GEMINI_API_KEY environment variable.")
        
        if not GEMINI_AVAILABLE:
            raise ImportError("Google Generative AI library is required. Install with: pip install google-generativeai")
        
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel(self.model_name)
    
    def _init_deepseek(self, api_key: str = None):
        """Initialize DeepSeek client"""
        self.api_key = api_key or os.getenv('DEEPSEEK_API_KEY')
        if not self.api_key:
            raise ValueError("DeepSeek API key is required. Set DEEPSEEK_API_KEY environment variable.")
        
        if not OPENAI_SDK_AVAILABLE:
            raise ImportError("OpenAI SDK is required for DeepSeek. Install with: pip install openai")
        
        self.client = OpenAI(
            api_key=self.api_key,
            base_url=DEEPSEEK_BASE_URL,
            timeout=self.timeout
        )
    
    def generate(self, prompt: str, log_request: bool = True) -> str:
        """
        Call LLM to generate response
        
        Args:
            prompt: Input prompt
            log_request: Whether to log request and response
            
        Returns:
            LLM response text
        """
        if log_request:
            logging.info(f"[{self.client_name}] Calling {self.provider} LLM...")
            logging.info("=" * 80)
            logging.info(f"[{self.client_name}] REQUEST:")
            logging.info("=" * 80)
            logging.info(f"\n{prompt}")
            logging.info("=" * 80)
        
        if self.provider == PROVIDER_DEEPSEEK:
            response_text = self._generate_deepseek(prompt)
        else:
            response_text = self._generate_gemini(prompt)
        
        if log_request:
            logging.info("=" * 80)
            logging.info(f"[{self.client_name}] RESPONSE:")
            logging.info("=" * 80)
            logging.info(f"\n{response_text}")
            logging.info("=" * 80)
        
        return response_text
    
    def _generate_gemini(self, prompt: str) -> str:
        """Call Gemini API"""
        response = self.model.generate_content(
            prompt,
            request_options={"timeout": self.timeout}
        )
        
        if not response.text:
            raise ValueError(f"[{self.client_name}] Empty response from Gemini")
        
        return response.text
    
    def _generate_deepseek(self, prompt: str) -> str:
        """Call DeepSeek API (supports reasoning mode)"""
        # Reasoning mode (deepseek-reasoner) does not support temperature parameter
        is_reasoner = "reasoner" in self.model_name.lower()
        
        # Reasoning mode needs larger max_tokens as reasoning_content also counts towards completion_tokens
        # DeepSeek reasoner's reasoning may consume 20000+ tokens
        max_tokens = 65536 if is_reasoner else 8192
        
        create_params = {
            "model": self.model_name,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "max_tokens": max_tokens
        }
        
        # Non-reasoning mode can set temperature
        if not is_reasoner:
            create_params["temperature"] = 0.7
        
        response = self.client.chat.completions.create(**create_params)
        
        if not response.choices:
            raise ValueError(f"[{self.client_name}] Empty response from DeepSeek")
        
        choice = response.choices[0]
        message = choice.message
        
        # Log detailed diagnostic info
        finish_reason = choice.finish_reason
        usage = response.usage
        
        logging.info(f"[{self.client_name}] DeepSeek response - finish_reason: {finish_reason}")
        if usage:
            logging.info(f"[{self.client_name}] Token usage - prompt: {usage.prompt_tokens}, "
                        f"completion: {usage.completion_tokens}, total: {usage.total_tokens}")
            # Check for reasoning tokens (reasoning_tokens in completion_tokens_details)
            if hasattr(usage, 'completion_tokens_details') and usage.completion_tokens_details:
                details = usage.completion_tokens_details
                reasoning_tokens = getattr(details, 'reasoning_tokens', None)
                if reasoning_tokens:
                    logging.info(f"[{self.client_name}] Reasoning tokens: {reasoning_tokens}")
        
        # Reasoning mode returns reasoning_content (chain of thought) and content (final answer)
        content = message.content
        reasoning_content = getattr(message, 'reasoning_content', None)
        
        # Log reasoning process length
        if reasoning_content:
            logging.info(f"[{self.client_name}] Reasoning content length: {len(reasoning_content)} chars")
        
        # Diagnose empty content cases
        if not content:
            error_details = []
            error_details.append(f"finish_reason={finish_reason}")
            error_details.append(f"has_reasoning_content={bool(reasoning_content)}")
            if reasoning_content:
                error_details.append(f"reasoning_length={len(reasoning_content)}")
                # Log last 500 chars of reasoning_content, may contain incomplete output
                logging.error(f"[{self.client_name}] Reasoning content tail: ...{reasoning_content[-500:]}")
            if usage:
                error_details.append(f"completion_tokens={usage.completion_tokens}")
            
            raise ValueError(f"[{self.client_name}] Empty content from DeepSeek ({', '.join(error_details)})")
        
        return content
    
    def start_chat(self, system_prompt: str = None) -> None:
        """
        Start multi-turn chat session
        
        After calling this method, subsequent chat() calls will be in the same session,
        allowing LLM to access previous conversation history.
        
        Args:
            system_prompt: System prompt to set LLM behavior and role
        """
        self.conversation_history = []
        self.system_prompt = system_prompt
        
        if self.provider == PROVIDER_GEMINI:
            # Gemini uses start_chat() to create session
            # system_instruction is set when creating model
            if system_prompt:
                self.model = genai.GenerativeModel(
                    self.model_name,
                    system_instruction=system_prompt
                )
            self.chat_session = self.model.start_chat(history=[])
            logging.info(f"[{self.client_name}] Started Gemini chat session")
        else:
            # DeepSeek uses messages list to maintain history
            # system message will be added on first call
            logging.info(f"[{self.client_name}] Started DeepSeek chat session")
    
    def chat(self, message: str, log_request: bool = True) -> str:
        """
        Send message in chat session (multi-turn conversation)
        
        Args:
            message: User message
            log_request: Whether to log request and response
            
        Returns:
            LLM response text
        """
        if log_request:
            logging.info(f"[{self.client_name}] Chat turn {len(self.conversation_history) + 1}...")
            logging.info("=" * 80)
            logging.info(f"[{self.client_name}] USER MESSAGE:")
            logging.info("=" * 80)
            logging.info(f"\n{message}")
            logging.info("=" * 80)
        
        if self.provider == PROVIDER_DEEPSEEK:
            response_text = self._chat_deepseek(message)
        else:
            response_text = self._chat_gemini(message)
        
        # Record to history
        self.conversation_history.append({"role": "user", "content": message})
        self.conversation_history.append({"role": "assistant", "content": response_text})
        
        if log_request:
            logging.info("=" * 80)
            logging.info(f"[{self.client_name}] ASSISTANT RESPONSE:")
            logging.info("=" * 80)
            logging.info(f"\n{response_text}")
            logging.info("=" * 80)
        
        return response_text
    
    def _chat_gemini(self, message: str) -> str:
        """Gemini multi-turn conversation"""
        if self.chat_session is None:
            self.start_chat()
        
        response = self.chat_session.send_message(
            message,
            request_options={"timeout": self.timeout}
        )
        
        if not response.text:
            raise ValueError(f"[{self.client_name}] Empty response from Gemini chat")
        
        return response.text
    
    def _chat_deepseek(self, message: str) -> str:
        """DeepSeek multi-turn conversation"""
        # Build complete message list
        messages = []
        
        # Add system message (if any)
        if hasattr(self, 'system_prompt') and self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        
        # Add history messages
        messages.extend(self.conversation_history)
        
        # Add current user message
        messages.append({"role": "user", "content": message})
        
        is_reasoner = "reasoner" in self.model_name.lower()
        max_tokens = 65536 if is_reasoner else 8192
        
        create_params = {
            "model": self.model_name,
            "messages": messages,
            "max_tokens": max_tokens
        }
        
        if not is_reasoner:
            create_params["temperature"] = 0.7
        
        response = self.client.chat.completions.create(**create_params)
        
        if not response.choices:
            raise ValueError(f"[{self.client_name}] Empty response from DeepSeek chat")
        
        content = response.choices[0].message.content
        
        if not content:
            raise ValueError(f"[{self.client_name}] Empty content from DeepSeek chat")
        
        return content
    
    def clear_chat(self) -> None:
        """Clear chat history"""
        self.conversation_history = []
        self.chat_session = None
        self.system_prompt = None
        logging.info(f"[{self.client_name}] Chat session cleared")
    
    def generate_json(self, prompt: str, log_request: bool = True) -> Dict[str, Any]:
        """
        Call LLM to generate JSON response and parse it
        
        Args:
            prompt: Input prompt
            log_request: Whether to log request and response
            
        Returns:
            Parsed JSON object
        """
        response_text = self.generate(prompt, log_request)
        return self.parse_json_response(response_text)
    
    @staticmethod
    def parse_json_response(response_text: str) -> Dict[str, Any]:
        """
        Parse JSON response returned by LLM
        
        Args:
            response_text: LLM response text
            
        Returns:
            Parsed JSON object
        """
        text = response_text.strip()
        
        # Extract JSON code block
        if '```json' in text:
            start = text.find('```json') + 7
            end = text.find('```', start)
            if end != -1:
                text = text[start:end].strip()
        elif '```' in text:
            start = text.find('```') + 3
            end = text.find('```', start)
            if end != -1:
                text = text[start:end].strip()
        
        # Try to find JSON object start position
        if not text.startswith('{') and not text.startswith('['):
            brace_pos = text.find('{')
            bracket_pos = text.find('[')
            if brace_pos != -1 and (bracket_pos == -1 or brace_pos < bracket_pos):
                text = text[brace_pos:]
            elif bracket_pos != -1:
                text = text[bracket_pos:]
        
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse JSON response: {e}")
            logging.error(f"Response text: {text[:500]}...")
            raise ValueError(f"Invalid JSON response: {e}")


def check_gemini_available() -> bool:
    """Check if Gemini API is available"""
    return GEMINI_AVAILABLE


def check_deepseek_available() -> bool:
    """Check if DeepSeek API is available (requires OpenAI SDK)"""
    return OPENAI_SDK_AVAILABLE


def check_api_key_configured(provider: str = None) -> bool:
    """
    Check if API key is configured
    
    Args:
        provider: Provider name (gemini/deepseek), checks any available if not specified
    """
    if provider == PROVIDER_DEEPSEEK:
        return bool(os.getenv('DEEPSEEK_API_KEY'))
    elif provider == PROVIDER_GEMINI:
        return bool(os.getenv('GEMINI_API_KEY'))
    else:
        # Check any API key is configured
        return bool(os.getenv('GEMINI_API_KEY') or os.getenv('DEEPSEEK_API_KEY'))
