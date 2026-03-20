#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Skills Base Framework

Defines Skill base class and registration mechanism.
Supports two modes:
1. Phase-based execution (traditional mode)
2. Tool invocation (conversational Agent mode)
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Type


class SkillPhase(Enum):
    """Skill execution phase"""
    PRE_PROCESS = "pre_process"       # Before PCAP preprocessing
    POST_EXTRACT = "post_extract"     # After message extraction
    PRE_ANALYSIS = "pre_analysis"     # Before LLM analysis
    POST_ANALYSIS = "post_analysis"   # After LLM analysis
    VALIDATION = "validation"         # Result validation
    POST_PROCESS = "post_process"     # Final post-processing


@dataclass
class SkillContext:
    """Skill execution context"""
    # Input information
    pcap_path: Optional[str] = None
    protocol_type: Optional[str] = None
    
    # Data being processed
    messages: List[Any] = field(default_factory=list)
    sessions: Dict[Any, Any] = field(default_factory=dict)
    headers: List[bytes] = field(default_factory=list)
    message_log: str = ""
    
    # LLM related
    prompt: str = ""
    llm_response: str = ""
    
    # Analysis result
    analysis_result: Dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Log directory
    log_dir: str = ""


@dataclass
class SkillResult:
    """Skill execution result"""
    success: bool = True
    modified: bool = False  # Whether context was modified
    message: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


@dataclass
class ToolSchema:
    """Tool invocation Schema (for LLM function calling)"""
    name: str
    description: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    
    def to_openai_format(self) -> Dict[str, Any]:
        """Convert to OpenAI function calling format"""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters
            }
        }
    
    def to_gemini_format(self) -> Dict[str, Any]:
        """Convert to Gemini function calling format"""
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters
        }


class Skill(ABC):
    """
    Skill Base Class
    
    Each Skill represents specialized capability in a specific domain, including:
    - Domain knowledge (via prompt enhancement)
    - Standardized workflow (SOP)
    - Executable processing logic
    - Tool interface (for LLM conversational invocation)
    """
    
    # Skill metadata (subclass must override)
    name: str = "base_skill"
    description: str = "Base skill class"
    version: str = "1.0.0"
    
    # Applicable protocol types (empty list means applicable to all protocols)
    supported_protocols: List[str] = []
    
    # Execution phases (can execute in multiple phases)
    phases: List[SkillPhase] = [SkillPhase.PRE_ANALYSIS]
    
    # Priority (lower number = higher priority)
    priority: int = 100
    
    # Whether can be invoked as Tool by LLM
    is_tool: bool = False
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize Skill
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger(f"skill.{self.name}")
    
    def is_applicable(self, context: SkillContext) -> bool:
        """
        Determine if Skill is applicable to current context
        
        Args:
            context: Execution context
            
        Returns:
            Whether applicable
        """
        if not self.supported_protocols:
            return True
        
        protocol = (context.protocol_type or "").lower()
        return protocol in [p.lower() for p in self.supported_protocols]
    
    @abstractmethod
    def execute(self, context: SkillContext, phase: SkillPhase) -> SkillResult:
        """
        Execute Skill (phase-based mode)
        
        Args:
            context: Execution context
            phase: Current execution phase
            
        Returns:
            Execution result
        """
        pass
    
    def get_prompt_enhancement(self, context: SkillContext) -> str:
        """
        Get prompt enhancement content (optional override)
        
        Args:
            context: Execution context
            
        Returns:
            Enhanced prompt fragment
        """
        return ""
    
    def get_sop(self) -> str:
        """
        Get Standard Operating Procedure (SOP)
        
        Returns:
            SOP text
        """
        return ""
    
    # ========== Tool Interface (Conversational Agent Mode) ==========
    
    def get_tool_schema(self) -> Optional[ToolSchema]:
        """
        Get Tool invocation Schema
        
        Subclass overrides this method to support being invoked as Tool by LLM.
        
        Returns:
            ToolSchema or None (does not support Tool mode)
        """
        return None
    
    def invoke(self, context: SkillContext, **kwargs) -> Dict[str, Any]:
        """
        Tool invocation entry point
        
        Executed when LLM decides to invoke this Tool.
        
        Args:
            context: Execution context
            **kwargs: Parameters passed by LLM
            
        Returns:
            Tool execution result (will be returned to LLM)
        """
        # Default implementation: call execute and return data
        result = self.execute(context, SkillPhase.PRE_ANALYSIS)
        return result.data
    
    def __repr__(self) -> str:
        return f"<Skill:{self.name} v{self.version}>"


class SkillRegistry:
    """
    Skill Registry
    
    Manages all available Skills, supports:
    - Register/unregister Skills
    - Query Skills by phase/protocol
    - Auto-discover and load Skills
    """
    
    _instance = None
    _skills: Dict[str, Type[Skill]] = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._skills = {}
        return cls._instance
    
    @classmethod
    def register(cls, skill_class: Type[Skill]) -> Type[Skill]:
        """
        Register Skill (can be used as decorator)
        
        Args:
            skill_class: Skill class
            
        Returns:
            Original Skill class
        """
        instance = cls()
        instance._skills[skill_class.name] = skill_class
        logging.info(f"Registered skill: {skill_class.name}")
        return skill_class
    
    @classmethod
    def unregister(cls, name: str) -> bool:
        """
        Unregister Skill
        
        Args:
            name: Skill name
            
        Returns:
            Whether successfully unregistered
        """
        instance = cls()
        if name in instance._skills:
            del instance._skills[name]
            return True
        return False
    
    @classmethod
    def get(cls, name: str) -> Optional[Type[Skill]]:
        """
        Get Skill class
        
        Args:
            name: Skill name
            
        Returns:
            Skill class or None
        """
        instance = cls()
        return instance._skills.get(name)
    
    @classmethod
    def get_all(cls) -> Dict[str, Type[Skill]]:
        """Get all registered Skills"""
        instance = cls()
        return dict(instance._skills)
    
    @classmethod
    def get_by_phase(cls, phase: SkillPhase) -> List[Type[Skill]]:
        """
        Get all Skills for a specific phase
        
        Args:
            phase: Execution phase
            
        Returns:
            Skill class list
        """
        instance = cls()
        return [
            skill_cls for skill_cls in instance._skills.values()
            if phase in skill_cls.phases
        ]
    
    @classmethod
    def get_by_protocol(cls, protocol: str) -> List[Type[Skill]]:
        """
        Get all Skills applicable to a specific protocol
        
        Args:
            protocol: Protocol type
            
        Returns:
            Skill class list
        """
        instance = cls()
        protocol_lower = protocol.lower()
        return [
            skill_cls for skill_cls in instance._skills.values()
            if not skill_cls.supported_protocols or 
               protocol_lower in [p.lower() for p in skill_cls.supported_protocols]
        ]
    
    @classmethod
    def list_skills(cls) -> List[Dict[str, Any]]:
        """
        List all Skills information
        
        Returns:
            Skills information list
        """
        instance = cls()
        return [
            {
                "name": skill_cls.name,
                "description": skill_cls.description,
                "version": skill_cls.version,
                "phases": [p.value for p in skill_cls.phases],
                "protocols": skill_cls.supported_protocols,
                "priority": skill_cls.priority,
            }
            for skill_cls in instance._skills.values()
        ]


# Convenience decorator
def skill(name: str = None, **kwargs):
    """
    Skill class decorator
    
    Usage:
        @skill(name="my_skill", description="My custom skill")
        class MySkill(Skill):
            pass
    """
    def decorator(cls: Type[Skill]) -> Type[Skill]:
        if name:
            cls.name = name
        for key, value in kwargs.items():
            if hasattr(cls, key):
                setattr(cls, key, value)
        return SkillRegistry.register(cls)
    return decorator
