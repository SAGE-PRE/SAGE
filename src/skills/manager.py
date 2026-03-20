#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Skill Manager

Responsible for Skills lifecycle management and workflow coordination.
Supports two modes:
1. Phase-based execution (traditional mode)
2. Tool invocation (conversational Agent mode)
"""

import logging
import importlib
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

from .base import Skill, SkillContext, SkillPhase, SkillRegistry, SkillResult, ToolSchema


class SkillManager:
    """
    Skill Manager
    
    Responsible for:
    - Auto-discover and load Skills
    - Coordinate Skill execution by phase
    - Manage Skill lifecycle
    - Collect and merge Skill results
    - Provide Tool invocation interface (conversational Agent)
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize manager
        
        Args:
            config: Global configuration, supports skills.{skill_name}.{option} format
        """
        self.config = config or {}
        self.logger = logging.getLogger("skill_manager")
        self._skill_instances: Dict[str, Skill] = {}
        self._loaded = False
    
    def set_skill_config(self, skill_name: str, key: str, value: Any) -> None:
        """
        Set Skill configuration
        
        Args:
            skill_name: Skill name
            key: Configuration key
            value: Configuration value
        """
        if "skills" not in self.config:
            self.config["skills"] = {}
        if skill_name not in self.config["skills"]:
            self.config["skills"][skill_name] = {}
        self.config["skills"][skill_name][key] = value
        
        # If skill is already instantiated, update its configuration
        if skill_name in self._skill_instances:
            skill = self._skill_instances[skill_name]
            if hasattr(skill, key):
                setattr(skill, key, value)
    
    def discover_and_load(self, skills_dir: str = None) -> int:
        """
        Discover and load Skills
        
        Args:
            skills_dir: Skills directory path
            
        Returns:
            Number of loaded Skills
        """
        if self._loaded:
            return len(self._skill_instances)
        
        # Determine skills directory
        if skills_dir is None:
            skills_dir = Path(__file__).parent / "builtin"
        else:
            skills_dir = Path(skills_dir)
        
        if not skills_dir.exists():
            self.logger.warning(f"Skills directory not found: {skills_dir}")
            # Create directory and load builtin skills
            skills_dir.mkdir(parents=True, exist_ok=True)
        
        # Scan and load Python files
        loaded_count = 0
        for py_file in skills_dir.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
            
            try:
                module_name = f"skills.builtin.{py_file.stem}"
                importlib.import_module(module_name)
                loaded_count += 1
                self.logger.debug(f"Loaded skill module: {module_name}")
            except Exception as e:
                self.logger.warning(f"Failed to load skill module {py_file}: {e}")
        
        # Instantiate all registered Skills
        for name, skill_cls in SkillRegistry.get_all().items():
            if name not in self._skill_instances:
                try:
                    skill_config = self.config.get("skills", {}).get(name, {})
                    self._skill_instances[name] = skill_cls(skill_config)
                    self.logger.info(f"Instantiated skill: {name}")
                except Exception as e:
                    self.logger.error(f"Failed to instantiate skill {name}: {e}")
        
        self._loaded = True
        return len(self._skill_instances)
    
    def get_skill(self, name: str) -> Optional[Skill]:
        """
        Get Skill instance
        
        Args:
            name: Skill name
            
        Returns:
            Skill instance or None
        """
        return self._skill_instances.get(name)
    
    def get_applicable_skills(
        self, 
        context: SkillContext, 
        phase: SkillPhase
    ) -> List[Skill]:
        """
        Get applicable Skills for current phase
        
        Args:
            context: Execution context
            phase: Execution phase
            
        Returns:
            List of applicable Skill instances (sorted by priority)
        """
        applicable = []
        
        for skill in self._skill_instances.values():
            if phase in skill.phases and skill.is_applicable(context):
                applicable.append(skill)
        
        # Sort by priority
        applicable.sort(key=lambda s: s.priority)
        return applicable
    
    def execute_phase(
        self, 
        context: SkillContext, 
        phase: SkillPhase
    ) -> List[SkillResult]:
        """
        Execute all applicable Skills for a specific phase
        
        Args:
            context: Execution context
            phase: Execution phase
            
        Returns:
            Execution results from all Skills
        """
        results = []
        skills = self.get_applicable_skills(context, phase)
        
        self.logger.info(f"Executing phase {phase.value} with {len(skills)} skills")
        
        for skill in skills:
            try:
                self.logger.debug(f"Executing skill: {skill.name}")
                result = skill.execute(context, phase)
                results.append(result)
                
                if not result.success:
                    self.logger.warning(
                        f"Skill {skill.name} failed: {result.message}"
                    )
                elif result.modified:
                    self.logger.info(
                        f"Skill {skill.name} modified context: {result.message}"
                    )
                    
            except Exception as e:
                self.logger.error(f"Skill {skill.name} raised exception: {e}")
                results.append(SkillResult(
                    success=False,
                    message=f"Exception: {str(e)}",
                    errors=[str(e)]
                ))
        
        return results
    
    def collect_prompt_enhancements(self, context: SkillContext) -> str:
        """
        Collect prompt enhancements from all applicable Skills
        
        Args:
            context: Execution context
            
        Returns:
            Merged prompt enhancement content
        """
        enhancements = []
        
        for skill in self._skill_instances.values():
            if skill.is_applicable(context):
                enhancement = skill.get_prompt_enhancement(context)
                if enhancement:
                    enhancements.append(f"# {skill.name} Enhancement\n{enhancement}")
        
        return "\n\n".join(enhancements)
    
    def get_combined_sop(self, context: SkillContext) -> str:
        """
        Get combined SOP from all applicable Skills
        
        Args:
            context: Execution context
            
        Returns:
            Combined SOP
        """
        sops = []
        
        for skill in self._skill_instances.values():
            if skill.is_applicable(context):
                sop = skill.get_sop()
                if sop:
                    sops.append(f"## {skill.name} SOP\n{sop}")
        
        return "\n\n".join(sops)
    
    def list_skills(self) -> List[Dict[str, Any]]:
        """
        List all loaded Skills
        
        Returns:
            Skills information list
        """
        return [
            {
                "name": skill.name,
                "description": skill.description,
                "version": skill.version,
                "phases": [p.value for p in skill.phases],
                "protocols": skill.supported_protocols,
                "priority": skill.priority,
                "is_tool": skill.is_tool,
                "loaded": True,
            }
            for skill in self._skill_instances.values()
        ]
    
    def reload_skills(self) -> int:
        """
        Reload all Skills
        
        Returns:
            Number of loaded Skills
        """
        self._skill_instances.clear()
        self._loaded = False
        return self.discover_and_load()
    
    # ========== Tool Mode Interface ==========
    
    def get_available_tools(self, context: SkillContext = None) -> List[Skill]:
        """
        Get available Tool Skills
        
        Args:
            context: Execution context (optional, for filtering)
            
        Returns:
            List of Skills that support Tool mode
        """
        tools = []
        for skill in self._skill_instances.values():
            if skill.is_tool and skill.get_tool_schema() is not None:
                if context is None or skill.is_applicable(context):
                    tools.append(skill)
        return tools
    
    def get_tool_schemas(self, context: SkillContext = None, format: str = "openai") -> List[Dict[str, Any]]:
        """
        Get Schema for all available Tools
        
        Args:
            context: Execution context (optional)
            format: Output format, "openai" or "gemini"
            
        Returns:
            Tool Schema list
        """
        schemas = []
        for skill in self.get_available_tools(context):
            schema = skill.get_tool_schema()
            if schema:
                if format == "openai":
                    schemas.append(schema.to_openai_format())
                elif format == "gemini":
                    schemas.append(schema.to_gemini_format())
                else:
                    schemas.append({
                        "name": schema.name,
                        "description": schema.description,
                        "parameters": schema.parameters
                    })
        return schemas
    
    def invoke_tool(
        self, 
        tool_name: str, 
        context: SkillContext, 
        **kwargs
    ) -> Dict[str, Any]:
        """
        Invoke specified Tool
        
        Args:
            tool_name: Tool name (can be skill name or tool schema name)
            context: Execution context
            **kwargs: Tool parameters
            
        Returns:
            Tool execution result
            
        Raises:
            ValueError: Tool does not exist or does not support invocation
        """
        # First try to find by skill name
        skill = self._skill_instances.get(tool_name)
        
        # If not found, try to find by tool schema name
        if skill is None:
            for s in self._skill_instances.values():
                if s.is_tool:
                    schema = s.get_tool_schema()
                    if schema and schema.name == tool_name:
                        skill = s
                        break
        
        if skill is None:
            raise ValueError(f"Tool not found: {tool_name}")
        
        if not skill.is_tool:
            raise ValueError(f"Skill '{tool_name}' is not a tool")
        
        self.logger.info(f"Invoking tool: {tool_name} with args: {kwargs}")
        
        try:
            result = skill.invoke(context, **kwargs)
            self.logger.info(f"Tool {tool_name} completed successfully")
            return result
        except Exception as e:
            self.logger.error(f"Tool {tool_name} failed: {e}")
            return {"error": str(e)}
    
    def get_tools_description(self, context: SkillContext = None) -> str:
        """
        Get text description of available Tools (for System Prompt)
        
        Args:
            context: Execution context (optional)
            
        Returns:
            Tools description text
        """
        tools = self.get_available_tools(context)
        if not tools:
            return "No tools available."
        
        lines = ["## Available Tools\n"]
        for skill in tools:
            schema = skill.get_tool_schema()
            if schema:
                lines.append(f"### {schema.name}")
                lines.append(f"{schema.description}\n")
                if schema.parameters.get("properties"):
                    lines.append("**Parameters:**")
                    for param_name, param_info in schema.parameters["properties"].items():
                        param_desc = param_info.get("description", "")
                        param_type = param_info.get("type", "any")
                        required = param_name in schema.parameters.get("required", [])
                        req_mark = " (required)" if required else ""
                        lines.append(f"- `{param_name}` ({param_type}){req_mark}: {param_desc}")
                lines.append("")
        
        return "\n".join(lines)
