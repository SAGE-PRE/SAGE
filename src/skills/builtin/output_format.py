#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Output Format Specification Skill (Tool Mode)

Provides get_output_format Tool for LLM to query format specification when ready to output results.
Includes:
- JSON structure definition
- Supported data types
- VALUE_RULE syntax (@/$ references)
- Quality constraints
"""

from typing import Any, Dict, List

from ..base import Skill, SkillContext, SkillPhase, SkillRegistry, SkillResult, ToolSchema


# Supported data types
SUPPORTED_TYPES = [
    "uint8", "uint16_be", "uint16_le", "uint32_be", "uint32_le",
    "uint64_be", "uint64_le", "int8", "int16_be", "int16_le",
    "int32_be", "int32_le", "float_be", "float_le", "double_be",
    "double_le", "timestamp_64", "bytes",
]


def get_output_format_prompt() -> str:
    """Get output format specification prompt (full version)"""
    types_str = ", ".join(f"`{t}`" for t in SUPPORTED_TYPES)
    
    return f'''# Output Format Requirements

You MUST output a JSON object with the following structure:

```json
{{
  "boundary_type": "static|dynamic",
  "fields": [
    {{
      "name": "field_name",
      "type": "data_type",
      "offset": "VALUE_RULE",
      "size": "VALUE_RULE"
    }}
  ]
}}
```

### Field Specification

**Required Keys:**
- `boundary_type` (string): "static" (fixed-length) or "dynamic" (variable-length)
- `fields` (array): List of field definitions

**Field Object:**
- `name` (string): Unique field name (lowercase with underscores)
- `type` (string): One of: {types_str}
- `offset` (int or string): See VALUE_RULE below
- `size` (int or string): See VALUE_RULE below

### VALUE_RULE

**1. `offset` (Position):**
- **Static:** Use **Integer** if fixed position (e.g., `0`, `4`, `12`)
- **Dynamic:** Use **String Formula** if position depends on previous fields:
  - End of previous field: `"$prev_field#"` (e.g., `"$header#"`)
  - Start of previous field: `"$prev_field"` (e.g., `"$header"`)
  - Expression: `"8 + @length"` (e.g., position after fixed header plus dynamic length)

**2. `size` (Length):**
- **Static:** Use **Integer** if constant (e.g., `1`, `2`, `4`, `8`)
- **Dynamic:** Use **String Formula** if size varies:
  - Reference to length field value: `"@length_field"` (e.g., `"@payload_len"`)
  - Expression: `"@total_length - 8"` (e.g., total minus header)
  - Calculated from length field: `"@length - 2"` (length field value minus header bytes)

**3. Special References:**
- `@total_length`: **Built-in variable** - total length of current message in bytes
- `@field_name`: Value of a previously defined field (for size calculations)
- `$field_name`: Start offset of a previously defined field
- `$field_name#`: End offset of a previously defined field (offset + size)
- **IMPORTANT:** Fields must be defined BEFORE being referenced. Use `@total_length` (NOT `@total_len`) for message length.

**IMPORTANT:** Do NOT use `"remaining"` keyword. Always use explicit expressions like `"@total_length - 8"`.

### boundary_type Selection

- **"static"**: All messages have the same length, all fields are fixed-size
- **"dynamic"**: Messages have varying lengths OR contain length-dependent fields
'''


def get_quality_constraints_prompt() -> str:
    """Get quality constraints prompt"""
    return '''# Quality Constraints

1. **No Hallucination**: Re-evaluate each field independently based on actual byte patterns
2. **Granularity**: Separate distinct fields (checksums, timestamps, flags) - do not merge
3. **Semantic Consistency**: Length/count fields must be integer types (uint8/16/32), not bytes
4. **No -1 Sizes**: Use formulas like `"@total_length - 8"` or `"@length - 2"`
5. **Minimum 5 Header Fields**: Break down the header into distinct components
6. **No "remaining" keyword**: Always use explicit length expressions
7. **Use @total_length**: For message length, always use `@total_length` (NOT `@total_len` or other variants)
'''


@SkillRegistry.register
class OutputFormatSkill(Skill):
    """
    Output Format Specification Skill (Tool Mode)
    
    Provides get_output_format Tool for LLM to query format specification when preparing output.
    """
    
    name = "output_format"
    description = "Provides output format specification on demand"
    version = "2.0.0"
    phases = [SkillPhase.PRE_ANALYSIS]
    priority = 5
    is_tool = True  # Enable Tool mode
    
    def get_tool_schema(self) -> ToolSchema:
        """Return Tool call schema"""
        return ToolSchema(
            name="get_output_format",
            description="""Get output format specification for protocol analysis results.

[When to Call This Tool]
Call this tool before outputting final JSON result after completing protocol analysis to get:
- JSON structure requirements
- List of supported data types
- VALUE_RULE syntax for offset/size
- Quality constraints and notes

[When Not Needed]
- Still in data analysis phase
- Already know the output format (called before)""",
            parameters={
                "type": "object",
                "properties": {
                    "include_examples": {
                        "type": "boolean",
                        "description": "Whether to include examples, default false",
                        "default": False
                    },
                    "section": {
                        "type": "string",
                        "description": "Get specific section only: all (everything), types (data types), value_rule (reference syntax), constraints (quality constraints)",
                        "enum": ["all", "types", "value_rule", "constraints"],
                        "default": "all"
                    }
                },
                "required": []
            }
        )
    
    def invoke(self, context: SkillContext, **kwargs) -> Dict[str, Any]:
        """Tool invocation entry point"""
        include_examples = kwargs.get("include_examples", False)
        section = kwargs.get("section", "all")
        
        result = {}
        
        if section in ["all", "types"]:
            result["supported_types"] = SUPPORTED_TYPES
        
        if section in ["all", "value_rule"]:
            result["value_rule"] = {
                "offset": {
                    "static": "Use integer for fixed position (e.g., 0, 4, 12)",
                    "dynamic": "Use string formula: \"$prev_field#\" (end of field), \"8 + @length\" (expression)"
                },
                "size": {
                    "static": "Use integer for fixed size (e.g., 1, 2, 4, 8)",
                    "dynamic": "Use string formula: \"@length_field\", \"@total_length - 8\""
                },
                "special_references": {
                    "@total_length": "Built-in: total message length in bytes",
                    "@field_name": "Value of a previously defined field",
                    "$field_name": "Start offset of a previously defined field",
                    "$field_name#": "End offset (offset + size) of a previously defined field"
                },
                "important": [
                    "Fields must be defined BEFORE being referenced",
                    "Use @total_length, NOT @total_len",
                    "Do NOT use 'remaining' keyword"
                ]
            }
        
        if section in ["all", "constraints"]:
            result["quality_constraints"] = [
                "No hallucination - base each field on actual byte patterns",
                "Fine granularity - separate distinct fields (checksums, timestamps, flags)",
                "Length/count fields must be integer types (uint8/16/32), not bytes",
                "No -1 sizes - use formulas like \"@total_length - 8\"",
                "Minimum 5 header fields - break down into distinct components",
                "No 'remaining' keyword - use explicit length expressions"
            ]
        
        if section == "all":
            result["json_structure"] = {
                "boundary_type": "static | dynamic",
                "fields": [
                    {
                        "name": "field_name (lowercase_with_underscores)",
                        "type": "one of supported_types",
                        "offset": "integer or VALUE_RULE string",
                        "size": "integer or VALUE_RULE string"
                    }
                ]
            }
            result["boundary_type_selection"] = {
                "static": "All messages same length, all fields fixed-size",
                "dynamic": "Messages vary in length OR contain length-dependent fields"
            }
        
        if include_examples:
            result["examples"] = {
                "static_protocol": {
                    "boundary_type": "static",
                    "fields": [
                        {"name": "magic", "type": "uint16_be", "offset": 0, "size": 2},
                        {"name": "version", "type": "uint8", "offset": 2, "size": 1},
                        {"name": "flags", "type": "uint8", "offset": 3, "size": 1},
                        {"name": "data", "type": "bytes", "offset": 4, "size": 12},
                        {"name": "checksum", "type": "uint16_be", "offset": 16, "size": 2}
                    ]
                },
                "dynamic_protocol": {
                    "boundary_type": "dynamic",
                    "fields": [
                        {"name": "magic", "type": "uint16_be", "offset": 0, "size": 2},
                        {"name": "length", "type": "uint16_be", "offset": 2, "size": 2},
                        {"name": "msg_type", "type": "uint8", "offset": 4, "size": 1},
                        {"name": "payload", "type": "bytes", "offset": 5, "size": "@length - 3"},
                        {"name": "checksum", "type": "uint16_be", "offset": "$payload#", "size": 2}
                    ]
                }
            }
        
        return result
    
    def execute(self, context: SkillContext, phase: SkillPhase) -> SkillResult:
        """Phase-based execution - only sets metadata, doesn't inject prompt"""
        context.metadata["output_format"] = {"supported_types": SUPPORTED_TYPES}
        return SkillResult(success=True, modified=True, message="Output format metadata set")
    
    def get_prompt_enhancement(self, context: SkillContext) -> str:
        """No longer auto-injects prompt, changed to Tool on-demand query"""
        return ""


def get_supported_types() -> List[str]:
    """Get list of supported data types"""
    return SUPPORTED_TYPES.copy()
