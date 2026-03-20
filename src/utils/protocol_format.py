"""
Protocol Format Specification Module

Compatibility layer: imports format definitions from skills.builtin.output_format.
This file is kept for compatibility with existing code.
"""

# Import from skill (source of truth)
try:
    from skills.builtin.output_format import (
        SUPPORTED_TYPES,
        get_output_format_prompt,
        get_quality_constraints_prompt,
        get_supported_types,
    )
except ImportError:
    # Fallback definitions (when skills not available)
    SUPPORTED_TYPES = [
        "uint8", "uint16_be", "uint16_le", "uint32_be", "uint32_le",
        "uint64_be", "uint64_le", "timestamp_64", "bytes",
    ]
    
    def get_output_format_prompt() -> str:
        return "# Output format not available"
    
    def get_quality_constraints_prompt() -> str:
        return "# Quality constraints not available"
    
    def get_supported_types():
        return SUPPORTED_TYPES.copy()

# Compatibility exports
BOUNDARY_TYPES = ["static", "dynamic"]

# Explicit exports
__all__ = [
    "SUPPORTED_TYPES",
    "BOUNDARY_TYPES",
    "get_output_format_prompt",
    "get_quality_constraints_prompt",
    "get_supported_types",
    "get_full_format_specification",
]


def get_full_format_specification() -> str:
    """Get complete format specification (for prompts)"""
    return f"{get_output_format_prompt()}\n\n{get_quality_constraints_prompt()}"
