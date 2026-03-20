#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Builtin Skills Module

Design principles (fuzzing scenario):
1. PRE_ANALYSIS phase:
   - output_format: Output format specification (technical spec, not protocol knowledge)
   - byte_analysis: Data-driven byte-level statistical analysis
2. POST_ANALYSIS phase:
   - protocol_validation: Comparison evaluation against ground truth
   - field_validation: Format compliance check
   - industrial_validation: Industrial protocol feature check
   - result_refiner: Fix common format issues

This allows:
- True blind analysis on unknown protocols
- Validate tool effectiveness with known protocols (analysis result vs ground truth)
"""

# Auto-import all builtin skills
from . import (
    output_format,        # Output format specification
    byte_analysis,        # Byte-level statistical analysis (including region analysis, boundary search)
    field_validation,     # Format validation
    tlv_detection,        # TLV structure detection
    endianness_detection, # Byte order detection
)

# Export format spec functions (for protocol_analyzer use)
from .output_format import get_output_format_prompt, get_quality_constraints_prompt, get_supported_types

# Export metadata class for cross-module use
from .byte_analysis import ProtocolMetadata, MessageAnalyzer
