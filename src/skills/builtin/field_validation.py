#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Field Validation Skill (Supports Tool Invocation)

Validates whether LLM analysis results conform to format specification.
- Phase mode: POST_ANALYSIS validation
- Tool mode: LLM can proactively call to validate intermediate results
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from ..base import Skill, SkillContext, SkillPhase, SkillRegistry, SkillResult, ToolSchema

# Import field boundary calculator
from utils.field_boundary import FieldBoundaryCalculator

# Import supported types from output_format or use from FieldBoundaryCalculator
try:
    from .output_format import SUPPORTED_TYPES
except ImportError:
    SUPPORTED_TYPES = FieldBoundaryCalculator.SUPPORTED_TYPES


@SkillRegistry.register
class FieldValidationSkill(Skill):
    """
    Field Validation Skill (Supports Tool Invocation)
    
    Phase mode: Validates LLM output in POST_ANALYSIS phase
    Tool mode: LLM can call validate_fields tool to verify intermediate results
    """
    
    name = "field_validation"
    description = "Validates protocol field definitions against format specification"
    version = "3.0.0"
    phases = [SkillPhase.POST_ANALYSIS, SkillPhase.VALIDATION]
    priority = 50
    is_tool = True  # Enable Tool mode
    
    # ========== Tool Interface ==========
    
    def get_tool_schema(self) -> ToolSchema:
        """Return Tool call schema"""
        return ToolSchema(
            name="validate_fields",
            description="Validate protocol field definitions against specification, and parse ALL messages to verify completeness. Checks: 1) Format specification (types, naming, etc.) 2) Can it fully parse ALL messages (no gaps, no omissions). Note: Validation uses all messages from context automatically.",
            parameters={
                "type": "object",
                "properties": {
                    "fields": {
                        "type": "array",
                        "description": "Array of field definitions to validate",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "type": {"type": "string"},
                                "offset": {"type": ["integer", "string"]},
                                "size": {"type": ["integer", "string"]}
                            }
                        }
                    },
                    "boundary_type": {
                        "type": "string",
                        "description": "Boundary type: static or dynamic",
                        "enum": ["static", "dynamic"]
                    }
                },
                "required": ["fields"]
            }
        )
    
    def invoke(self, context: SkillContext, **kwargs) -> Dict[str, Any]:
        """Tool invocation entry point"""
        fields = kwargs.get("fields", [])
        boundary_type = kwargs.get("boundary_type")
        
        if not fields:
            return {"valid": False, "errors": ["No fields provided"]}
        
        # Construct temporary result object
        result = {"fields": fields}
        if boundary_type:
            result["boundary_type"] = boundary_type
        
        # Validate structure
        errors = []
        warnings = []
        
        if boundary_type:
            structure_errors = self._validate_structure(result)
            errors.extend(structure_errors)
        
        # Validate field format
        field_errors, field_warnings = self._validate_fields(fields)
        errors.extend(field_errors)
        warnings.extend(field_warnings)
        
        # Parse validation: use ALL messages from context
        parse_results = []
        all_msgs = []
        
        if context.messages:
            for msg in context.messages:
                if hasattr(msg, 'data'):
                    all_msgs.append(msg.data.hex())
                elif isinstance(msg, bytes):
                    all_msgs.append(msg.hex())
        
        if all_msgs:
            parse_results = self._validate_parsing(fields, all_msgs)
            
            # Count failures by type for summary
            gap_failures = 0
            overlap_failures = 0
            other_failures = 0
            
            for pr in parse_results:
                if not pr["success"]:
                    # Gaps and overlaps are now errors (not warnings)
                    if pr.get("gaps"):
                        gap_failures += 1
                    if pr.get("overlaps"):
                        overlap_failures += 1
                    if not pr.get("gaps") and not pr.get("overlaps"):
                        other_failures += 1
                    # Add first few failures as errors
                    if len(errors) < 5:
                        errors.append(f"Parse error (msg {pr['index']}): {pr.get('error', 'unknown')}")
            
            # Add summary if many failures
            total_failures = gap_failures + overlap_failures + other_failures
            if total_failures > 5:
                summary_parts = []
                if gap_failures > 0:
                    summary_parts.append(f"{gap_failures} with gaps")
                if overlap_failures > 0:
                    summary_parts.append(f"{overlap_failures} with overlaps")
                if other_failures > 0:
                    summary_parts.append(f"{other_failures} other errors")
                errors.append(f"... and {total_failures - 5} more failures: {', '.join(summary_parts)}")
        
        # Endianness consistency check
        endianness_issues = []
        if all_msgs:
            endianness_issues = self._check_endianness_consistency(fields, all_msgs, context)
            for issue in endianness_issues:
                warnings.append(issue)
        
        # Payload structure detection - check if large bytes fields have internal structure
        payload_analysis_hints = []
        if all_msgs and parse_results:
            payload_analysis_hints = self._detect_payload_structure(fields, all_msgs, parse_results)
            for hint in payload_analysis_hints:
                warnings.append(hint)
        
        # Check if payload analysis is required based on:
        # 1. Field warnings about large bytes fields
        # 2. Payload structure detection hints
        payload_required = False
        
        # Check field_warnings for MUST analyze hints
        for w in field_warnings:
            if 'MUST analyze' in w or 'internal structure' in w.lower():
                payload_required = True
                break
        
        # Also check payload_analysis_hints
        if payload_analysis_hints:
            payload_required = True
        
        # Calculate parse success rate
        parse_success_count = sum(1 for pr in parse_results if pr["success"])
        parse_success_rate = parse_success_count / len(parse_results) if parse_results else 0
        
        response = {
            "valid": len(errors) == 0,
            "total_messages": len(all_msgs),
            "parse_success_count": parse_success_count,
            "parse_success_rate": round(parse_success_rate * 100, 1),
            "error_count": len(errors),
            "warning_count": len(warnings),
            "errors": errors,
            "warnings": warnings,
            "parse_results": parse_results[:5] if parse_results else [],
            "supported_types": SUPPORTED_TYPES,
            "payload_analysis_required": payload_required
        }
        
        # Add endianness recommendation if issues found
        if endianness_issues:
            response["endianness_recommendation"] = (
                "Some fields may have incorrect byte order. "
                "Consider calling detect_endianness() or analyze_bytes(basic) to determine protocol byte order."
            )
        
        # Add payload analysis recommendation if structure detected
        if payload_required:
            response["payload_analysis_recommendation"] = (
                "Large bytes field(s) detected with potential internal structure. "
                "You MUST call analyze_bytes(mode=pattern) to detect field boundaries before outputting."
            )
        
        return response
    
    # ========== Phase-based Execution ==========
    
    def execute(self, context: SkillContext, phase: SkillPhase) -> SkillResult:
        """Execute validation"""
        result = context.analysis_result
        if not result or "error" in result:
            return SkillResult(
                success=True,
                modified=False,
                message="No valid result to validate"
            )
        
        errors = []
        warnings = []
        
        # Validate structure
        structure_errors = self._validate_structure(result)
        errors.extend(structure_errors)
        
        # Validate fields
        if "fields" in result:
            field_errors, field_warnings = self._validate_fields(result["fields"])
            errors.extend(field_errors)
            warnings.extend(field_warnings)
        
        # Save validation result (merge, not overwrite, to preserve evaluation data)
        existing_validation = context.metadata.get("validation", {})
        validation_result = {
            **existing_validation,
            "format_valid": len(errors) == 0,
            "format_errors": errors,
            "format_warnings": warnings,
            "valid": existing_validation.get("valid", True) and len(errors) == 0,
            "errors": existing_validation.get("errors", []) + errors,
            "warnings": existing_validation.get("warnings", []) + warnings,
        }
        
        context.metadata["validation"] = validation_result
        
        if errors:
            return SkillResult(
                success=True,
                modified=True,
                message=f"Format validation: {len(errors)} errors, {len(warnings)} warnings",
                data=validation_result,
                errors=errors
            )
        
        return SkillResult(
            success=True,
            modified=True,
            message=f"Format validation passed ({len(warnings)} warnings)",
            data=validation_result
        )
    
    def _validate_structure(self, result: Dict) -> List[str]:
        """Validate result structure"""
        errors = []
        
        if "boundary_type" not in result:
            errors.append("Missing: boundary_type")
        elif result["boundary_type"] not in ["static", "dynamic"]:
            errors.append(f"Invalid boundary_type: {result['boundary_type']}")
        
        if "fields" not in result:
            errors.append("Missing: fields")
        elif not isinstance(result["fields"], list):
            errors.append("'fields' must be an array")
        elif len(result["fields"]) == 0:
            errors.append("'fields' cannot be empty")
        
        return errors
    
    def _validate_fields(self, fields: List[Dict]) -> Tuple[List[str], List[str]]:
        """Validate field definitions"""
        errors = []
        warnings = []
        
        seen_names = set()
        seen_offsets = set()
        
        valid_types = set(SUPPORTED_TYPES)
        
        # Track fields in header region (first 16 bytes) for special checks
        header_region_bytes_fields = []
        
        for i, field in enumerate(fields):
            fid = f"[{i}]"
            
            # name
            if "name" not in field:
                errors.append(f"{fid}: Missing 'name'")
            else:
                name = field["name"]
                if name in seen_names:
                    errors.append(f"{fid}: Duplicate name '{name}'")
                seen_names.add(name)
                
                if not name.replace("_", "").isalnum():
                    warnings.append(f"{fid}: Name '{name}' contains special chars")
                elif not name.islower():
                    warnings.append(f"{fid}: Name '{name}' should be lowercase")
            
            # type
            if "type" not in field:
                errors.append(f"{fid}: Missing 'type'")
            elif field["type"] not in valid_types:
                errors.append(f"{fid}: Unknown type '{field['type']}'")
            
            # offset
            if "offset" not in field:
                errors.append(f"{fid}: Missing 'offset'")
            else:
                offset = field["offset"]
                if isinstance(offset, int):
                    if offset < 0:
                        errors.append(f"{fid}: Negative offset: {offset}")
                    elif offset in seen_offsets:
                        warnings.append(f"{fid}: Duplicate offset {offset}")
                    seen_offsets.add(offset)
                elif isinstance(offset, str):
                    if not self._validate_expression(offset, seen_names):
                        warnings.append(f"{fid}: Unverified expression '{offset}'")
            
                # size
                if "size" not in field:
                    errors.append(f"{fid}: Missing 'size'")
                else:
                    size = field["size"]
                    field_type = field.get("type", "")
                    field_name = field.get("name", f"field_{i}")
                    field_offset = field.get("offset", 0)
                    
                    if isinstance(size, int):
                        if size <= 0:
                            errors.append(f"{fid}: Invalid size: {size}")
                        elif size > 256:
                            warnings.append(f"{fid}: Large size: {size}")
                        
                        # ========== Header region bytes field check ==========
                        # If a bytes field starts in the first 16 bytes and is >= 8 bytes,
                        # it might need further analysis (but NOT for typical magic/signature fields)
                        # Magic/signature fields (4-8 bytes at offset 0) are common and valid
                        if field_type == "bytes" and isinstance(field_offset, int):
                            # Only flag if:
                            # 1. Size >= 8 bytes (larger than typical magic)
                            # 2. NOT at offset 0 (offset 0 bytes are almost always magic)
                            # 3. Field name doesn't suggest magic/signature
                            is_likely_magic = (
                                field_offset == 0 or 
                                size <= 8 or
                                "magic" in field_name.lower() or
                                "signature" in field_name.lower() or
                                "protocol" in field_name.lower()
                            )
                            if field_offset < 16 and size >= 8 and not is_likely_magic:
                                header_region_bytes_fields.append({
                                    "name": field_name,
                                    "offset": field_offset,
                                    "size": size,
                                    "end": field_offset + size
                                })
                        
                        # Check for large bytes fields that MUST be analyzed further
                        # Threshold: 16 bytes for mandatory analysis
                        if size > 16 and field_type == "bytes":
                            offset_str = str(field_offset) if isinstance(field_offset, int) else field_offset
                            warnings.append(
                                f"{fid}: Field '{field_name}' is a large bytes field ({size} bytes) - "
                                f"MUST analyze internal structure. "
                                f"Call: analyze_bytes(mode=pattern, start={offset_str}, end={offset_str}+{size})"
                            )
                        elif size > 8 and field_type == "bytes":
                            # Smaller bytes fields - suggest but don't require
                            offset_str = str(field_offset) if isinstance(field_offset, int) else field_offset
                            warnings.append(
                                f"{fid}: Field '{field_name}' is a bytes field ({size} bytes). "
                                f"Consider analyzing its internal structure with "
                                f"analyze_bytes(mode=pattern, start={offset_str}, end={offset_str}+{size})"
                            )
                    elif isinstance(size, str):
                        if "remaining" in size.lower():
                            errors.append(f"{fid}: 'remaining' not allowed")
                        elif size == "-1":
                            errors.append(f"{fid}: '-1' not allowed")
                        # Check for dynamic bytes fields (likely payload) - MUST be analyzed
                        elif field_type == "bytes" and ("total_length" in size or "length" in size):
                            offset_str = str(field_offset) if isinstance(field_offset, int) else field_offset
                            warnings.append(
                                f"{fid}: Field '{field_name}' is a variable-length payload - "
                                f"MUST analyze internal structure. "
                                f"Call: analyze_bytes(mode=pattern, start={offset_str}, end=-1)"
                            )
        
        # ========== Header region analysis requirement ==========
        # If there are large bytes fields in the first 16 bytes (excluding typical magic), suggest analysis
        if header_region_bytes_fields:
            for hf in header_region_bytes_fields:
                warnings.append(
                    f"Field '{hf['name']}' is a {hf['size']}-byte 'bytes' field "
                    f"starting at offset {hf['offset']} (within header region 0-16). "
                    f"Consider analyzing internal structure with "
                    f"analyze_bytes(mode=pattern, start={hf['offset']}, end={hf['end']})"
                )
        
        if len(fields) < 3:
            warnings.append(f"Only {len(fields)} fields, consider finer granularity")
        
        return errors, warnings
    
    def _validate_expression(self, expr: str, defined_names: set) -> bool:
        """Validate expression references"""
        refs = re.findall(r'[@$](\w+)', expr)
        for ref in refs:
            if ref.rstrip('#') not in defined_names:
                return False
        return True
    
    def _validate_parsing(self, fields: List[Dict], test_messages: List[str]) -> List[Dict[str, Any]]:
        """
        Try to parse test messages using field definitions to verify completeness
        
        Uses FieldBoundaryCalculator for consistent parsing logic.
        
        Returns:
            List of parse results, each element contains:
            - index: Message index
            - success: Whether parsing succeeded
            - error: Error message (if failed)
            - coverage: Coverage percentage
            - gaps: Uncovered byte ranges (causes failure)
            - overlaps: Overlapping byte ranges (causes failure)
            - parsed_fields: Parsed field values
        """
        # Use the common FieldBoundaryCalculator for parsing
        return FieldBoundaryCalculator.validate_fields_on_messages(fields, test_messages)
    
    def _check_endianness_consistency(self, fields: List[Dict], test_messages: List[str],
                                       context: SkillContext) -> List[str]:
        """
        Check if field byte orders produce reasonable values.
        
        Detects potential endianness issues:
        - BE type giving very large values while LE would give small values
        - LE type giving very large values while BE would give small values
        
        Returns:
            List of warning messages for fields with potential endianness issues
        """
        issues = []
        
        # Parse messages
        try:
            msg_bytes_list = [bytes.fromhex(m.replace(" ", "").replace("0x", "")) 
                            for m in test_messages[:5]]
        except ValueError:
            return []
        
        if not msg_bytes_list:
            return []
        
        min_len = min(len(m) for m in msg_bytes_list)
        
        # Check each field with integer types
        for field in fields:
            field_type = field.get("type", "")
            field_name = field.get("name", "unknown")
            offset = field.get("offset")
            size = field.get("size")
            
            # Only check fixed-offset integer fields
            if not isinstance(offset, int) or not isinstance(size, int):
                continue
            
            # Skip if out of range
            if offset + size > min_len:
                continue
            
            # Check 16-bit fields
            if field_type in ("uint16_be", "uint16_le") and size == 2:
                current_values = []
                alternate_values = []
                
                for msg in msg_bytes_list:
                    if field_type == "uint16_be":
                        current_values.append(int.from_bytes(msg[offset:offset+2], 'big'))
                        alternate_values.append(int.from_bytes(msg[offset:offset+2], 'little'))
                    else:
                        current_values.append(int.from_bytes(msg[offset:offset+2], 'little'))
                        alternate_values.append(int.from_bytes(msg[offset:offset+2], 'big'))
                
                current_max = max(current_values)
                alternate_max = max(alternate_values)
                
                # Flag if current type gives large values but alternate would give small values
                if current_max > 5000 and alternate_max < 500:
                    alt_type = "uint16_le" if field_type == "uint16_be" else "uint16_be"
                    issues.append(
                        f"Field '{field_name}': {field_type} gives large values (max={current_max}), "
                        f"consider {alt_type} (max={alternate_max})"
                    )
            
            # Check 32-bit fields
            elif field_type in ("uint32_be", "uint32_le") and size == 4:
                current_values = []
                alternate_values = []
                
                for msg in msg_bytes_list:
                    if field_type == "uint32_be":
                        current_values.append(int.from_bytes(msg[offset:offset+4], 'big'))
                        alternate_values.append(int.from_bytes(msg[offset:offset+4], 'little'))
                    else:
                        current_values.append(int.from_bytes(msg[offset:offset+4], 'little'))
                        alternate_values.append(int.from_bytes(msg[offset:offset+4], 'big'))
                
                current_max = max(current_values)
                alternate_max = max(alternate_values)
                
                # Flag if current type gives very large values but alternate would be reasonable
                if current_max > 10000000 and alternate_max < 100000:
                    alt_type = "uint32_le" if field_type == "uint32_be" else "uint32_be"
                    issues.append(
                        f"Field '{field_name}': {field_type} gives very large values (max={current_max}), "
                        f"consider {alt_type} (max={alternate_max})"
                    )
        
        return issues[:5]  # Limit to 5 issues
    
    def _detect_payload_structure(self, fields: List[Dict], test_messages: List[str],
                                   parse_results: List[Dict]) -> List[str]:
        """
        Detect if large bytes fields have internal structure that should be analyzed.
        
        Examines payload regions for:
        1. Constant byte patterns (magic bytes, version numbers)
        2. Printable ASCII strings
        3. Repeating patterns suggesting sub-structures
        4. Potential length fields
        
        Returns:
            List of warning messages with specific analysis suggestions
        """
        hints = []
        
        # Find bytes fields that might be payloads
        payload_fields = []
        for field in fields:
            field_type = field.get("type", "")
            field_size = field.get("size")
            field_name = field.get("name", "unknown")
            field_offset = field.get("offset")
            
            # Check for large static bytes fields or dynamic bytes fields
            if field_type == "bytes":
                if isinstance(field_size, int) and field_size > 16:
                    payload_fields.append({
                        "name": field_name,
                        "offset": field_offset,
                        "size": field_size,
                        "is_dynamic": False
                    })
                elif isinstance(field_size, str) and ("total_length" in field_size or "length" in field_size):
                    payload_fields.append({
                        "name": field_name,
                        "offset": field_offset,
                        "size": field_size,
                        "is_dynamic": True
                    })
        
        if not payload_fields:
            return []
        
        # Parse messages
        try:
            msg_bytes_list = [bytes.fromhex(m.replace(" ", "").replace("0x", "")) 
                            for m in test_messages[:10]]
        except ValueError:
            return []
        
        if not msg_bytes_list:
            return []
        
        # Analyze each payload field
        for pf in payload_fields:
            field_name = pf["name"]
            field_offset = pf["offset"]
            
            # Skip if offset is dynamic (can't easily analyze)
            if not isinstance(field_offset, int):
                hints.append(
                    f"Field '{field_name}' has dynamic offset - "
                    f"MUST call analyze_bytes(mode=region, start={field_offset}, end=-1) to examine structure"
                )
                continue
            
            # Collect payload bytes from multiple messages
            payload_samples = []
            for msg in msg_bytes_list:
                if pf["is_dynamic"]:
                    # For dynamic size, take from offset to end
                    if field_offset < len(msg):
                        payload_samples.append(msg[field_offset:])
                else:
                    # For static size
                    end = field_offset + pf["size"]
                    if end <= len(msg):
                        payload_samples.append(msg[field_offset:end])
            
            if not payload_samples:
                continue
            
            # Check for structure indicators
            structure_indicators = []
            
            # 1. Check for constant bytes at the start (magic bytes)
            if len(payload_samples) >= 2:
                min_len = min(len(p) for p in payload_samples)
                constant_prefix_len = 0
                for i in range(min(min_len, 8)):  # Check first 8 bytes
                    byte_values = [p[i] for p in payload_samples if i < len(p)]
                    if len(set(byte_values)) == 1:
                        constant_prefix_len += 1
                    else:
                        break
                
                if constant_prefix_len >= 2:
                    prefix_hex = payload_samples[0][:constant_prefix_len].hex()
                    structure_indicators.append(f"constant prefix '{prefix_hex}'")
            
            # 2. Check for printable ASCII strings
            for sample in payload_samples[:3]:
                ascii_runs = []
                current_run = []
                for b in sample:
                    if 0x20 <= b <= 0x7e:  # Printable ASCII
                        current_run.append(chr(b))
                    else:
                        if len(current_run) >= 4:
                            ascii_runs.append("".join(current_run))
                        current_run = []
                if len(current_run) >= 4:
                    ascii_runs.append("".join(current_run))
                
                if ascii_runs:
                    sample_str = ascii_runs[0][:20]  # First 20 chars of first run
                    structure_indicators.append(f"ASCII string '{sample_str}...'")
                    break
            
            # 3. Check for potential length field at start
            if len(payload_samples) >= 2:
                for sample in payload_samples:
                    if len(sample) >= 4:
                        # Check if first 2 bytes could be length (little-endian)
                        potential_len_le = int.from_bytes(sample[:2], 'little')
                        potential_len_be = int.from_bytes(sample[:2], 'big')
                        
                        # Check if matches actual payload length
                        actual_len = len(sample) - 2  # Minus the length field itself
                        if abs(potential_len_le - actual_len) <= 4:
                            structure_indicators.append(f"potential length field (LE, value={potential_len_le})")
                            break
                        elif abs(potential_len_be - actual_len) <= 4:
                            structure_indicators.append(f"potential length field (BE, value={potential_len_be})")
                            break
            
            # Generate hint if structure detected
            if structure_indicators:
                indicators_str = ", ".join(structure_indicators[:3])
                end_expr = "-1" if pf["is_dynamic"] else f"{field_offset}+{pf['size']}"
                hints.append(
                    f"Field '{field_name}' has internal structure: {indicators_str}. "
                    f"MUST analyze with: analyze_bytes(mode=region, start={field_offset}, end={end_expr})"
                )
            elif pf["is_dynamic"] or (isinstance(pf["size"], int) and pf["size"] > 32):
                # Large field without obvious structure - still suggest analysis
                end_expr = "-1" if pf["is_dynamic"] else f"{field_offset}+{pf['size']}"
                hints.append(
                    f"Field '{field_name}' is large ({pf['size']} bytes) - "
                    f"should analyze with: analyze_bytes(mode=region, start={field_offset}, end={end_expr})"
                )
        
        return hints[:5]  # Limit to 5 hints
    
    def get_prompt_enhancement(self, context: SkillContext) -> str:
        """No prompt enhancement provided (handled by output_format skill)"""
        return ""


@SkillRegistry.register  
class ResultRefinerSkill(Skill):
    """Result Refiner Skill"""
    
    name = "result_refiner"
    description = "Refines and fixes common issues in analysis results"
    version = "1.0.0"
    phases = [SkillPhase.POST_ANALYSIS]
    priority = 60  # Execute after validation
    
    def execute(self, context: SkillContext, phase: SkillPhase) -> SkillResult:
        """Try to fix common issues"""
        result = context.analysis_result
        if not result or "error" in result:
            return SkillResult(success=True, modified=False)
        
        modified = False
        fixes = []
        
        # Fix common issues
        if "fields" in result:
            for field in result["fields"]:
                # Fix 'remaining' keyword
                if isinstance(field.get("size"), str) and "remaining" in field["size"].lower():
                    # Try to infer correct expression
                    if "@" in field["size"]:
                        # Keep original reference
                        pass
                    else:
                        field["size"] = "@total_length - header_size"
                        fixes.append(f"Fixed 'remaining' in {field.get('name', 'unknown')}")
                        modified = True
                
                # Fix -1 size
                if field.get("size") == -1 or field.get("size") == "-1":
                    field["size"] = "@payload_length"
                    fixes.append(f"Fixed -1 size in {field.get('name', 'unknown')}")
                    modified = True
                
                # Normalize names
                name = field.get("name", "")
                if name and not name.islower():
                    field["name"] = name.lower().replace(" ", "_").replace("-", "_")
                    if field["name"] != name:
                        fixes.append(f"Normalized name: {name} -> {field['name']}")
                        modified = True
        
        if modified:
            context.analysis_result = result
        
        return SkillResult(
            success=True,
            modified=modified,
            message=f"Applied {len(fixes)} fixes" if fixes else "No fixes needed",
            data={"fixes": fixes}
        )
