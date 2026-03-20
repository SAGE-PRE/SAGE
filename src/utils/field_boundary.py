#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Field Boundary Calculation Module

Common module for calculating field boundaries from field definitions.
Used by both field_validation.py and evaluate_boundaries.py to ensure consistent behavior.
"""

import re
from typing import Any, Dict, List, Optional, Set, Tuple


class FieldBoundaryCalculator:
    """Field Boundary Calculator
    
    Provides unified field parsing and boundary calculation logic.
    """
    
    # Supported field types
    SUPPORTED_TYPES = [
        "uint8", "uint16_be", "uint16_le", "uint32_be", "uint32_le",
        "uint64_be", "uint64_le", "timestamp_64", "bytes"
    ]
    
    @staticmethod
    def evaluate_expression(
        expr: Any,
        field_values: Dict[str, int],
        field_offsets: Dict[str, int],
        field_ends: Dict[str, int],
        packet_length: int
    ) -> int:
        """Evaluate offset/size expression
        
        Supported reference syntax:
        - Integer: return directly
        - @total_length / @packet_length / @message_length: Packet total length
        - @field_name: Field value (for size calculation)
        - $field_name: Field start offset
        - $field_name#: Field end offset (offset + size)
        - Arithmetic expressions: e.g., "@length - 2", "12 + @param_len"
        
        Args:
            expr: Expression (int or str)
            field_values: Dict of field_name -> parsed value
            field_offsets: Dict of field_name -> start offset
            field_ends: Dict of field_name -> end offset
            packet_length: Total packet length in bytes
        
        Returns:
            Evaluated integer value
        
        Raises:
            ValueError: When expression contains unresolved variable references or invalid syntax
        """
        if isinstance(expr, int):
            return expr
        
        if not isinstance(expr, str):
            raise ValueError(f"Invalid expression type: {type(expr)}")
        
        expr = expr.strip()
        
        # Prohibit "remaining" keyword
        if expr.lower() == "remaining" or "-1" == expr:
            raise ValueError(
                f"'{expr}' is not supported. Use explicit expression like '@total_length - @header_size' instead."
            )
        
        # Replace built-in variables (packet length aliases)
        length_aliases = ['@total_length', '@packet_length', '@message_length', '@msg_len', '@total_len', '@message_len']
        for alias in length_aliases:
            expr = expr.replace(alias, str(packet_length))
        
        # Replace $field_name# references (field end position) - must process # suffixed first
        for name, end_offset in field_ends.items():
            expr = expr.replace(f"${name}#", str(end_offset))
        
        # Replace $field_name references (field start position)
        for name, start_offset in field_offsets.items():
            expr = expr.replace(f"${name}", str(start_offset))
        
        # Replace @field_name references (field value)
        for name, value in field_values.items():
            if isinstance(value, int):
                expr = expr.replace(f"@{name}", str(value))
        
        # Check for unresolved variable references
        unresolved = re.findall(r'[@$][\w]+#?', expr)
        if unresolved:
            available_fields = list(field_values.keys())
            raise ValueError(
                f"Unresolved variable(s): {unresolved}. "
                f"Available built-in: @total_length/@packet_length/@message_length. "
                f"Defined fields: {available_fields}. "
                f"Hint: Use '@field' for value, '$field' for offset, '$field#' for end offset."
            )
        
        # Convert C-style ternary expression to Python syntax
        # (cond) ? a : b  ->  (a if cond else b)
        ternary_pattern = r'\(([^)]+)\)\s*\?\s*([^:]+)\s*:\s*(\S+)'
        ternary_match = re.search(ternary_pattern, expr)
        if ternary_match:
            cond, true_val, false_val = ternary_match.groups()
            # Convert || and && to Python syntax
            cond = cond.replace('||', ' or ').replace('&&', ' and ')
            python_ternary = f"({true_val.strip()} if ({cond.strip()}) else {false_val.strip()})"
            expr = re.sub(ternary_pattern, python_ternary, expr)
        
        # Evaluate expression safely
        try:
            # Safe eval environment
            safe_dict = {
                "__builtins__": {},
                "abs": abs, "min": min, "max": max,
                "int": int, "float": float
            }
            # Check for valid characters
            if not re.match(r'^[\d\s\+\-\*\/\(\)\<\>\=\!andorift\s]+$', expr):
                # If there are other characters, try direct eval with safe dict
                pass
            result = eval(expr, safe_dict, {})
            return int(result)
        except Exception as e:
            raise ValueError(f"Failed to evaluate expression '{expr}': {e}")
    
    @staticmethod
    def extract_field_value(data: bytes, field_type: str) -> Any:
        """Extract field value from bytes
        
        Args:
            data: Raw bytes
            field_type: Field type string
        
        Returns:
            Parsed value (int for numeric types, hex string for bytes)
        """
        if not data:
            return None
        
        try:
            if field_type == "uint8":
                return data[0] if len(data) >= 1 else 0
            elif field_type == "uint16_be":
                return int.from_bytes(data[:2], 'big') if len(data) >= 2 else 0
            elif field_type == "uint16_le":
                return int.from_bytes(data[:2], 'little') if len(data) >= 2 else 0
            elif field_type == "uint32_be":
                return int.from_bytes(data[:4], 'big') if len(data) >= 4 else 0
            elif field_type == "uint32_le":
                return int.from_bytes(data[:4], 'little') if len(data) >= 4 else 0
            elif field_type == "uint64_be":
                return int.from_bytes(data[:8], 'big') if len(data) >= 8 else 0
            elif field_type == "uint64_le":
                return int.from_bytes(data[:8], 'little') if len(data) >= 8 else 0
            elif field_type == "bytes":
                return len(data)  # For bytes type, return length for size calculations
            else:
                return len(data)
        except Exception:
            return len(data) if data else 0
    
    @classmethod
    def parse_message_fields(
        cls,
        fields: List[Dict[str, Any]],
        packet_hex: str,
        strict_boundary_check: bool = True
    ) -> Dict[str, Any]:
        """Parse a message using field definitions
        
        Args:
            fields: List of field definitions, each with name, type, offset, size
            packet_hex: Hex string of the packet
            strict_boundary_check: If True, raises error when field exceeds packet boundary
        
        Returns:
            Dict containing:
            - success: bool
            - error: str (if failed)
            - packet_length: int
            - parsed_fields: Dict of field_name -> {offset, size, value, hex}
            - field_values: Dict of field_name -> value
            - field_offsets: Dict of field_name -> start offset
            - field_ends: Dict of field_name -> end offset
            - coverage_count: List[int] - coverage count per byte
            - boundaries: Set[int] - field boundary positions (excluding 0 and packet_length)
        """
        try:
            packet_bytes = bytes.fromhex(packet_hex.replace(" ", "").replace("0x", ""))
        except ValueError as e:
            return {
                "success": False,
                "error": f"Invalid hex: {e}",
                "packet_length": 0
            }
        
        packet_length = len(packet_bytes)
        
        # Track coverage count per byte (0=uncovered, 1=covered once, 2+=overlap)
        coverage_count = [0] * packet_length
        
        # Context for expression evaluation
        field_values = {}      # field_name -> parsed value
        field_offsets = {}     # field_name -> start offset
        field_ends = {}        # field_name -> end offset
        
        parsed_fields = {}     # field_name -> {offset, size, value, hex}
        boundaries = set()     # Field boundaries (excluding 0 and packet_length)
        
        for field in fields:
            name = field.get("name", "unknown")
            field_type = field.get("type", "bytes")
            offset_expr = field.get("offset")
            size_expr = field.get("size")
            
            # Calculate offset
            try:
                offset = cls.evaluate_expression(
                    offset_expr, field_values, field_offsets, field_ends, packet_length
                )
            except Exception as e:
                return {
                    "success": False,
                    "error": f"Field '{name}': cannot eval offset '{offset_expr}': {e}",
                    "packet_length": packet_length,
                    "parsed_fields": parsed_fields
                }
            
            # Calculate size
            try:
                size = cls.evaluate_expression(
                    size_expr, field_values, field_offsets, field_ends, packet_length
                )
            except Exception as e:
                return {
                    "success": False,
                    "error": f"Field '{name}': cannot eval size '{size_expr}': {e}",
                    "packet_length": packet_length,
                    "parsed_fields": parsed_fields
                }
            
            # Validate offset range
            if offset < 0:
                return {
                    "success": False,
                    "error": f"Field '{name}': negative offset {offset}",
                    "packet_length": packet_length,
                    "parsed_fields": parsed_fields
                }
            
            if offset >= packet_length:
                return {
                    "success": False,
                    "error": f"Field '{name}': offset {offset} out of range [0, {packet_length})",
                    "packet_length": packet_length,
                    "parsed_fields": parsed_fields
                }
            
            # Calculate end offset
            end_offset = offset + size
            
            # Strict boundary check
            if strict_boundary_check and end_offset > packet_length:
                return {
                    "success": False,
                    "error": f"Field '{name}' extends beyond packet boundary: offset={offset}, size={size}, packet_length={packet_length}",
                    "packet_length": packet_length,
                    "parsed_fields": parsed_fields
                }
            
            # Mark covered range
            actual_end = min(end_offset, packet_length)
            for j in range(offset, actual_end):
                coverage_count[j] += 1
            
            # Add boundary (excluding packet_length)
            if end_offset < packet_length:
                boundaries.add(end_offset)
            
            # Extract field bytes and value
            field_bytes = packet_bytes[offset:actual_end]
            field_value = cls.extract_field_value(field_bytes, field_type)
            
            # Store field info
            field_values[name] = field_value
            field_offsets[name] = offset
            field_ends[name] = end_offset
            
            parsed_fields[name] = {
                "offset": offset,
                "size": size,
                "value": field_value,
                "hex": field_bytes.hex()
            }
        
        return {
            "success": True,
            "packet_length": packet_length,
            "parsed_fields": parsed_fields,
            "field_values": field_values,
            "field_offsets": field_offsets,
            "field_ends": field_ends,
            "coverage_count": coverage_count,
            "boundaries": boundaries
        }
    
    @classmethod
    def analyze_coverage(cls, coverage_count: List[int], packet_length: int) -> Dict[str, Any]:
        """Analyze coverage and detect gaps/overlaps
        
        Args:
            coverage_count: List of coverage count per byte
            packet_length: Total packet length
        
        Returns:
            Dict containing:
            - has_gaps: bool
            - has_overlaps: bool
            - gaps: List[str] - gap ranges as strings (e.g., "10-15")
            - overlaps: List[str] - overlap ranges as strings
            - coverage: float - coverage percentage
            - covered_bytes: int
        """
        # Detect gaps (uncovered bytes)
        gaps = []
        gap_start = None
        for j, count in enumerate(coverage_count):
            if count == 0 and gap_start is None:
                gap_start = j
            elif count > 0 and gap_start is not None:
                gaps.append(f"{gap_start}-{j-1}")
                gap_start = None
        if gap_start is not None:
            gaps.append(f"{gap_start}-{packet_length-1}")
        
        # Detect overlaps (bytes covered by multiple fields)
        overlaps = []
        overlap_start = None
        for j, count in enumerate(coverage_count):
            if count > 1 and overlap_start is None:
                overlap_start = j
            elif count <= 1 and overlap_start is not None:
                overlaps.append(f"{overlap_start}-{j-1}")
                overlap_start = None
        if overlap_start is not None:
            overlaps.append(f"{overlap_start}-{packet_length-1}")
        
        # Calculate coverage
        covered_bytes = sum(1 for c in coverage_count if c > 0)
        coverage = covered_bytes * 100 / packet_length if packet_length > 0 else 100
        
        return {
            "has_gaps": len(gaps) > 0,
            "has_overlaps": len(overlaps) > 0,
            "gaps": gaps,
            "overlaps": overlaps,
            "coverage": round(coverage, 1),
            "covered_bytes": covered_bytes
        }
    
    @classmethod
    def generate_boundaries_for_message(
        cls,
        fields: List[Dict[str, Any]],
        packet_hex: str
    ) -> Tuple[Set[int], int]:
        """Generate boundary set for a single packet
        
        This is the main entry point for boundary evaluation.
        
        Args:
            fields: Field definition list
            packet_hex: Packet hex string
        
        Returns:
            Tuple of (boundary position set, packet length)
            Boundary set excludes 0 and packet_length as inherent boundaries
        
        Raises:
            ValueError: When field definition has boundary errors
        """
        result = cls.parse_message_fields(fields, packet_hex, strict_boundary_check=True)
        
        if not result["success"]:
            raise ValueError(result["error"])
        
        return result["boundaries"], result["packet_length"]
    
    @classmethod
    def validate_fields_on_messages(
        cls,
        fields: List[Dict[str, Any]],
        messages: List[str]
    ) -> List[Dict[str, Any]]:
        """Validate field definitions against multiple messages
        
        Args:
            fields: Field definition list
            messages: List of packet hex strings
        
        Returns:
            List of parse results, each containing:
            - index: Message index
            - success: Whether parsing succeeded
            - error: Error message (if failed)
            - message_length: Packet length
            - coverage: Coverage percentage
            - covered_bytes: Number of covered bytes
            - gaps: Uncovered byte ranges (causes failure)
            - overlaps: Overlapping byte ranges (causes failure)
            - parsed_fields: Parsed field values
        """
        results = []
        
        for i, hex_msg in enumerate(messages):
            result = cls.parse_message_fields(fields, hex_msg, strict_boundary_check=True)
            
            if not result["success"]:
                results.append({
                    "index": i,
                    "success": False,
                    "error": result["error"],
                    "message_length": result.get("packet_length", 0),
                    "parsed_fields": result.get("parsed_fields", {})
                })
                continue
            
            # Analyze coverage
            coverage_analysis = cls.analyze_coverage(
                result["coverage_count"],
                result["packet_length"]
            )
            
            # Determine success: no gaps AND no overlaps
            success = not coverage_analysis["has_gaps"] and not coverage_analysis["has_overlaps"]
            
            result_entry = {
                "index": i,
                "success": success,
                "message_length": result["packet_length"],
                "coverage": coverage_analysis["coverage"],
                "covered_bytes": coverage_analysis["covered_bytes"],
                "parsed_fields": result["parsed_fields"]
            }
            
            # Add error info if not successful
            error_parts = []
            if coverage_analysis["has_gaps"]:
                result_entry["gaps"] = coverage_analysis["gaps"]
                error_parts.append(f"Uncovered bytes (gaps) at: {coverage_analysis['gaps']}")
            
            if coverage_analysis["has_overlaps"]:
                result_entry["overlaps"] = coverage_analysis["overlaps"]
                error_parts.append(f"Overlapping bytes at: {coverage_analysis['overlaps']}")
            
            if error_parts:
                result_entry["error"] = "; ".join(error_parts)
            
            results.append(result_entry)
        
        return results
