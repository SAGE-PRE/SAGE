#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Endianness Detection Skill

Provides detect_endianness tool to help identify protocol byte order.
Should be called early in analysis (STATISTICS stage) to guide field type selection.

Detection methods:
1. Value range analysis - small values vs large values
2. High-byte-zero pattern detection
3. Length field correlation
4. Sequence value detection
5. Common protocol patterns
"""

import logging
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from ..base import Skill, SkillContext, SkillPhase, SkillRegistry, SkillResult, ToolSchema


@SkillRegistry.register
class EndiannessDetectionSkill(Skill):
    """
    Endianness Detection Skill
    
    Analyzes message data to determine likely byte order (little-endian vs big-endian).
    Provides evidence-based recommendations for LLM to use correct integer types.
    """
    
    name = "endianness_detection"
    description = "Detects protocol byte order based on statistical analysis"
    version = "1.0.0"
    phases = [SkillPhase.POST_EXTRACT]
    priority = 15  # Run before byte_analysis (priority 20)
    is_tool = True
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.min_messages = (config or {}).get("min_messages", 5)
    
    def get_tool_schema(self) -> ToolSchema:
        """Return tool call schema"""
        return ToolSchema(
            name="detect_endianness",
            description="""Detect the likely byte order (endianness) of the protocol.

[When to Call This Tool]
- Early in analysis (after analyze_bytes basic mode)
- When you need to decide between uint16_be/uint16_le, uint32_be/uint32_le types
- When you see 2-byte or 4-byte fields and are unsure about byte order

[What This Tool Analyzes]
- Value range: Which interpretation gives smaller, more reasonable values?
- High-byte-zero patterns: 0xNN00 suggests LE, 0x00NN suggests BE
- Length field correlation: Which byte order matches message lengths?
- Sequence patterns: Which byte order shows sequential values across messages?

[Return Information]
- suggested_endianness: "little", "big", or "mixed"
- confidence: 0.0-1.0 confidence score
- evidence: List of supporting evidence
- field_hints: Suggested field types for specific offsets""",
            parameters={
                "type": "object",
                "properties": {
                    "start_offset": {
                        "type": "integer",
                        "description": "Start offset for analysis (default: 0, skip potential magic bytes)",
                        "default": 0
                    },
                    "end_offset": {
                        "type": "integer",
                        "description": "End offset for analysis (default: 64 or min message length)",
                        "default": 64
                    },
                    "skip_constant_regions": {
                        "type": "boolean",
                        "description": "Skip regions where all bytes are constant (likely magic/padding)",
                        "default": True
                    }
                },
                "required": []
            }
        )
    
    def invoke(self, context: SkillContext, **kwargs) -> Dict[str, Any]:
        """Tool invocation entry point"""
        start_offset = kwargs.get("start_offset", 0)
        end_offset = kwargs.get("end_offset", 64)
        skip_constant = kwargs.get("skip_constant_regions", True)
        
        messages = context.messages
        if not messages:
            return {"error": "No messages available for analysis"}
        
        raw_messages = self._extract_raw_messages(messages)
        if not raw_messages or len(raw_messages) < self.min_messages:
            return {"error": f"Need at least {self.min_messages} messages for reliable detection"}
        
        result = self._detect_endianness(
            raw_messages, 
            start_offset, 
            end_offset, 
            skip_constant
        )
        
        # Store in context for other skills to use
        context.metadata["endianness_detection"] = result
        
        return result
    
    def _detect_endianness(self, messages: List[bytes], start: int, end: int, 
                           skip_constant: bool) -> Dict[str, Any]:
        """
        Main detection logic
        
        Returns:
            Detection result with suggested endianness and evidence
        """
        min_len = min(len(m) for m in messages)
        end = min(end, min_len - 1)
        
        if end <= start + 1:
            return {"error": f"Analysis range too small: [{start}, {end})"}
        
        # Find constant byte positions (to optionally skip)
        constant_positions = set()
        if skip_constant:
            for pos in range(start, end):
                values = [m[pos] for m in messages]
                if len(set(values)) == 1:
                    constant_positions.add(pos)
        
        le_score = 0.0
        be_score = 0.0
        evidence = []
        field_hints = []
        
        # Analyze 2-byte aligned positions
        for pos in range(start, end - 1, 2):
            # Skip if both bytes are constant
            if skip_constant and pos in constant_positions and (pos + 1) in constant_positions:
                continue
            
            pos_evidence = self._analyze_uint16_position(messages, pos, constant_positions)
            if pos_evidence:
                le_score += pos_evidence.get("le_score", 0)
                be_score += pos_evidence.get("be_score", 0)
                if pos_evidence.get("evidence"):
                    evidence.append(pos_evidence["evidence"])
                if pos_evidence.get("hint"):
                    field_hints.append(pos_evidence["hint"])
        
        # Analyze 4-byte aligned positions
        for pos in range(start, end - 3, 4):
            if skip_constant:
                if all(p in constant_positions for p in range(pos, pos + 4)):
                    continue
            
            pos_evidence = self._analyze_uint32_position(messages, pos)
            if pos_evidence:
                le_score += pos_evidence.get("le_score", 0)
                be_score += pos_evidence.get("be_score", 0)
                if pos_evidence.get("evidence"):
                    evidence.append(pos_evidence["evidence"])
        
        # Check for length field correlation
        length_evidence = self._check_length_field_correlation(messages, start, min(16, end))
        if length_evidence:
            le_score += length_evidence.get("le_score", 0)
            be_score += length_evidence.get("be_score", 0)
            if length_evidence.get("evidence"):
                evidence.append(length_evidence["evidence"])
            if length_evidence.get("hint"):
                field_hints.append(length_evidence["hint"])
        
        # Calculate result
        total_score = le_score + be_score
        if total_score == 0:
            suggested = "unknown"
            confidence = 0.5
        else:
            le_ratio = le_score / total_score
            if le_ratio > 0.65:
                suggested = "little"
                confidence = min(0.95, le_ratio)
            elif le_ratio < 0.35:
                suggested = "big"
                confidence = min(0.95, 1 - le_ratio)
            else:
                suggested = "mixed"
                confidence = 0.5
        
        # Build recommendation message
        if suggested == "little":
            recommendation = "Use little-endian types: uint16_le, uint32_le, uint64_le"
        elif suggested == "big":
            recommendation = "Use big-endian types: uint16_be, uint32_be, uint64_be"
        else:
            recommendation = "Mixed or unclear - analyze individual fields carefully"
        
        return {
            "suggested_endianness": suggested,
            "confidence": round(confidence, 2),
            "le_score": round(le_score, 2),
            "be_score": round(be_score, 2),
            "recommendation": recommendation,
            "evidence": evidence[:10],  # Limit evidence count
            "field_hints": field_hints[:8],  # Limit hints
            "analysis_range": {"start": start, "end": end}
        }
    
    def _analyze_uint16_position(self, messages: List[bytes], pos: int,
                                  constant_positions: set) -> Optional[Dict]:
        """Analyze a 2-byte position for endianness indicators"""
        le_values = []
        be_values = []
        
        for msg in messages:
            le_val = int.from_bytes(msg[pos:pos+2], 'little')
            be_val = int.from_bytes(msg[pos:pos+2], 'big')
            le_values.append(le_val)
            be_values.append(be_val)
        
        le_score = 0.0
        be_score = 0.0
        evidence = None
        hint = None
        
        le_max = max(le_values)
        be_max = max(be_values)
        le_unique = len(set(le_values))
        be_unique = len(set(be_values))
        
        # Check byte patterns
        high_bytes = [msg[pos + 1] for msg in messages]  # For LE: this is high byte
        low_bytes = [msg[pos] for msg in messages]      # For LE: this is low byte
        
        high_byte_zero = all(h == 0 for h in high_bytes)
        low_byte_zero = all(l == 0 for l in low_bytes)
        high_byte_constant = len(set(high_bytes)) == 1
        low_byte_constant = len(set(low_bytes)) == 1
        
        # Rule 1: Value range - smaller values are more likely correct
        if le_max < 1000 and be_max > 10000:
            le_score += 2.0
            evidence = {
                "offset": pos,
                "type": "value_range",
                "le_max": le_max,
                "be_max": be_max,
                "favor": "little",
                "reason": f"LE gives small values (max={le_max}), BE gives large (max={be_max})"
            }
            hint = {"offset": pos, "size": 2, "suggested_type": "uint16_le", 
                   "reason": "Small value range"}
        elif be_max < 1000 and le_max > 10000:
            be_score += 2.0
            evidence = {
                "offset": pos,
                "type": "value_range",
                "le_max": le_max,
                "be_max": be_max,
                "favor": "big",
                "reason": f"BE gives small values (max={be_max}), LE gives large (max={le_max})"
            }
            hint = {"offset": pos, "size": 2, "suggested_type": "uint16_be",
                   "reason": "Small value range"}
        
        # Rule 2: High-byte-zero pattern (common for small LE values)
        # Pattern: 0xNN 0x00 -> LE small value, varying low byte
        elif high_byte_zero and not low_byte_constant and len(set(low_bytes)) > 1:
            le_score += 1.5
            if not evidence:
                evidence = {
                    "offset": pos,
                    "type": "high_byte_zero_le",
                    "favor": "little",
                    "reason": f"Pattern 0xNN 0x00 at offset {pos} (LE small values)"
                }
                hint = {"offset": pos, "size": 2, "suggested_type": "uint16_le",
                       "reason": "High byte is 0x00, low byte varies"}
        
        # Pattern: 0x00 0xNN -> BE small value, varying low byte
        elif low_byte_zero and not high_byte_constant and len(set(high_bytes)) > 1:
            be_score += 1.5
            if not evidence:
                evidence = {
                    "offset": pos,
                    "type": "high_byte_zero_be",
                    "favor": "big",
                    "reason": f"Pattern 0x00 0xNN at offset {pos} (BE small values)"
                }
                hint = {"offset": pos, "size": 2, "suggested_type": "uint16_be",
                       "reason": "High byte is 0x00, low byte varies"}
        
        # Rule 3: Sequence detection - which interpretation shows sequential values?
        elif le_unique > 2 and be_unique > 2:
            le_sorted = sorted(set(le_values))
            be_sorted = sorted(set(be_values))
            
            # Check if values form a sequence (differences of 1)
            le_sequential = self._is_sequential(le_sorted)
            be_sequential = self._is_sequential(be_sorted)
            
            if le_sequential and not be_sequential:
                le_score += 1.0
                if not evidence:
                    evidence = {
                        "offset": pos,
                        "type": "sequence",
                        "favor": "little",
                        "reason": f"LE values form sequence: {le_sorted[:5]}"
                    }
            elif be_sequential and not le_sequential:
                be_score += 1.0
                if not evidence:
                    evidence = {
                        "offset": pos,
                        "type": "sequence",
                        "favor": "big",
                        "reason": f"BE values form sequence: {be_sorted[:5]}"
                    }
        
        if le_score == 0 and be_score == 0:
            return None
        
        return {
            "le_score": le_score,
            "be_score": be_score,
            "evidence": evidence,
            "hint": hint
        }
    
    def _analyze_uint32_position(self, messages: List[bytes], pos: int) -> Optional[Dict]:
        """Analyze a 4-byte position for endianness indicators"""
        le_values = []
        be_values = []
        
        for msg in messages:
            le_val = int.from_bytes(msg[pos:pos+4], 'little')
            be_val = int.from_bytes(msg[pos:pos+4], 'big')
            le_values.append(le_val)
            be_values.append(be_val)
        
        le_max = max(le_values)
        be_max = max(be_values)
        
        le_score = 0.0
        be_score = 0.0
        evidence = None
        
        # Strong indicator: one interpretation gives reasonable values, other gives astronomical
        if le_max < 100000 and be_max > 1000000000:
            le_score += 2.5
            evidence = {
                "offset": pos,
                "size": 4,
                "type": "uint32_value_range",
                "favor": "little",
                "reason": f"LE gives reasonable 32-bit values (max={le_max}), BE astronomical ({be_max})"
            }
        elif be_max < 100000 and le_max > 1000000000:
            be_score += 2.5
            evidence = {
                "offset": pos,
                "size": 4,
                "type": "uint32_value_range",
                "favor": "big",
                "reason": f"BE gives reasonable 32-bit values (max={be_max}), LE astronomical ({le_max})"
            }
        
        # Check for high-bytes-zero pattern in 32-bit values
        high_bytes = [msg[pos+2:pos+4] for msg in messages]
        low_bytes = [msg[pos:pos+2] for msg in messages]
        
        high_all_zero = all(b == b'\x00\x00' for b in high_bytes)
        low_all_zero = all(b == b'\x00\x00' for b in low_bytes)
        
        if high_all_zero and not low_all_zero:
            le_score += 1.0
            if not evidence:
                evidence = {
                    "offset": pos,
                    "size": 4,
                    "type": "uint32_high_bytes_zero",
                    "favor": "little",
                    "reason": f"Upper 2 bytes are 0x0000 (LE 32-bit small value pattern)"
                }
        elif low_all_zero and not high_all_zero:
            be_score += 1.0
            if not evidence:
                evidence = {
                    "offset": pos,
                    "size": 4,
                    "type": "uint32_high_bytes_zero",
                    "favor": "big",
                    "reason": f"Lower 2 bytes are 0x0000 (BE 32-bit small value pattern)"
                }
        
        if le_score == 0 and be_score == 0:
            return None
        
        return {
            "le_score": le_score,
            "be_score": be_score,
            "evidence": evidence
        }
    
    def _check_length_field_correlation(self, messages: List[bytes], 
                                         start: int, end: int) -> Optional[Dict]:
        """Check if any 2-byte field correlates with message length"""
        msg_lengths = [len(m) for m in messages]
        
        best_le_match = 0
        best_be_match = 0
        best_le_pos = -1
        best_be_pos = -1
        
        for pos in range(start, min(end, min(len(m) for m in messages) - 1), 2):
            le_matches = 0
            be_matches = 0
            
            for i, msg in enumerate(messages):
                le_val = int.from_bytes(msg[pos:pos+2], 'little')
                be_val = int.from_bytes(msg[pos:pos+2], 'big')
                
                # Check if value relates to message length
                # Common patterns: total_length, total_length - header, etc.
                length_variants = [
                    msg_lengths[i],
                    msg_lengths[i] - pos - 2,  # Length of remaining bytes
                    msg_lengths[i] - 4,        # Common header offset
                    msg_lengths[i] - 8,
                    64,                        # Common fixed header size
                ]
                
                if le_val in length_variants:
                    le_matches += 1
                if be_val in length_variants:
                    be_matches += 1
            
            if le_matches > best_le_match:
                best_le_match = le_matches
                best_le_pos = pos
            if be_matches > best_be_match:
                best_be_match = be_matches
                best_be_pos = pos
        
        threshold = len(messages) * 0.7
        
        if best_le_match >= threshold and best_le_match > best_be_match:
            return {
                "le_score": 3.0,  # Length field is strong evidence
                "be_score": 0,
                "evidence": {
                    "offset": best_le_pos,
                    "type": "length_field",
                    "favor": "little",
                    "matches": best_le_match,
                    "total": len(messages),
                    "reason": f"Found LE length field at offset {best_le_pos} ({best_le_match}/{len(messages)} match)"
                },
                "hint": {
                    "offset": best_le_pos,
                    "size": 2,
                    "suggested_type": "uint16_le",
                    "reason": "Correlates with message length"
                }
            }
        elif best_be_match >= threshold and best_be_match > best_le_match:
            return {
                "le_score": 0,
                "be_score": 3.0,
                "evidence": {
                    "offset": best_be_pos,
                    "type": "length_field",
                    "favor": "big",
                    "matches": best_be_match,
                    "total": len(messages),
                    "reason": f"Found BE length field at offset {best_be_pos} ({best_be_match}/{len(messages)} match)"
                },
                "hint": {
                    "offset": best_be_pos,
                    "size": 2,
                    "suggested_type": "uint16_be",
                    "reason": "Correlates with message length"
                }
            }
        
        return None
    
    def _is_sequential(self, sorted_values: List[int], max_gap: int = 5) -> bool:
        """Check if values form a rough sequence (with small gaps)"""
        if len(sorted_values) < 3:
            return False
        
        sequential_count = 0
        for i in range(1, len(sorted_values)):
            if sorted_values[i] - sorted_values[i-1] <= max_gap:
                sequential_count += 1
        
        return sequential_count >= len(sorted_values) * 0.6
    
    def _extract_raw_messages(self, messages) -> List[bytes]:
        """Extract raw byte data from messages"""
        raw = []
        for msg in messages:
            if hasattr(msg, 'data'):
                raw.append(bytes(msg.data))
            elif isinstance(msg, bytes):
                raw.append(msg)
            elif isinstance(msg, (list, tuple)):
                raw.append(bytes(msg))
        return raw
    
    # ========== Phase-based Execution ==========
    
    def execute(self, context: SkillContext, phase: SkillPhase) -> SkillResult:
        """Auto-execute endianness detection in POST_EXTRACT phase"""
        if phase != SkillPhase.POST_EXTRACT:
            return SkillResult(success=True, modified=False)
        
        messages = context.messages
        if not messages or len(messages) < self.min_messages:
            return SkillResult(
                success=True,
                modified=False,
                message=f"Not enough messages for endianness detection"
            )
        
        raw_messages = self._extract_raw_messages(messages)
        if not raw_messages:
            return SkillResult(success=True, modified=False, message="No raw data")
        
        # Run detection with default parameters
        result = self._detect_endianness(raw_messages, start=0, end=64, skip_constant=True)
        
        if "error" in result:
            return SkillResult(
                success=True,
                modified=False,
                message=result["error"]
            )
        
        context.metadata["endianness_detection"] = result
        
        return SkillResult(
            success=True,
            modified=True,
            message=f"Endianness detection: {result['suggested_endianness']} (confidence: {result['confidence']})",
            data=result
        )
    
    def get_prompt_enhancement(self, context: SkillContext) -> str:
        """Generate prompt enhancement based on detection result"""
        detection = context.metadata.get("endianness_detection", {})
        if not detection or "error" in detection:
            return ""
        
        suggested = detection.get("suggested_endianness", "unknown")
        confidence = detection.get("confidence", 0)
        recommendation = detection.get("recommendation", "")
        
        lines = [
            "## Byte Order Detection",
            "",
            f"- Suggested endianness: **{suggested}** (confidence: {confidence:.0%})",
            f"- {recommendation}",
        ]
        
        # Add field hints if available
        hints = detection.get("field_hints", [])
        if hints:
            lines.append("")
            lines.append("Field type suggestions:")
            for hint in hints[:5]:
                lines.append(f"  - Offset {hint['offset']}: {hint['suggested_type']} ({hint.get('reason', '')})")
        
        return "\n".join(lines)
