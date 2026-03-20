#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TLV Detection Skill

Based on BinaryInferno algorithm, detects TLV (Type-Length-Value) structures in protocol messages.
Supports multiple TLV variants:
- LV (Length-Value): No Type field
- TLV (Type-Length-Value): Standard TLV
- QTLV (Quantity + TLV): TLV array with quantity prefix
- Supports 1-4 byte Type and Length fields
- Supports big-endian and little-endian byte order
"""

import logging
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass

from ..base import Skill, SkillContext, SkillPhase, SkillRegistry, SkillResult, ToolSchema


@dataclass
class TLVPattern:
    """TLV pattern description"""
    pattern_type: str  # "LV", "TLV", "QLV", "QTLV"
    type_width: int    # Type field width (0, 1, 2, 4)
    length_width: int  # Length field width (1, 2, 3, 4)
    endian: str        # "big" or "little"
    quantity_width: int = 0  # Quantity field width (0 means none)
    
    @property
    def label(self) -> str:
        """Generate pattern label"""
        parts = []
        if self.quantity_width > 0:
            parts.append(f"{self.quantity_width}Q")
        parts.append(f"{self.type_width}T")
        parts.append(f"{self.length_width}L")
        parts.append("V")
        parts.append(self.endian[:3])
        return "_".join(parts)


@dataclass 
class TLVMatch:
    """TLV match result"""
    offset: int           # Start offset
    pattern: TLVPattern   # Matched pattern
    confidence: float     # Confidence 0-1
    blocks: List[Dict]    # Detected TLV blocks list
    covers_to_end: bool   # Whether covers to message end


class TLVDetector:
    """TLV structure detector"""
    
    def __init__(self):
        self.logger = logging.getLogger("tlv_detector")
    
    def detect_tlv_at_offset(
        self, 
        messages: List[bytes], 
        offset: int,
        pattern: TLVPattern
    ) -> Optional[TLVMatch]:
        """
        Detect TLV structure at specified offset
        
        Args:
            messages: Message list
            offset: Start offset
            pattern: TLV pattern to detect
            
        Returns:
            TLVMatch or None
        """
        total_matched = 0
        all_blocks = []
        
        for msg in messages:
            if offset >= len(msg):
                return None
                
            data = msg[offset:]
            blocks, remaining = self._parse_tlv_chain(data, pattern)
            
            if blocks is not None:
                total_matched += 1
                all_blocks.append(blocks)
        
        if total_matched == 0:
            return None
            
        confidence = total_matched / len(messages)
        
        if confidence < 0.7:  # At least 70% messages match
            return None
        
        # Check if covers to end (leaving 0-2 bytes for checksum)
        covers_to_end = all(
            len(msg) - offset - sum(b.get('total_size', 0) for b in blocks) <= 2
            for msg, blocks in zip(messages, all_blocks)
            if blocks
        )
        
        # Merge block info
        merged_blocks = self._merge_block_info(all_blocks)
        
        return TLVMatch(
            offset=offset,
            pattern=pattern,
            confidence=confidence,
            blocks=merged_blocks,
            covers_to_end=covers_to_end
        )
    
    def _parse_tlv_chain(
        self, 
        data: bytes, 
        pattern: TLVPattern
    ) -> Tuple[Optional[List[Dict]], bytes]:
        """
        Parse TLV chain
        
        Returns:
            (block list, remaining data) or (None, data) if parsing fails
        """
        blocks = []
        remaining = data
        
        # Handle Quantity prefix
        if pattern.quantity_width > 0:
            if len(remaining) < pattern.quantity_width:
                return None, data
            
            quantity = int.from_bytes(
                remaining[:pattern.quantity_width], 
                pattern.endian
            )
            remaining = remaining[pattern.quantity_width:]
            
            # Limit quantity range
            if quantity <= 0 or quantity > 20:
                return None, data
            
            max_iterations = quantity
        else:
            max_iterations = 50  # Prevent infinite loop
        
        iteration = 0
        while remaining and iteration < max_iterations:
            iteration += 1
            
            header_size = pattern.type_width + pattern.length_width
            if len(remaining) < header_size:
                break
            
            # Parse Type
            type_val = None
            if pattern.type_width > 0:
                type_val = int.from_bytes(
                    remaining[:pattern.type_width],
                    pattern.endian
                )
                remaining = remaining[pattern.type_width:]
            
            # Parse Length
            length_val = int.from_bytes(
                remaining[:pattern.length_width],
                pattern.endian
            )
            remaining = remaining[pattern.length_width:]
            
            # Validate Length reasonableness
            if length_val > len(remaining):
                return None, data
            
            # Limit single value size
            if length_val > 1024:
                return None, data
            
            # Extract Value
            value = remaining[:length_val]
            remaining = remaining[length_val:]
            
            block = {
                'type': type_val,
                'length': length_val,
                'value_hex': value.hex().upper(),
                'total_size': header_size + length_val
            }
            blocks.append(block)
            
            # If has Quantity, check if count reached
            if pattern.quantity_width > 0 and len(blocks) >= max_iterations:
                break
        
        if not blocks:
            return None, data
            
        return blocks, remaining
    
    def _merge_block_info(self, all_blocks: List[List[Dict]]) -> List[Dict]:
        """Merge block info from multiple messages"""
        if not all_blocks:
            return []
        
        # Find most common block count
        block_counts = Counter(len(b) for b in all_blocks)
        common_count = block_counts.most_common(1)[0][0]
        
        # Only consider messages with same block count
        valid_blocks = [b for b in all_blocks if len(b) == common_count]
        
        if not valid_blocks:
            return all_blocks[0] if all_blocks else []
        
        merged = []
        for i in range(common_count):
            types = [b[i]['type'] for b in valid_blocks if b[i]['type'] is not None]
            lengths = [b[i]['length'] for b in valid_blocks]
            
            block_info = {
                'index': i,
                'type_values': list(set(types)) if types else None,
                'type_constant': len(set(types)) == 1 if types else None,
                'length_min': min(lengths),
                'length_max': max(lengths),
                'length_constant': min(lengths) == max(lengths)
            }
            
            if block_info['type_constant'] and types:
                block_info['type'] = types[0]
                block_info['type_hex'] = f"0x{types[0]:02X}"
            
            merged.append(block_info)
        
        return merged
    
    def detect_all_patterns(
        self, 
        messages: List[bytes],
        start_offset: int = 0,
        max_offset: int = 32
    ) -> List[TLVMatch]:
        """
        Detect all possible TLV patterns
        
        Args:
            messages: Message list
            start_offset: Start search offset
            max_offset: Maximum search offset
            
        Returns:
            List of all detected TLV matches
        """
        matches = []
        
        # Generate all possible pattern combinations
        patterns = []
        for endian in ['big', 'little']:
            for type_width in [0, 1, 2]:
                for length_width in [1, 2]:
                    # Basic TLV/LV
                    patterns.append(TLVPattern(
                        pattern_type="TLV" if type_width > 0 else "LV",
                        type_width=type_width,
                        length_width=length_width,
                        endian=endian
                    ))
                    
                    # QTLV/QLV with Quantity prefix
                    for q_width in [1]:
                        patterns.append(TLVPattern(
                            pattern_type="QTLV" if type_width > 0 else "QLV",
                            type_width=type_width,
                            length_width=length_width,
                            endian=endian,
                            quantity_width=q_width
                        ))
        
        # Try each pattern at each offset position
        for offset in range(start_offset, min(max_offset, min(len(m) for m in messages))):
            for pattern in patterns:
                match = self.detect_tlv_at_offset(messages, offset, pattern)
                if match and match.confidence >= 0.8:
                    matches.append(match)
        
        # Sort by confidence and coverage
        matches.sort(key=lambda m: (-m.confidence, -int(m.covers_to_end), m.offset))
        
        return matches


@SkillRegistry.register
class TLVDetectionSkill(Skill):
    """
    TLV Detection Skill
    
    Provides detect_tlv tool to help LLM identify TLV structures in protocols.
    """
    
    name = "tlv_detection"
    description = "Detect TLV (Type-Length-Value) patterns in protocol messages"
    version = "1.0.0"
    phases = [SkillPhase.PRE_ANALYSIS]
    priority = 25
    is_tool = True
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.detector = TLVDetector()
    
    def get_tool_schema(self) -> ToolSchema:
        """Return Tool call schema"""
        return ToolSchema(
            name="detect_tlv",
            description="""Detect TLV (Type-Length-Value) structures in messages.

This tool automatically detects multiple TLV variants:
- LV: No Type field, only Length + Value
- TLV: Standard Type + Length + Value  
- QTLV: TLV array with quantity prefix
- Supports 1-2 byte Type/Length fields
- Supports big-endian and little-endian byte order

[When to Call This Tool - Based on Data Features]
1. analyze_header returns constant_bytes showing **scattered but regular distribution** after fixed header
   - Example: offsets 9, 10, 15, 16, 19, 20, 23, 24... are all constants
   - This pattern may be Type and Length fields in TLV structure
   
2. Message length varies, but changes are **regular increments**
   - Example: 38, 41, 48, 52 bytes (differences 3, 7, 4)
   - Suggests some TLV blocks have variable-length Values
   
3. After fixed header, a byte value correlates with subsequent data amount
   - Example: value at offset 8 is 5, followed by 5 repeating substructures
   - May be TLV quantity counter (Quantity)
   
4. Within continuous constant byte sequences, there are **periodic non-constant bytes**
   - Example: a constant appears every 6-8 bytes, middle bytes vary
   - Suggests Type(constant) + Length(possibly constant) + Value(varying)

[Not Applicable Scenarios]
- All messages have exactly same length (pure fixed-length protocol)
- Constant bytes only concentrated at message start (may be simple fixed header)
- Message length differences are large and irregular (may be other encoding methods)""",
            parameters={
                "type": "object",
                "properties": {
                    "start_offset": {
                        "type": "integer",
                        "description": "Byte offset to start detection, default 0",
                        "default": 0
                    },
                    "max_offset": {
                        "type": "integer",
                        "description": "Maximum search offset, default 32",
                        "default": 32
                    }
                },
                "required": []
            }
        )
    
    def invoke(self, context: SkillContext, **kwargs) -> Dict[str, Any]:
        """Tool invocation entry point"""
        start_offset = kwargs.get("start_offset", 0)
        max_offset = kwargs.get("max_offset", 32)
        
        messages = context.messages
        if not messages:
            return {"error": "No messages available for analysis"}
        
        # Extract raw byte data
        raw_messages = self._extract_raw_messages(messages)
        if not raw_messages:
            return {"error": "Could not extract raw message data"}
        
        # Detect TLV patterns
        matches = self.detector.detect_all_patterns(
            raw_messages,
            start_offset=start_offset,
            max_offset=max_offset
        )
        
        # Filter low-confidence matches using fixed threshold
        matches = [m for m in matches if m.confidence >= 0.8]
        
        if not matches:
            return {
                "found": False,
                "message": "No TLV patterns detected with sufficient confidence",
                "suggestion": "The protocol may use fixed-length fields or other encoding schemes"
            }
        
        # Format results
        results = []
        for match in matches[:5]:  # Return at most 5 matches
            result = {
                "offset": match.offset,
                "pattern": match.pattern.label,
                "pattern_description": self._describe_pattern(match.pattern),
                "covers_to_end": match.covers_to_end,
                "blocks": []
            }
            
            for block in match.blocks:
                block_info = {
                    "index": block.get('index', 0)
                }
                if block.get('type_constant') and block.get('type_hex'):
                    block_info["type"] = block['type_hex']
                elif block.get('type_values'):
                    block_info["type_values"] = [f"0x{t:02X}" for t in block['type_values'][:5]]
                
                if block.get('length_constant'):
                    block_info["length"] = block['length_min']
                else:
                    block_info["length_range"] = f"{block['length_min']}-{block['length_max']}"
                
                result["blocks"].append(block_info)
            
            results.append(result)
        
        # Generate suggestion
        best_match = matches[0]
        suggestion = self._generate_suggestion(best_match)
        
        return {
            "found": True,
            "matches": results,
            "best_match": {
                "offset": best_match.offset,
                "pattern": best_match.pattern.label
            },
            "suggestion": suggestion
        }
    
    def _extract_raw_messages(self, messages) -> List[bytes]:
        """Extract raw byte data"""
        raw = []
        for msg in messages:
            if hasattr(msg, 'data'):
                raw.append(bytes(msg.data))
            elif isinstance(msg, bytes):
                raw.append(msg)
            elif isinstance(msg, (list, tuple)):
                raw.append(bytes(msg))
        return raw
    
    def _describe_pattern(self, pattern: TLVPattern) -> str:
        """Generate human-readable pattern description"""
        parts = []
        
        if pattern.quantity_width > 0:
            parts.append(f"Quantity ({pattern.quantity_width}B)")
        
        if pattern.type_width > 0:
            parts.append(f"Type ({pattern.type_width}B)")
        
        parts.append(f"Length ({pattern.length_width}B, {pattern.endian}-endian)")
        parts.append("Value (variable)")
        
        return " + ".join(parts)
    
    def _generate_suggestion(self, match: TLVMatch) -> str:
        """Generate field definition suggestion"""
        lines = []
        
        if match.pattern.quantity_width > 0:
            lines.append(f"- Add 'tlv_count' field at offset {match.offset} (uint{match.pattern.quantity_width * 8})")
            lines.append(f"- TLV blocks start at offset {match.offset + match.pattern.quantity_width}")
        else:
            lines.append(f"- TLV blocks start at offset {match.offset}")
        
        lines.append(f"- Each TLV block format: {self._describe_pattern(match.pattern)}")
        
        if match.blocks:
            lines.append(f"- Detected {len(match.blocks)} TLV block(s) per message")
            
            for block in match.blocks:
                if block.get('type_constant') and block.get('type_hex'):
                    lines.append(f"  - Block {block['index']}: Type={block['type_hex']}, Length={'fixed' if block.get('length_constant') else 'variable'}")
        
        if match.covers_to_end:
            lines.append("- TLV blocks cover message until checksum (last 1-2 bytes)")
        
        return "\n".join(lines)
    
    def execute(self, context: SkillContext, phase: SkillPhase) -> SkillResult:
        """Phase-based execution (optional, mainly uses Tool mode)"""
        return SkillResult(success=True, modified=False)


# Convenience functions
def detect_tlv_patterns(messages: List[bytes], start_offset: int = 0) -> List[TLVMatch]:
    """
    Detect TLV patterns in messages
    
    Args:
        messages: Byte message list
        start_offset: Start offset
        
    Returns:
        TLV match list
    """
    detector = TLVDetector()
    return detector.detect_all_patterns(messages, start_offset=start_offset)
