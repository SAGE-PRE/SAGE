#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Byte Statistical Analysis Skill

Provides analyze_bytes Tool for byte-level statistical analysis of protocol messages:
- basic: Basic statistics (constant bytes, length field candidates, entropy distribution)
- region: Detailed statistical features for specified range
- boundary: Search for structure boundary (header/payload delimiter)
- compare: Compare structural differences between two regions

Supports caching to avoid repeated analysis.
"""

import hashlib
import json
import logging
from collections import Counter
from math import log2
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..base import Skill, SkillContext, SkillPhase, SkillRegistry, SkillResult, ToolSchema


# Cache directory
CACHE_DIR = Path(__file__).parent.parent.parent / ".cache" / "byte_analysis"


def get_cache_path(protocol: str) -> Path:
    """Get cache file path for protocol"""
    safe_name = protocol.lower().replace("/", "_").replace("\\", "_")
    return CACHE_DIR / f"{safe_name}.json"


def load_cache(protocol: str) -> Optional[Dict[str, Any]]:
    """Load cached analysis result"""
    cache_path = get_cache_path(protocol)
    if cache_path.exists():
        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return None
    return None


def save_cache(protocol: str, analysis: Dict[str, Any]) -> bool:
    """Save analysis result to cache"""
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cache_path = get_cache_path(protocol)
        with open(cache_path, 'w', encoding='utf-8') as f:
            json.dump(analysis, f, indent=2, ensure_ascii=False)
        return True
    except IOError as e:
        logging.warning(f"Failed to save byte analysis cache: {e}")
        return False


def clear_cache(protocol: str = None) -> int:
    """Clear cache (specified protocol or all)"""
    if not CACHE_DIR.exists():
        return 0
    
    count = 0
    if protocol:
        cache_path = get_cache_path(protocol)
        if cache_path.exists():
            cache_path.unlink()
            count = 1
    else:
        for f in CACHE_DIR.glob("*.json"):
            f.unlink()
            count += 1
    return count


def list_cached_protocols() -> List[str]:
    """List cached protocols"""
    if not CACHE_DIR.exists():
        return []
    return [f.stem for f in CACHE_DIR.glob("*.json")]


def calculate_entropy(values: List[int]) -> float:
    """Calculate entropy value"""
    if not values:
        return 0.0
    counter = Counter(values)
    total = len(values)
    entropy = 0.0
    for count in counter.values():
        p = count / total
        if p > 0:
            entropy -= p * log2(p)
    return round(entropy, 3)


class ProtocolMetadata:
    """
    Protocol metadata that captures key characteristics discovered during analysis.
    
    This metadata is populated incrementally as analysis progresses and influences
    subsequent analysis stages. It should be passed to LLM for context-aware analysis.
    
    Attributes:
        endianness: Detected byte order ("little", "big", or "unknown")
        has_payload: Whether messages have variable-length payload after header
        header_end: Byte offset where header ends and payload begins (None if no payload)
        length_field: Info about length field if detected {"offset": int, "size": int, "type": str}
        magic_bytes: Magic signature info if detected {"offset": int, "size": int, "value": str}
        confidence: Overall confidence in the metadata (0.0-1.0)
    """
    
    def __init__(self):
        self.endianness: str = "unknown"  # "little", "big", "unknown"
        self.has_payload: Optional[bool] = None  # True, False, or None (unknown)
        self.header_end: Optional[int] = None  # Byte offset, or None if no payload
        self.length_field: Optional[Dict[str, Any]] = None  # {"offset", "size", "type"}
        self.magic_bytes: Optional[Dict[str, Any]] = None  # {"offset", "size", "value"}
        self.confidence: float = 0.0
        self._discovery_log: List[str] = []  # Track how metadata was discovered
    
    def update_endianness(self, value: str, source: str = "auto"):
        """Update endianness with discovery source tracking"""
        if value in ("little", "big", "unknown"):
            self.endianness = value
            self._discovery_log.append(f"endianness={value} (source: {source})")
    
    def update_header_boundary(self, offset: int, has_payload: bool, source: str = "auto"):
        """Update header/payload boundary info"""
        self.header_end = offset
        self.has_payload = has_payload
        self._discovery_log.append(f"header_end={offset}, has_payload={has_payload} (source: {source})")
    
    def update_length_field(self, offset: int, size: int, field_type: str, source: str = "auto"):
        """Update length field info"""
        self.length_field = {"offset": offset, "size": size, "type": field_type}
        self._discovery_log.append(f"length_field at {offset}, {size}B {field_type} (source: {source})")
    
    def update_magic_bytes(self, offset: int, size: int, value: str, source: str = "auto"):
        """Update magic bytes info"""
        self.magic_bytes = {"offset": offset, "size": size, "value": value}
        self._discovery_log.append(f"magic_bytes at {offset}: {value} (source: {source})")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization and LLM context"""
        return {
            "endianness": self.endianness,
            "has_payload": self.has_payload,
            "header_end": self.header_end,
            "length_field": self.length_field,
            "magic_bytes": self.magic_bytes,
            "confidence": self.confidence,
        }
    
    def to_llm_context(self) -> str:
        """Generate concise description for LLM prompt inclusion"""
        parts = []
        
        if self.endianness != "unknown":
            parts.append(f"Endianness: {self.endianness}-endian")
        
        if self.magic_bytes:
            parts.append(f"Magic: {self.magic_bytes['value']} at offset {self.magic_bytes['offset']}")
        
        if self.has_payload is not None:
            if self.has_payload and self.header_end is not None:
                parts.append(f"Header: 0-{self.header_end-1}, Payload: {self.header_end}+")
            elif not self.has_payload:
                parts.append("Fixed-length messages (no payload)")
        
        if self.length_field:
            lf = self.length_field
            parts.append(f"Length field: {lf['type']} at offset {lf['offset']}")
        
        if not parts:
            return "Protocol metadata: No significant features detected yet."
        
        return "Protocol metadata: " + "; ".join(parts)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProtocolMetadata":
        """Create from dictionary (e.g., loaded from cache or previous analysis)"""
        meta = cls()
        meta.endianness = data.get("endianness", "unknown")
        meta.has_payload = data.get("has_payload")
        meta.header_end = data.get("header_end")
        meta.length_field = data.get("length_field")
        meta.magic_bytes = data.get("magic_bytes")
        meta.confidence = data.get("confidence", 0.0)
        return meta
    
    def __repr__(self):
        return f"ProtocolMetadata({self.to_dict()})"


class MessageAnalyzer:
    """Unified message analyzer"""
    
    def __init__(self, messages: List[bytes], max_header_size: int = 64, 
                 metadata: Optional[ProtocolMetadata] = None):
        self.messages = messages
        self.msg_count = len(messages)
        self.min_len = min(len(m) for m in messages) if messages else 0
        self.max_len = max(len(m) for m in messages) if messages else 0
        self.max_header_size = max_header_size
        
        # Protocol metadata - can be pre-populated or discovered during analysis
        self.metadata = metadata if metadata else ProtocolMetadata()
    
    @property
    def detected_endianness(self) -> str:
        """Backward-compatible access to endianness via metadata"""
        return self.metadata.endianness
    
    @detected_endianness.setter
    def detected_endianness(self, value: str):
        """Backward-compatible setter for endianness"""
        self.metadata.update_endianness(value, source="detect_field_boundaries")
    
    def get_llm_context(self) -> str:
        """Get metadata context string for including in LLM prompts"""
        return self.metadata.to_llm_context()
    
    # ========== Basic Statistical Analysis ==========
    
    def find_constant_bytes(self, start: int = 0, end: int = -1) -> List[Dict]:
        """Find constant byte positions"""
        if not self.messages:
            return []
        
        if end == -1:
            end = min(self.min_len, self.max_header_size)
        end = min(end, self.min_len)
        
        constants = []
        for pos in range(start, end):
            values = [m[pos] for m in self.messages]
            if len(set(values)) == 1:
                constants.append({
                    "offset": pos,
                    "value": values[0],
                    "hex": f"0x{values[0]:02x}"
                })
        return constants
    
    def find_length_fields(self) -> List[Dict]:
        """Find potential length fields (checks both LE and BE)"""
        if not self.messages:
            return []
        
        candidates = []
        min_len = self.min_len
        msg_lengths = [len(m) for m in self.messages]
        
        for pos in range(min(16, min_len - 1)):
            # 1-byte length field
            matches = sum(1 for msg in self.messages 
                         if msg[pos] in (len(msg), len(msg) - pos - 1, len(msg) - 7))
            if matches > len(self.messages) * 0.7:
                candidates.append({
                    "offset": pos, "size": 1, "type": "uint8",
                    "confidence": round(matches / len(self.messages), 2)
                })
            
            # 2-byte length fields - check both BE and LE
            if pos + 1 < min_len:
                length_variants = lambda msg_len, p: [msg_len, msg_len - p - 2, 64]
                
                # Big-endian
                be_matches = sum(1 for i, msg in enumerate(self.messages)
                                if (msg[pos] << 8 | msg[pos + 1]) in length_variants(msg_lengths[i], pos))
                if be_matches > len(self.messages) * 0.7:
                    candidates.append({
                        "offset": pos, "size": 2, "type": "uint16_be",
                        "confidence": round(be_matches / len(self.messages), 2)
                    })
                
                # Little-endian
                le_matches = sum(1 for i, msg in enumerate(self.messages)
                                if (msg[pos] | (msg[pos + 1] << 8)) in length_variants(msg_lengths[i], pos))
                if le_matches > len(self.messages) * 0.7:
                    candidates.append({
                        "offset": pos, "size": 2, "type": "uint16_le",
                        "confidence": round(le_matches / len(self.messages), 2)
                    })
        
        # Update metadata with best length field candidate
        if candidates:
            best = max(candidates, key=lambda x: x["confidence"])
            self.metadata.update_length_field(
                best["offset"], best["size"], best["type"],
                source="find_length_fields"
            )
            # If length field exists, likely has payload
            if self.metadata.has_payload is None:
                self.metadata.has_payload = True
        
        return candidates
    
    def detect_endianness_hints(self, start: int = 0, end: int = -1) -> Dict[str, Any]:
        """
        Detect likely byte order (endianness) based on value patterns.
        
        Analyzes 2-byte and 4-byte aligned positions to determine if protocol
        uses little-endian or big-endian byte order.
        
        Returns:
            Dictionary with suggested endianness and supporting evidence
        """
        if not self.messages:
            return {"suggested": "unknown", "confidence": 0.5, "reasons": []}
        
        if end == -1:
            end = min(self.min_len, self.max_header_size)
        end = min(end, self.min_len - 1)
        
        if end <= start + 1:
            return {"suggested": "unknown", "confidence": 0.5, "reasons": ["Range too small"]}
        
        le_score = 0.0
        be_score = 0.0
        reasons = []
        
        # Find constant byte positions
        constant_positions = set()
        for pos in range(start, end):
            values = [m[pos] for m in self.messages]
            if len(set(values)) == 1:
                constant_positions.add(pos)
        
        # Analyze 2-byte positions
        for pos in range(start, end - 1, 2):
            # Skip fully constant pairs
            if pos in constant_positions and (pos + 1) in constant_positions:
                continue
            
            le_values = [int.from_bytes(m[pos:pos+2], 'little') for m in self.messages]
            be_values = [int.from_bytes(m[pos:pos+2], 'big') for m in self.messages]
            
            le_max = max(le_values)
            be_max = max(be_values)
            
            # Value range comparison
            if le_max < 1000 and be_max > 10000:
                le_score += 2.0
                reasons.append(f"offset {pos}-{pos+1}: LE={le_max} (small), BE={be_max} (large)")
            elif be_max < 1000 and le_max > 10000:
                be_score += 2.0
                reasons.append(f"offset {pos}-{pos+1}: BE={be_max} (small), LE={le_max} (large)")
            
            # High-byte-zero pattern
            high_bytes = [m[pos + 1] for m in self.messages]
            low_bytes = [m[pos] for m in self.messages]
            
            if all(h == 0 for h in high_bytes) and len(set(low_bytes)) > 1:
                le_score += 1.0
                if len(reasons) < 5:
                    reasons.append(f"offset {pos}: pattern 0xNN 0x00 (LE small values)")
            elif all(l == 0 for l in low_bytes) and len(set(high_bytes)) > 1:
                be_score += 1.0
                if len(reasons) < 5:
                    reasons.append(f"offset {pos}: pattern 0x00 0xNN (BE small values)")
        
        # Calculate result
        total_score = le_score + be_score
        if total_score == 0:
            return {"suggested": "unknown", "confidence": 0.5, "reasons": ["No clear pattern"]}
        
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
        
        return {
            "suggested": suggested,
            "confidence": round(confidence, 2),
            "le_score": round(le_score, 1),
            "be_score": round(be_score, 1),
            "reasons": reasons[:5]  # Limit to top 5 reasons
        }
    
    def calculate_entropy_profile(self, start: int = 0, end: int = -1) -> List[float]:
        """Calculate entropy for each position"""
        if not self.messages:
            return []
        
        if end == -1:
            end = min(self.min_len, self.max_header_size)
        end = min(end, self.min_len)
        
        entropies = []
        for pos in range(start, end):
            values = [m[pos] for m in self.messages]
            entropies.append(calculate_entropy(values))
        
        return entropies
    
    def analyze_lengths(self) -> Dict:
        """Analyze message length distribution"""
        lengths = [len(m) for m in self.messages]
        return {
            "min": min(lengths),
            "max": max(lengths),
            "is_fixed": len(set(lengths)) == 1,
            "unique_count": len(set(lengths)),
            "total": len(lengths),
        }
    
    # ========== Region Analysis ==========
    
    def analyze_region(self, start: int, end: int) -> Dict[str, Any]:
        """
        Analyze statistical features for specified byte range
        
        Args:
            start: Start offset (inclusive)
            end: End offset (exclusive), -1 means to message end
            
        Returns:
            Statistical features dictionary
        """
        if end == -1:
            end = self.min_len
        
        # Boundary check
        if start < 0 or start >= self.min_len:
            return {"error": f"start offset {start} out of range [0, {self.min_len})"}
        if end <= start:
            return {"error": f"end ({end}) must be greater than start ({start})"}
        
        actual_end = min(end, self.min_len)
        region_size = actual_end - start
        
        result = {
            "range": {"start": start, "end": actual_end, "size": region_size},
            "message_count": self.msg_count,
        }
        
        # 1. Constant byte analysis
        constant_positions = []
        for pos in range(start, actual_end):
            values = [m[pos] for m in self.messages]
            if len(set(values)) == 1:
                constant_positions.append({
                    "offset": pos,
                    "value": f"0x{values[0]:02X}"
                })
        
        result["constant_bytes"] = {
            "count": len(constant_positions),
            "ratio": round(len(constant_positions) / region_size, 3) if region_size > 0 else 0,
            "positions": constant_positions[:20]
        }
        
        # 2. Entropy distribution
        entropy_values = self.calculate_entropy_profile(start, actual_end)
        if entropy_values:
            avg_entropy = sum(entropy_values) / len(entropy_values)
            result["entropy"] = {
                "avg": round(avg_entropy, 3),
                "min": round(min(entropy_values), 3),
                "max": round(max(entropy_values), 3),
                "low_entropy_ratio": round(sum(1 for e in entropy_values if e < 1.0) / len(entropy_values), 3),
                "high_entropy_ratio": round(sum(1 for e in entropy_values if e > 6.0) / len(entropy_values), 3),
                "profile": entropy_values
            }
        
        # 3. Byte value distribution features
        all_bytes = []
        for m in self.messages:
            all_bytes.extend(m[start:actual_end])
        
        if all_bytes:
            byte_counter = Counter(all_bytes)
            unique_values = len(byte_counter)
            most_common = byte_counter.most_common(5)
            result["byte_distribution"] = {
                "unique_values": unique_values,
                "unique_ratio": round(unique_values / 256, 3),
                "most_common": [{"value": f"0x{v:02X}", "count": c, "ratio": round(c/len(all_bytes), 3)} 
                               for v, c in most_common]
            }
        
        # 4. Cross-message variation analysis
        position_variability = []
        for pos in range(start, actual_end):
            values = [m[pos] for m in self.messages]
            variability = len(set(values)) / self.msg_count if self.msg_count > 0 else 0
            position_variability.append(round(variability, 3))
        
        result["variability"] = {
            "avg": round(sum(position_variability) / len(position_variability), 3) if position_variability else 0,
            "profile": position_variability
        }
        
        # 5. Structure level assessment
        if entropy_values:
            avg_entropy = sum(entropy_values) / len(entropy_values)
            structure_score = 1.0 - (avg_entropy / 8.0)
            structure_score = max(0, min(1, structure_score))
            constant_ratio = len(constant_positions) / region_size if region_size > 0 else 0
            overall_structure = (structure_score * 0.6 + constant_ratio * 0.4)
            
            result["structure_assessment"] = {
                "score": round(overall_structure, 3),
                "interpretation": self._interpret_structure(overall_structure)
            }
        
        # 6. Multi-byte field candidates detection
        multi_byte_candidates = self._detect_multi_byte_fields(start, actual_end)
        if multi_byte_candidates:
            result["multi_byte_field_candidates"] = multi_byte_candidates
        
        return result
    
    def _detect_multi_byte_fields(self, start: int, end: int) -> List[Dict]:
        """
        Detect potential multi-byte fields (uint16, uint32) in the region.
        
        Looks for patterns like:
        - Adjacent bytes where one is constant (often 0x00) and other varies (common in little-endian addresses/IDs)
        - Byte pairs that change together across messages (same 16-bit value)
        - Values that look like small integers in 16-bit or 32-bit format
        """
        candidates = []
        
        # Check for uint16 candidates (2-byte fields)
        for pos in range(start, end - 1):
            byte1_values = [m[pos] for m in self.messages]
            byte2_values = [m[pos + 1] for m in self.messages]
            
            byte1_unique = len(set(byte1_values))
            byte2_unique = len(set(byte2_values))
            
            # Pattern 1: Little-endian small value (low byte varies, high byte is constant 0x00)
            # Common in address fields like 0x0001, 0x000A, etc.
            if byte2_unique == 1 and byte2_values[0] == 0x00 and 1 < byte1_unique <= 10:
                # Check if values look like sequential IDs or addresses
                uint16_le_values = sorted(set(byte1_values[i] | (byte2_values[i] << 8) 
                                              for i in range(len(self.messages))))
                if max(uint16_le_values) < 256:  # Small values, likely address/ID
                    candidates.append({
                        "offset": pos,
                        "size": 2,
                        "type": "uint16_le",
                        "confidence": 0.8,
                        "reason": "Low byte varies, high byte constant 0x00 (likely address/ID field)",
                        "sample_values": uint16_le_values[:5]
                    })
            
            # Pattern 2: Big-endian small value (high byte is constant 0x00, low byte varies)
            elif byte1_unique == 1 and byte1_values[0] == 0x00 and 1 < byte2_unique <= 10:
                uint16_be_values = sorted(set((byte1_values[i] << 8) | byte2_values[i] 
                                              for i in range(len(self.messages))))
                if max(uint16_be_values) < 256:
                    candidates.append({
                        "offset": pos,
                        "size": 2,
                        "type": "uint16_be",
                        "confidence": 0.8,
                        "reason": "High byte constant 0x00, low byte varies (likely address/ID field)",
                        "sample_values": uint16_be_values[:5]
                    })
            
            # Pattern 3: Both bytes vary but are correlated (same 16-bit value across messages)
            elif byte1_unique > 1 and byte2_unique > 1:
                # Check if they form consistent 16-bit values
                uint16_le_values = [byte1_values[i] | (byte2_values[i] << 8) 
                                   for i in range(len(self.messages))]
                uint16_be_values = [(byte1_values[i] << 8) | byte2_values[i] 
                                   for i in range(len(self.messages))]
                
                # Check for correlation: if 16-bit values have fewer unique values than individual bytes
                le_unique = len(set(uint16_le_values))
                be_unique = len(set(uint16_be_values))
                
                if le_unique < min(byte1_unique, byte2_unique) * 0.7:
                    candidates.append({
                        "offset": pos,
                        "size": 2,
                        "type": "uint16_le",
                        "confidence": 0.6,
                        "reason": "Bytes appear correlated as 16-bit little-endian value",
                        "sample_values": sorted(set(uint16_le_values))[:5]
                    })
                elif be_unique < min(byte1_unique, byte2_unique) * 0.7:
                    candidates.append({
                        "offset": pos,
                        "size": 2,
                        "type": "uint16_be",
                        "confidence": 0.6,
                        "reason": "Bytes appear correlated as 16-bit big-endian value",
                        "sample_values": sorted(set(uint16_be_values))[:5]
                    })
        
        # Remove overlapping candidates, prefer higher confidence
        if candidates:
            candidates.sort(key=lambda x: (-x["confidence"], x["offset"]))
            filtered = []
            used_offsets = set()
            for c in candidates:
                offsets_needed = set(range(c["offset"], c["offset"] + c["size"]))
                if not offsets_needed & used_offsets:
                    filtered.append(c)
                    used_offsets |= offsets_needed
            candidates = filtered
        
        return candidates
    
    def _interpret_structure(self, score: float) -> str:
        """Interpret structure level"""
        if score > 0.7:
            return "highly_structured (likely fixed header/metadata)"
        elif score > 0.4:
            return "moderately_structured (likely semi-fixed fields)"
        elif score > 0.2:
            return "weakly_structured (likely variable data with some patterns)"
        else:
            return "unstructured (likely payload/random/encrypted data)"
    
    # ========== Fine-grained Field Boundary Detection ==========
    
    def _find_message_type_field(self, max_offset: int = 8) -> Optional[Dict[str, Any]]:
        """
        Find a message type discriminator field in the first few bytes.
        
        A message type field typically has:
        1. Small number of unique values (2-10)
        2. Each value appears multiple times
        3. Located in first few bytes (usually byte 1 or 2)
        
        Returns:
            Dictionary with field info or None if not found
        """
        if not self.messages or self.msg_count < 10:
            return None
        
        best_candidate = None
        best_score = 0
        
        for pos in range(min(max_offset, self.min_len)):
            values = [m[pos] for m in self.messages]
            unique_values = set(values)
            unique_count = len(unique_values)
            
            # Look for 2-10 unique values (too few = constant, too many = variable data)
            if 2 <= unique_count <= 10:
                # Check if each value appears multiple times (not just noise)
                value_counts = {}
                for v in values:
                    value_counts[v] = value_counts.get(v, 0) + 1
                
                min_occurrences = min(value_counts.values())
                max_occurrences = max(value_counts.values())
                
                # Each type should appear at least a few times
                if min_occurrences >= 2:
                    # Score: prefer fewer unique values and more balanced distribution
                    balance = min_occurrences / max_occurrences
                    score = (1.0 / unique_count) * balance * 100
                    
                    if score > best_score:
                        best_score = score
                        best_candidate = {
                            "offset": pos,
                            "unique_values": sorted(unique_values),
                            "value_counts": value_counts,
                            "score": score
                        }
        
        return best_candidate
    
    def _analyze_by_message_type(self, type_field_offset: int, start: int, end: int) -> Dict[str, List[int]]:
        """
        Analyze field boundaries separately for each message type.
        
        Returns:
            Dictionary mapping message type value to detected boundaries
        """
        # Group messages by type
        type_groups = {}
        for msg in self.messages:
            type_val = msg[type_field_offset]
            if type_val not in type_groups:
                type_groups[type_val] = []
            type_groups[type_val].append(msg)
        
        results = {}
        for type_val, group_messages in type_groups.items():
            if len(group_messages) < 3:  # Need at least 3 messages for meaningful stats
                continue
            
            # Create a sub-analyzer for this group
            sub_analyzer = MessageAnalyzer(group_messages, self.max_header_size)
            sub_result = sub_analyzer._detect_boundaries_core(start, end)
            results[type_val] = sub_result.get("boundaries", [])
        
        return results
    
    def _merge_type_boundaries(self, type_boundaries: Dict[str, List[int]], type_counts: Dict[str, int]) -> List[int]:
        """
        Merge boundaries from different message types using intelligent voting.
        
        Strategy:
        1. Identify which message types are "structured" (fewer boundaries = more structured)
        2. Give higher weight to structured types
        3. Prefer boundaries that appear consistently across structured types
        """
        if not type_boundaries:
            return []
        
        # Calculate "structure score" for each type based on boundary density
        # Fewer boundaries = more structured = higher score
        type_scores = {}
        max_boundaries = max(len(b) for b in type_boundaries.values()) if type_boundaries else 1
        
        for type_val, boundaries in type_boundaries.items():
            # Score inversely proportional to boundary count
            density = len(boundaries) / max_boundaries if max_boundaries > 0 else 1
            # Types with fewer boundaries are more structured
            type_scores[type_val] = 1.0 - density + 0.1  # Add 0.1 to avoid zero weight
        
        # Identify "structured" types (those with below-average boundary count)
        avg_boundaries = sum(len(b) for b in type_boundaries.values()) / len(type_boundaries)
        structured_types = {t for t, b in type_boundaries.items() if len(b) <= avg_boundaries}
        
        # Count boundary votes with structure-weighted scoring
        boundary_votes = {}
        total_weight = sum(type_scores.values())
        
        for type_val, boundaries in type_boundaries.items():
            weight = type_scores[type_val] / total_weight
            for b in boundaries:
                if b not in boundary_votes:
                    boundary_votes[b] = {"total": 0.0, "structured": 0.0, "types": set()}
                boundary_votes[b]["total"] += weight
                boundary_votes[b]["types"].add(type_val)
                if type_val in structured_types:
                    boundary_votes[b]["structured"] += weight
        
        # Select boundaries based on multiple criteria
        merged = []
        for b, votes in boundary_votes.items():
            # Include if:
            # 1. High structured vote (appears in structured types)
            # 2. OR appears in multiple types (consensus)
            structured_threshold = 0.3  # Require support from structured types
            consensus_threshold = len(type_boundaries) // 2 + 1  # Majority of types
            
            if votes["structured"] >= structured_threshold or len(votes["types"]) >= consensus_threshold:
                merged.append(b)
        
        return sorted(set(merged))
    
    def detect_field_boundaries(self, start: int = 0, end: int = -1) -> Dict[str, Any]:
        """
        Detect fine-grained field boundaries based on byte variation patterns.
        
        This method analyzes byte-level patterns to suggest potential field boundaries:
        1. Changes in entropy level between adjacent bytes
        2. Changes in value variation patterns (constant vs variable)
        3. Common field size patterns (1, 2, 4 bytes)
        4. Multi-byte field detection (uint16, uint32)
        5. Message type-aware analysis for multi-type protocols
        
        Args:
            start: Start offset (inclusive)
            end: End offset (exclusive), -1 means min message length
            
        Returns:
            Dictionary with detected boundaries and field suggestions
        """
        if end == -1:
            end = min(self.min_len, self.max_header_size)
        end = min(end, self.min_len)
        
        if end <= start + 1:
            return {"error": "Range too small for boundary detection"}
        
        # Check if there's a message type field that could help with analysis
        type_field = self._find_message_type_field(max_offset=min(4, start + 1) if start > 0 else 4)
        
        if type_field and self.msg_count >= 20:
            # Multi-type protocol detected - analyze by type and merge results
            type_boundaries = self._analyze_by_message_type(
                type_field["offset"], start, end
            )
            
            if len(type_boundaries) > 1:
                # Merge boundaries from different types using intelligent voting
                merged_boundaries = self._merge_type_boundaries(
                    type_boundaries, 
                    type_field["value_counts"]
                )
                
                # For multi-type protocols, use ONLY the type-aware merged boundaries
                # Standard analysis would be polluted by high-entropy message types
                
                # Build result
                result = {
                    "range": {"start": start, "end": end},
                    "message_count": self.msg_count,
                    "boundaries": sorted(merged_boundaries),
                    "boundary_count": len(merged_boundaries),
                    "suggested_fields": [],  # Would need type-specific field suggestions
                    "summary": {
                        "multi_type_protocol": True,
                        "type_count": len(type_boundaries),
                        "boundaries_per_type": {str(k): len(v) for k, v in type_boundaries.items()}
                    },
                    "type_field_detected": {
                        "offset": type_field["offset"],
                        "unique_values": type_field["unique_values"]
                    }
                }
                
                return result
        
        # Single-type protocol or not enough messages - use standard analysis
        return self._detect_boundaries_core(start, end)
    
    def _detect_boundaries_core(self, start: int, end: int) -> Dict[str, Any]:
        """
        Core implementation of field boundary detection.
        
        This is the main algorithm that analyzes byte patterns to detect field boundaries.
        """
        result = {
            "range": {"start": start, "end": end},
            "message_count": self.msg_count,
            "boundaries": [],
            "suggested_fields": []
        }
        
        # Collect per-position statistics
        position_stats = []
        for pos in range(start, end):
            values = [m[pos] for m in self.messages]
            unique_values = set(values)
            stats = {
                "offset": pos,
                "unique_count": len(unique_values),
                "is_constant": len(unique_values) == 1,
                "constant_value": values[0] if len(unique_values) == 1 else None,
                "min_value": min(values),
                "max_value": max(values),
                "value_range": max(values) - min(values),
                "entropy": calculate_entropy(values),
                "is_zero_common": values.count(0) > len(values) * 0.8,
                "is_all_zero": all(v == 0 for v in values),
            }
            position_stats.append(stats)
        
        # Step 0: Detect protocol endianness to guide all subsequent analysis
        detected_endianness = self._detect_protocol_endianness(position_stats, start, end)
        # Store as instance attribute for use by other methods
        self.detected_endianness = detected_endianness
        
        # Step 1: First identify 1-byte constant/enum fields (these are clear boundaries)
        used_positions = set()
        suggested_fields = []
        
        # Pass 1: Mark clear 1-byte fields (constant or low-entropy enum-like)
        # BUT: defer constant bytes that might be part of uint16 fixed values
        # Use detected endianness to guide which patterns to defer
        deferred_uint16_positions = set()  # Track positions deferred for uint16 detection
        
        for pos in range(start, end):
            rel_pos = pos - start
            stats = position_stats[rel_pos]
            
            # Skip if this position is part of a deferred uint16
            if pos in deferred_uint16_positions:
                continue
            
            # Constant bytes - check if part of uint16 fixed value first
            if stats["is_constant"]:
                if pos + 1 < end:
                    next_stats = position_stats[rel_pos + 1]
                    
                    # Check for uint16_le fixed value pattern: [constant_nonzero, constant_zero]
                    # Only defer if endianness is LE or unknown
                    if detected_endianness in ("little", "unknown"):
                        if stats["constant_value"] != 0x00 and next_stats["is_constant"] and next_stats["constant_value"] == 0x00:
                            # This looks like a uint16_le fixed value, defer both bytes to Pass 2
                            deferred_uint16_positions.add(pos)
                            deferred_uint16_positions.add(pos + 1)
                            continue
                    
                    # Check for uint16_be fixed value pattern: [constant_zero, constant_nonzero]
                    # Only defer if endianness is BE or unknown
                    if detected_endianness in ("big", "unknown"):
                        if stats["constant_value"] == 0x00 and next_stats["is_constant"] and next_stats["constant_value"] != 0x00:
                            # This looks like a uint16_be fixed value, defer both bytes to Pass 2
                            deferred_uint16_positions.add(pos)
                            deferred_uint16_positions.add(pos + 1)
                            continue
                
                # Regular constant byte - mark as uint8
                field = self._create_uint8_field(stats, pos)
                suggested_fields.append(field)
                used_positions.add(pos)
            # Enum-like bytes (very few distinct values) are usually single fields
            # But only mark if truly enum-like (<=3 values), otherwise leave for multi-byte detection
            elif stats["unique_count"] <= 3:
                field = self._create_uint8_field(stats, pos)
                suggested_fields.append(field)
                used_positions.add(pos)
        
        # Pass 2: Try to detect 2-byte fields FIRST (more fine-grained)
        # This is important because many protocols use uint16_be for lengths/counts
        pos = start
        while pos <= end - 2:
            if pos in used_positions or pos + 1 in used_positions:
                pos += 1
                continue
                
            rel_pos = pos - start
            stats = position_stats[rel_pos:rel_pos + 2]
            
            if self._is_uint16_field(stats, pos):
                field = self._create_uint16_field(stats, pos)
                suggested_fields.append(field)
                used_positions.update(range(pos, pos + 2))
                pos += 2
            else:
                pos += 1
        
        # Pass 3: Try to detect 4-byte fields in remaining positions
        # Only use for clear 4-byte patterns (e.g., all zeros padding)
        pos = start
        while pos <= end - 4:
            if any(p in used_positions for p in range(pos, pos + 4)):
                pos += 1
                continue
                
            rel_pos = pos - start
            stats = position_stats[rel_pos:rel_pos + 4]
            
            if self._is_uint32_field_strict(stats, pos):
                field = self._create_uint32_field(stats, pos)
                suggested_fields.append(field)
                used_positions.update(range(pos, pos + 4))
                pos += 4
            else:
                pos += 1
        
        # Pass 4: Fill in remaining 1-byte fields
        for pos in range(start, end):
            if pos not in used_positions:
                rel_pos = pos - start
                stats = position_stats[rel_pos]
                field = self._create_uint8_field(stats, pos)
                suggested_fields.append(field)
        
        # Sort fields by offset
        suggested_fields.sort(key=lambda x: x["offset"])
        
        # Pass 5: Smart merge - combine adjacent constant/zero bytes into multi-byte fields
        merged_fields = self._smart_merge_fields(suggested_fields, position_stats, start)
        
        # Generate boundaries from fields
        boundaries = [start]
        for field in merged_fields:
            field_end = field["offset"] + field["size"]
            if field_end not in boundaries and field_end <= end:
                boundaries.append(field_end)
        if end not in boundaries:
            boundaries.append(end)
        boundaries.sort()
        
        result["boundaries"] = boundaries
        result["boundary_count"] = len(boundaries)
        result["suggested_fields"] = merged_fields
        result["detected_endianness"] = detected_endianness
        
        # Update and include metadata
        # Check for magic bytes (first field if it's a constant bytes type)
        if merged_fields and merged_fields[0].get("suggested_type") == "bytes":
            first_field = merged_fields[0]
            if first_field.get("is_constant") and "magic" in first_field.get("hint", "").lower():
                magic_value = "".join(f"{b:02X}" for b in self.messages[0][first_field["offset"]:first_field["offset"]+first_field["size"]])
                self.metadata.update_magic_bytes(
                    first_field["offset"], first_field["size"], f"0x{magic_value}",
                    source="detect_field_boundaries"
                )
        
        result["metadata"] = self.metadata.to_dict()
        result["metadata_context"] = self.metadata.to_llm_context()
        
        # Add summary
        constant_fields = sum(1 for f in merged_fields if f.get("is_constant", False))
        result["summary"] = {
            "total_fields_suggested": len(merged_fields),
            "constant_fields": constant_fields,
            "variable_fields": len(merged_fields) - constant_fields,
            "field_sizes": [f["size"] for f in merged_fields],
            "endianness": detected_endianness
        }
        
        return result
    
    def _is_ascii_letter_constant(self, field: Dict) -> bool:
        """Check if field is a constant ASCII letter (A-Z or a-z)."""
        hint = field.get("hint", "")
        if not hint.startswith("constant 0x"):
            return False
        try:
            # Extract hex value from hint like "constant 0x54"
            hex_str = hint.split("constant ")[1].split()[0]
            value = int(hex_str, 16)
            # Check if ASCII letter: A-Z (0x41-0x5A) or a-z (0x61-0x7A)
            return (0x41 <= value <= 0x5A) or (0x61 <= value <= 0x7A)
        except (IndexError, ValueError):
            return False
    
    def _is_constant_non_semantic(self, field: Dict, all_messages: List[bytes] = None) -> bool:
        """
        Check if a constant field has no obvious semantic meaning.
        
        A field is considered semantic if:
        - It correlates with message length
        - It looks like a version number (small values like 0x01-0x0F)
        - It's at a typical semantic position (offset 4-8 for type/version fields)
        
        Returns True if the field can be merged with magic, False otherwise.
        """
        if not field.get("is_constant", False):
            return False
        
        hint = field.get("hint", "")
        if not hint.startswith("constant 0x"):
            return False
        
        try:
            hex_str = hint.split("constant ")[1].split()[0]
            value = int(hex_str, 16)
        except (IndexError, ValueError):
            return False
        
        # Zero bytes are typically padding, can be merged
        if value == 0x00:
            return True
        
        # ASCII letters are part of magic
        if (0x41 <= value <= 0x5A) or (0x61 <= value <= 0x7A):
            return True
        
        # Small values (0x01-0x0F) at typical positions are likely version/type
        # Don't merge these
        offset = field.get("offset", 0)
        if value <= 0x0F and offset >= 4:
            return False
        
        # High values (>0x7F) that are not ASCII are likely part of magic prefix
        # e.g., 0xFE, 0xFF in SMB
        if value > 0x7F:
            return True
        
        # Values in printable ASCII range but not letters might be delimiters
        # Be conservative, don't merge
        if 0x20 <= value <= 0x7E:
            return False
        
        # Other constant values - allow merge if adjacent to magic
        return True
    
    def _smart_merge_fields(self, fields: List[Dict], position_stats: List[Dict], start: int) -> List[Dict]:
        """
        Smart merge adjacent fields that likely belong together.
        
        Merge rules:
        1. Adjacent constant ASCII letters + adjacent non-semantic constants -> magic/signature
        2. Adjacent constant zero bytes -> merge into uint16/uint32 padding
        3. Constant byte followed by variable byte -> potential uint16_be
        4. Variable byte followed by constant zero -> potential uint16_le
        5. Sequence of 4 related bytes -> potential uint32
        """
        if not fields:
            return fields
        
        merged = []
        i = 0
        
        while i < len(fields):
            current = fields[i]
            
            # === First pass: Try to merge magic/signature sequences ===
            # Look for patterns like [non-letter-constant] + [letters] or [letters] + [non-letter-constant]
            
            # Try 4-byte magic: check if contains ASCII letters and adjacent constants
            if i + 3 < len(fields):
                f1, f2, f3, f4 = fields[i:i+4]
                if (f1["size"] == 1 and f2["size"] == 1 and f3["size"] == 1 and f4["size"] == 1 and
                    f1["offset"] + 1 == f2["offset"] and f2["offset"] + 1 == f3["offset"] and 
                    f3["offset"] + 1 == f4["offset"]):
                    
                    # Count ASCII letters and non-semantic constants
                    letter_count = sum(1 for f in [f1, f2, f3, f4] if self._is_ascii_letter_constant(f))
                    non_semantic_count = sum(1 for f in [f1, f2, f3, f4] if self._is_constant_non_semantic(f))
                    
                    # If has letters and all are non-semantic constants -> magic
                    if letter_count >= 2 and non_semantic_count == 4:
                        merged.append({
                            "offset": f1["offset"],
                            "size": 4,
                            "suggested_type": "bytes",
                            "hint": "magic/signature (constant bytes with ASCII)",
                            "is_constant": True,
                            "avg_unique_values": 1.0
                        })
                        i += 4
                        continue
                    
                    # All zeros (padding)
                    all_zero = all(f.get("hint", "").startswith("constant 0x00") for f in [f1, f2, f3, f4])
                    if all_zero:
                        # Use detected endianness for padding
                        field_type = "uint32_le" if self.detected_endianness == "little" else "uint32_be"
                        merged.append({
                            "offset": f1["offset"],
                            "size": 4,
                            "suggested_type": field_type,
                            "hint": f"padding/reserved (all zeros, {self.detected_endianness} endian)",
                            "is_constant": True,
                            "avg_unique_values": 1.0
                        })
                        i += 4
                        continue
                    
                    # 3 zeros + 1 variable (big-endian small value)
                    three_zeros = sum(1 for f in [f1, f2, f3] if f.get("hint", "").startswith("constant 0x00"))
                    if three_zeros >= 2 and not f4.get("is_constant", True):
                        merged.append({
                            "offset": f1["offset"],
                            "size": 4,
                            "suggested_type": "uint32_be",
                            "hint": "32-bit big-endian (likely counter/ID)",
                            "is_constant": False,
                            "avg_unique_values": f4.get("avg_unique_values", 1)
                        })
                        i += 4
                        continue
                    
                    # 1 variable + 3 zeros (little-endian small value)
                    last_three_zeros = sum(1 for f in [f2, f3, f4] if f.get("hint", "").startswith("constant 0x00"))
                    if last_three_zeros >= 2 and not f1.get("is_constant", True):
                        merged.append({
                            "offset": f1["offset"],
                            "size": 4,
                            "suggested_type": "uint32_le",
                            "hint": "32-bit little-endian (likely counter/ID)",
                            "is_constant": False,
                            "avg_unique_values": f1.get("avg_unique_values", 1)
                        })
                        i += 4
                        continue
            
            # Try 3-byte magic
            if i + 2 < len(fields):
                f1, f2, f3 = fields[i:i+3]
                if (f1["size"] == 1 and f2["size"] == 1 and f3["size"] == 1 and
                    f1["offset"] + 1 == f2["offset"] and f2["offset"] + 1 == f3["offset"]):
                    
                    letter_count = sum(1 for f in [f1, f2, f3] if self._is_ascii_letter_constant(f))
                    non_semantic_count = sum(1 for f in [f1, f2, f3] if self._is_constant_non_semantic(f))
                    
                    if letter_count >= 2 and non_semantic_count == 3:
                        merged.append({
                            "offset": f1["offset"],
                            "size": 3,
                            "suggested_type": "bytes",
                            "hint": "magic/signature (constant bytes with ASCII)",
                            "is_constant": True,
                            "avg_unique_values": 1.0
                        })
                        i += 3
                        continue
            
            # Try 2-byte sequences
            if i + 1 < len(fields):
                f1, f2 = fields[i], fields[i+1]
                if f1["size"] == 1 and f2["size"] == 1 and f1["offset"] + 1 == f2["offset"]:
                    
                    # Both ASCII letters or (letter + non-semantic constant)
                    f1_letter = self._is_ascii_letter_constant(f1)
                    f2_letter = self._is_ascii_letter_constant(f2)
                    f1_non_semantic = self._is_constant_non_semantic(f1)
                    f2_non_semantic = self._is_constant_non_semantic(f2)
                    
                    # At least one letter and both are non-semantic -> magic part
                    if (f1_letter or f2_letter) and f1_non_semantic and f2_non_semantic:
                        merged.append({
                            "offset": f1["offset"],
                            "size": 2,
                            "suggested_type": "bytes",
                            "hint": "magic/signature (constant bytes)",
                            "is_constant": True,
                            "avg_unique_values": 1.0
                        })
                        i += 2
                        continue
                    
                    # Both zeros -> padding
                    both_zero = (f1.get("hint", "").startswith("constant 0x00") and 
                                f2.get("hint", "").startswith("constant 0x00"))
                    if both_zero:
                        # Use detected endianness for padding
                        field_type = "uint16_le" if self.detected_endianness == "little" else "uint16_be"
                        merged.append({
                            "offset": f1["offset"],
                            "size": 2,
                            "suggested_type": field_type,
                            "hint": f"padding/reserved (all zeros, {self.detected_endianness} endian)",
                            "is_constant": True,
                            "avg_unique_values": 1.0
                        })
                        i += 2
                        continue
                    
                    # Constant zero + variable -> big-endian uint16
                    if f1.get("hint", "").startswith("constant 0x00") and not f2.get("is_constant", True):
                        merged.append({
                            "offset": f1["offset"],
                            "size": 2,
                            "suggested_type": "uint16_be",
                            "hint": "16-bit big-endian (high byte is 0)",
                            "is_constant": False,
                            "avg_unique_values": f2.get("avg_unique_values", 1)
                        })
                        i += 2
                        continue
                    
                    # Variable + constant zero -> little-endian uint16
                    if not f1.get("is_constant", True) and f2.get("hint", "").startswith("constant 0x00"):
                        # Check if next field is also a constant zero
                        if i + 2 < len(fields):
                            f3 = fields[i + 2]
                            if f3.get("hint", "").startswith("constant 0x00") and f3["offset"] == f2["offset"] + 1:
                                # Pattern: [variable] [0x00] [0x00] - likely uint8 + uint16_be
                                merged.append(current)
                                i += 1
                                continue
                        
                        merged.append({
                            "offset": f1["offset"],
                            "size": 2,
                            "suggested_type": "uint16_le",
                            "hint": "16-bit little-endian (high byte is 0)",
                            "is_constant": False,
                            "avg_unique_values": f1.get("avg_unique_values", 1)
                        })
                        i += 2
                        continue
            
            # No merge possible, keep as-is
            merged.append(current)
            i += 1
        
        return merged
    
    def _is_uint32_field_strict(self, stats: List[Dict], offset: int) -> bool:
        """
        Strict check if 4 bytes look like a uint32 field.
        
        This is more conservative than _is_uint32_field and only returns True
        for very clear 4-byte patterns. This helps avoid incorrectly merging
        what should be 2x uint16 or uint16 + 2x uint8 fields.
        """
        if len(stats) < 4:
            return False
        
        # Clear pattern: All 4 bytes are constant zeros (padding/reserved)
        if all(s["is_all_zero"] for s in stats):
            return True
        
        # Clear pattern: First 3 bytes are zeros, last byte varies (big-endian small value)
        # This is a strong indicator of uint32_be
        zeros_at_start = sum(1 for s in stats[:3] if s["is_all_zero"])
        if zeros_at_start == 3 and not stats[3]["is_constant"]:
            return True
        
        # Clear pattern: Last 3 bytes are zeros, first byte varies (little-endian small value)
        # This is a strong indicator of uint32_le
        zeros_at_end = sum(1 for s in stats[1:] if s["is_all_zero"])
        if zeros_at_end == 3 and not stats[0]["is_constant"]:
            return True
        
        # Don't use entropy correlation for 4-byte detection - too error-prone
        # Let _smart_merge_fields handle merging smaller fields if needed
        return False
    
    def _is_uint32_field(self, stats: List[Dict], offset: int) -> bool:
        """Check if 4 bytes look like a uint32 field"""
        if len(stats) < 4:
            return False
        
        # All zeros = reserved/padding
        if all(s["is_all_zero"] for s in stats):
            return True
        
        # Check if it looks like a 32-bit value (common patterns)
        # Pattern: first 2-3 bytes are zero (big-endian small value)
        zeros_at_start = sum(1 for s in stats[:3] if s["is_all_zero"])
        if zeros_at_start >= 2 and not stats[3]["is_constant"]:
            return True
        
        # Pattern: last 2-3 bytes are zero (little-endian small value)
        zeros_at_end = sum(1 for s in stats[1:] if s["is_all_zero"])
        if zeros_at_end >= 2 and not stats[0]["is_constant"]:
            return True
        
        # Check if bytes are correlated (change together)
        if self._bytes_are_correlated(stats):
            return True
        
        return False
    
    def _detect_protocol_endianness(self, position_stats: List[Dict], start: int, end: int) -> str:
        """
        Detect the predominant endianness of the protocol by analyzing multi-byte patterns.
        
        Returns: "little", "big", or "unknown"
        
        Strategy:
        1. Count LE patterns: [nonzero_const, 0x00], [variable, all_zero]
        2. Count BE patterns: [0x00, nonzero_const], [all_zero, variable]
        3. Also analyze 16-bit value interpretations for variable pairs
        """
        le_score = 0
        be_score = 0
        
        # Scan for 2-byte patterns
        for pos in range(start, end - 1):
            rel_pos = pos - start
            stats0 = position_stats[rel_pos]
            stats1 = position_stats[rel_pos + 1]
            
            # Pattern 1: Fixed value patterns with one zero byte
            if stats0["is_constant"] and stats1["is_constant"]:
                v0 = stats0["constant_value"]
                v1 = stats1["constant_value"]
                
                # [nonzero, 0x00] -> LE fixed value
                if v0 != 0x00 and v1 == 0x00:
                    le_score += 2
                # [0x00, nonzero] -> BE fixed value
                elif v0 == 0x00 and v1 != 0x00:
                    be_score += 2
            
            # Pattern 2: Variable + zero patterns (common for small values)
            elif not stats0["is_constant"] and stats1["is_all_zero"]:
                # [variable, 0x00] -> LE small values
                le_score += 1
            elif stats0["is_all_zero"] and not stats1["is_constant"]:
                # [0x00, variable] -> BE small values
                be_score += 1
            
            # Pattern 3: Two variable bytes - check correlation via 16-bit interpretation
            elif not stats0["is_constant"] and not stats1["is_constant"]:
                # Calculate LE and BE 16-bit values
                le_values = []
                be_values = []
                for msg in self.messages:
                    b0 = msg[pos]
                    b1 = msg[pos + 1]
                    le_values.append(b0 | (b1 << 8))
                    be_values.append((b0 << 8) | b1)
                
                le_unique = len(set(le_values))
                be_unique = len(set(be_values))
                byte0_unique = stats0["unique_count"]
                byte1_unique = stats1["unique_count"]
                
                # If one interpretation gives significantly fewer unique values,
                # it's likely the correct endianness
                if le_unique < be_unique and le_unique < min(byte0_unique, byte1_unique):
                    le_score += 1
                elif be_unique < le_unique and be_unique < min(byte0_unique, byte1_unique):
                    be_score += 1
        
        # Determine result with a threshold
        total = le_score + be_score
        if total == 0:
            return "unknown"
        
        le_ratio = le_score / total
        if le_ratio >= 0.6:
            return "little"
        elif le_ratio <= 0.4:
            return "big"
        else:
            return "unknown"
    
    def _is_uint16_field(self, stats: List[Dict], offset: int) -> bool:
        """Check if 2 bytes look like a uint16 field"""
        if len(stats) < 2:
            return False
        
        # Both zeros = reserved/padding
        if stats[0]["is_all_zero"] and stats[1]["is_all_zero"]:
            return True
        
        # NEW: Two constant bytes forming a fixed uint16 value
        # Pattern: [constant_nonzero, constant_zero] = uint16_le fixed value (e.g., 64 = 0x0040)
        if stats[0]["is_constant"] and stats[1]["is_constant"]:
            if stats[0]["constant_value"] != 0x00 and stats[1]["constant_value"] == 0x00:
                return True
            # Pattern: [constant_zero, constant_nonzero] = uint16_be fixed value
            if stats[0]["constant_value"] == 0x00 and stats[1]["constant_value"] != 0x00:
                return True
        
        # Pattern: high byte zero, low byte varies (big-endian small value)
        if stats[0]["is_all_zero"] and not stats[1]["is_constant"]:
            return True
        
        # Pattern: low byte varies, high byte zero (little-endian small value)
        # BUT: check if next byte is also zero - if so, might be uint8 + uint16_be padding
        if stats[1]["is_all_zero"] and not stats[0]["is_constant"]:
            # Check if there's context to see the next byte
            if offset + 2 < self.min_len:
                next_values = [m[offset + 2] for m in self.messages]
                if all(v == 0 for v in next_values):
                    # Pattern: [variable] [0] [0] - likely uint8 + uint16_be, not uint16_le
                    return False
            return True
        
        # NOTE: We intentionally do NOT merge two non-zero constant bytes,
        # as they are often independent fields (e.g., magic + msg_type)
        
        # Check for correlation pattern (bytes change together)
        if not stats[0]["is_constant"] and not stats[1]["is_constant"]:
            # Calculate 16-bit values and check variance
            le_values = []
            be_values = []
            for i in range(len(self.messages)):
                b0 = self.messages[i][offset]
                b1 = self.messages[i][offset + 1]
                le_values.append(b0 | (b1 << 8))
                be_values.append((b0 << 8) | b1)
            
            le_unique = len(set(le_values))
            be_unique = len(set(be_values))
            byte0_unique = stats[0]["unique_count"]
            byte1_unique = stats[1]["unique_count"]
            
            # If 16-bit interpretation has fewer unique values, likely a 16-bit field
            if le_unique < byte0_unique and le_unique < byte1_unique:
                return True
            if be_unique < byte0_unique and be_unique < byte1_unique:
                return True
        
        return False
    
    def _bytes_are_correlated(self, stats: List[Dict]) -> bool:
        """Check if bytes in the region appear correlated (change together)"""
        # If all constant or all variable with similar entropy, might be correlated
        all_constant = all(s["is_constant"] for s in stats)
        if all_constant:
            return True
        
        # Check entropy similarity
        entropies = [s["entropy"] for s in stats]
        if entropies:
            avg_entropy = sum(entropies) / len(entropies)
            variance = sum((e - avg_entropy) ** 2 for e in entropies) / len(entropies)
            if variance < 0.5 and avg_entropy > 0:  # Similar entropy levels
                return True
        
        return False
    
    def _create_uint32_field(self, stats: List[Dict], offset: int) -> Dict:
        """Create a uint32 field suggestion, using detected_endianness as default"""
        all_zero = all(s["is_all_zero"] for s in stats)
        all_constant = all(s["is_constant"] for s in stats)
        
        # Default based on detected protocol endianness
        default_type = "uint32_le" if self.detected_endianness == "little" else "uint32_be"
        
        # Determine endianness from zero byte positions
        zeros_at_start = sum(1 for s in stats[:2] if s["is_all_zero"])
        zeros_at_end = sum(1 for s in stats[2:] if s["is_all_zero"])
        
        if zeros_at_start > zeros_at_end:
            field_type = "uint32_be"
        elif zeros_at_end > zeros_at_start:
            field_type = "uint32_le"
        else:
            # Equal or no zeros - use detected endianness
            field_type = default_type
        
        if all_zero:
            hint = f"padding/reserved (all zeros, {self.detected_endianness} endian)"
        elif all_constant:
            if self.detected_endianness == "little":
                const_val = sum(stats[i]["constant_value"] << (8 * i) for i in range(4))
                const_hex = f"{const_val:08X}"
            else:
                const_hex = "".join(f"{s['constant_value']:02X}" for s in stats)
            hint = f"constant 0x{const_hex} ({self.detected_endianness} endian)"
        else:
            hint = f"32-bit field ({self.detected_endianness} endian)"
        
        return {
            "offset": offset,
            "size": 4,
            "suggested_type": field_type,
            "hint": hint,
            "is_constant": all_constant,
            "avg_unique_values": round(sum(s["unique_count"] for s in stats) / 4, 1)
        }
    
    def _create_uint16_field(self, stats: List[Dict], offset: int) -> Dict:
        """Create a uint16 field suggestion, using detected_endianness as default"""
        all_zero = stats[0]["is_all_zero"] and stats[1]["is_all_zero"]
        all_constant = stats[0]["is_constant"] and stats[1]["is_constant"]
        
        # Default based on detected protocol endianness
        default_type = "uint16_le" if self.detected_endianness == "little" else "uint16_be"
        
        # Determine endianness - specific patterns override default
        if stats[0]["is_all_zero"] and not stats[1]["is_all_zero"]:
            field_type = "uint16_be"
            hint = "likely big-endian (high byte is 0)"
        elif stats[1]["is_all_zero"] and not stats[0]["is_all_zero"]:
            field_type = "uint16_le"
            hint = "likely little-endian (high byte is 0)"
        elif all_zero:
            # All zeros - use detected endianness
            field_type = default_type
            hint = f"padding/reserved (all zeros, {self.detected_endianness} endian)"
        elif all_constant:
            # Fixed uint16 value - determine endianness by the zero byte position
            if stats[1]["constant_value"] == 0x00 and stats[0]["constant_value"] != 0x00:
                # Pattern [nonzero, 0x00] = little-endian fixed value
                const_val = stats[0]["constant_value"] | (stats[1]["constant_value"] << 8)
                field_type = "uint16_le"
                hint = f"constant {const_val} (0x{const_val:04X} LE)"
            elif stats[0]["constant_value"] == 0x00 and stats[1]["constant_value"] != 0x00:
                # Pattern [0x00, nonzero] = big-endian fixed value
                const_val = (stats[0]["constant_value"] << 8) | stats[1]["constant_value"]
                field_type = "uint16_be"
                hint = f"constant {const_val} (0x{const_val:04X} BE)"
            else:
                # Both non-zero constants - use detected endianness
                if self.detected_endianness == "little":
                    const_val = stats[0]["constant_value"] | (stats[1]["constant_value"] << 8)
                    field_type = "uint16_le"
                    hint = f"constant 0x{const_val:04X} (LE)"
                else:
                    const_val = (stats[0]["constant_value"] << 8) | stats[1]["constant_value"]
                    field_type = "uint16_be"
                    hint = f"constant 0x{const_val:04X} (BE)"
        else:
            # Variable field - use detected endianness as default
            field_type = default_type
            hint = f"16-bit field ({self.detected_endianness} endian)"
        
        return {
            "offset": offset,
            "size": 2,
            "suggested_type": field_type,
            "hint": hint,
            "is_constant": all_constant,
            "avg_unique_values": round((stats[0]["unique_count"] + stats[1]["unique_count"]) / 2, 1)
        }
    
    def _create_uint8_field(self, stats: Dict, offset: int) -> Dict:
        """Create a uint8 field suggestion"""
        if stats["is_constant"]:
            hint = f"constant 0x{stats['constant_value']:02X}"
        elif stats["unique_count"] <= 5:
            hint = f"enum-like ({stats['unique_count']} distinct values)"
        else:
            hint = "variable"
        
        return {
            "offset": offset,
            "size": 1,
            "suggested_type": "uint8",
            "hint": hint,
            "is_constant": stats["is_constant"],
            "avg_unique_values": stats["unique_count"]
        }
    
    # ========== Boundary Search ==========
    
    def find_structure_boundary(self, search_start: int = 0, search_end: int = -1, 
                                window_size: int = 4) -> Dict[str, Any]:
        """
        Use sliding window to find positions with sudden structure level change (potential header/payload boundary)
        """
        if search_end == -1:
            search_end = self.min_len
        search_end = min(search_end, self.min_len)
        
        if search_end - search_start < window_size * 2:
            return {"error": "Search range too small for boundary detection"}
        
        # Calculate local entropy for each position
        local_entropy = self.calculate_entropy_profile(search_start, search_end)
        
        # Calculate average entropy within sliding window
        window_avg = []
        for i in range(len(local_entropy) - window_size + 1):
            avg = sum(local_entropy[i:i+window_size]) / window_size
            window_avg.append(round(avg, 3))
        
        # Find positions with significant entropy change
        boundaries = []
        for i in range(1, len(window_avg)):
            delta = window_avg[i] - window_avg[i-1]
            if abs(delta) > 1.0:
                boundaries.append({
                    "offset": search_start + i + window_size // 2,
                    "entropy_delta": round(delta, 3),
                    "direction": "increasing" if delta > 0 else "decreasing",
                    "interpretation": "structured_to_unstructured" if delta > 0 else "unstructured_to_structured"
                })
        
        boundaries.sort(key=lambda x: abs(x["entropy_delta"]), reverse=True)
        
        # Find constant region boundary
        constant_end = search_start
        for pos in range(search_start, search_end):
            values = [m[pos] for m in self.messages]
            if len(set(values)) > 1:
                break
            constant_end = pos + 1
        
        # Update metadata with detected boundary
        if boundaries:
            best_boundary = boundaries[0]
            if best_boundary["interpretation"] == "structured_to_unstructured":
                # Header ends, payload starts
                self.metadata.update_header_boundary(
                    best_boundary["offset"], has_payload=True,
                    source="find_structure_boundary"
                )
        
        result = {
            "entropy_boundaries": boundaries[:5],
            "constant_region_end": constant_end if constant_end > search_start else None,
            "window_entropy_profile": window_avg,
            "metadata": self.metadata.to_dict(),
            "metadata_context": self.metadata.to_llm_context()
        }
        
        return result
    
    # ========== Region Comparison ==========
    
    def compare_regions(self, region1: Tuple[int, int], region2: Tuple[int, int]) -> Dict[str, Any]:
        """Compare statistical feature differences between two regions"""
        analysis1 = self.analyze_region(region1[0], region1[1])
        analysis2 = self.analyze_region(region2[0], region2[1])
        
        if "error" in analysis1 or "error" in analysis2:
            return {"error": analysis1.get("error") or analysis2.get("error")}
        
        comparison = {
            "region1": {"start": region1[0], "end": region1[1]},
            "region2": {"start": region2[0], "end": region2[1]},
        }
        
        # Entropy comparison
        if "entropy" in analysis1 and "entropy" in analysis2:
            e1 = analysis1["entropy"]
            e2 = analysis2["entropy"]
            comparison["entropy_comparison"] = {
                "region1_avg": e1["avg"],
                "region2_avg": e2["avg"],
                "difference": round(e2["avg"] - e1["avg"], 3),
                "region1_more_structured": e1["avg"] < e2["avg"]
            }
        
        # Constant ratio comparison
        c1 = analysis1["constant_bytes"]["ratio"]
        c2 = analysis2["constant_bytes"]["ratio"]
        comparison["constant_ratio_comparison"] = {
            "region1": c1,
            "region2": c2,
            "difference": round(c1 - c2, 3)
        }
        
        # Structure score comparison
        if "structure_assessment" in analysis1 and "structure_assessment" in analysis2:
            s1 = analysis1["structure_assessment"]["score"]
            s2 = analysis2["structure_assessment"]["score"]
            comparison["structure_comparison"] = {
                "region1_score": s1,
                "region2_score": s2,
                "region1_interpretation": analysis1["structure_assessment"]["interpretation"],
                "region2_interpretation": analysis2["structure_assessment"]["interpretation"]
            }
        
        return comparison
    
    def compute_fingerprint(self) -> str:
        """Compute data fingerprint"""
        h = hashlib.md5()
        for msg in self.messages[:10]:
            h.update(msg[:32])
        return h.hexdigest()[:16]


@SkillRegistry.register
class ByteAnalysisSkill(Skill):
    """
    Byte Statistical Analysis Skill
    
    Provides analyze_bytes Tool with multiple analysis modes:
    - basic: Basic statistical analysis (constant bytes, length candidates, entropy distribution)
    - region: Detailed statistical features for specified range
    - boundary: Search for structure boundary
    - compare: Compare differences between two regions
    """
    
    name = "byte_analysis"
    description = "Byte-level statistical analysis for protocol messages"
    version = "1.0.0"
    phases = [SkillPhase.POST_EXTRACT, SkillPhase.PRE_ANALYSIS]
    priority = 20
    is_tool = True
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.min_messages = (config or {}).get("min_messages", 5)
        self.max_header_size = (config or {}).get("max_header_size", 64)
        self.use_cache = (config or {}).get("use_cache", True)
    
    # ========== Tool Interface ==========
    
    def get_tool_schema(self) -> ToolSchema:
        """Return Tool call schema"""
        return ToolSchema(
            name="analyze_bytes",
            description="""Perform byte-level statistical analysis on protocol messages, supporting multiple analysis modes.

[Analysis Modes]
- basic: Basic statistical analysis (default), returns constant bytes, length field candidates, entropy distribution for first N bytes
- pattern: Fine-grained field boundary detection based on byte variation patterns. HIGHLY RECOMMENDED for header analysis.
- region: Detailed statistics for specified range, includes structure score, variability analysis
- boundary: Search for header/payload boundary within specified range
- compare: Compare statistical feature differences between two regions

[When to Use]
- basic: Initial understanding of protocol structure features
- pattern: MUST USE before finalizing fields, especially for the first 16-32 bytes. Detects field boundaries based on entropy changes, constant/variable transitions, value range patterns.
- region: Verify whether a region is fixed header or variable payload
- boundary: When basic mode shows entropy changes, further locate the boundary
- compare: Compare features of different message regions

[Return Information]
- constant_bytes: Constant byte positions and ratio
- entropy_profile: Entropy distribution (low entropy=structured, high entropy=random)
- length_field_candidates: Possible length fields (basic mode only)
- structure_assessment: Structure level score (region mode only)
- boundaries: Detected field boundary positions (pattern mode)
- suggested_fields: Field suggestions with type hints (pattern mode)""",
            parameters={
                "type": "object",
                "properties": {
                    "mode": {
                        "type": "string",
                        "description": "Analysis mode: basic (basic statistics), pattern (field boundary detection - RECOMMENDED), region (region analysis), boundary (boundary search), compare (region comparison)",
                        "enum": ["basic", "pattern", "region", "boundary", "compare"],
                        "default": "basic"
                    },
                    "max_bytes": {
                        "type": "integer",
                        "description": "[basic mode] Analyze first N bytes of message, default 32",
                        "default": 32
                    },
                    "start": {
                        "type": "integer",
                        "description": "[region/boundary/compare mode] Analysis start offset, default 0",
                        "default": 0
                    },
                    "end": {
                        "type": "integer",
                        "description": "[region/boundary/compare mode] Analysis end offset, -1 means to message end",
                        "default": -1
                    },
                    "region2_start": {
                        "type": "integer",
                        "description": "[compare mode] Second region start offset"
                    },
                    "region2_end": {
                        "type": "integer",
                        "description": "[compare mode] Second region end offset"
                    },
                    "window_size": {
                        "type": "integer",
                        "description": "[boundary mode] Sliding window size, default 4",
                        "default": 4
                    },
                    "use_cache": {
                        "type": "boolean",
                        "description": "Whether to use cached results, default true",
                        "default": True
                    }
                },
                "required": []
            }
        )
    
    def invoke(self, context: SkillContext, **kwargs) -> Dict[str, Any]:
        """Tool invocation entry point"""
        mode = kwargs.get("mode", "basic")
        use_cache = kwargs.get("use_cache", self.use_cache)
        
        messages = context.messages
        if not messages:
            return {"error": "No messages available for analysis"}
        
        raw_messages = self._extract_raw_messages(messages)
        if not raw_messages:
            return {"error": "Could not extract raw message data"}
        
        analyzer = MessageAnalyzer(raw_messages, self.max_header_size)
        protocol = (context.protocol_type or "unknown").lower()
        
        if mode == "basic":
            return self._invoke_basic(analyzer, context, protocol, kwargs, use_cache)
        elif mode == "pattern":
            return self._invoke_pattern(analyzer, kwargs)
        elif mode == "region":
            return self._invoke_region(analyzer, kwargs)
        elif mode == "boundary":
            return self._invoke_boundary(analyzer, kwargs)
        elif mode == "compare":
            return self._invoke_compare(analyzer, kwargs)
        else:
            return {"error": f"Unknown mode: {mode}"}
    
    def _invoke_basic(self, analyzer: MessageAnalyzer, context: SkillContext, 
                      protocol: str, kwargs: Dict, use_cache: bool) -> Dict[str, Any]:
        """Basic statistical analysis"""
        max_bytes = kwargs.get("max_bytes", 32)
        
        # Try to use cache
        if use_cache:
            cached = load_cache(protocol)
            if cached:
                return {
                    "mode": "basic",
                    "source": "cache",
                    **self._format_basic_result(cached, max_bytes)
                }
        
        # Execute analysis
        old_max = analyzer.max_header_size
        analyzer.max_header_size = max_bytes
        
        analysis = {
            "message_count": analyzer.msg_count,
            "constant_bytes": analyzer.find_constant_bytes(0, max_bytes),
            "length_candidates": analyzer.find_length_fields(),
            "entropy_profile": analyzer.calculate_entropy_profile(0, max_bytes),
            "message_lengths": analyzer.analyze_lengths(),
            "endianness_hints": analyzer.detect_endianness_hints(0, max_bytes),
        }
        
        analyzer.max_header_size = old_max
        
        # Save to context
        context.metadata["byte_analysis"] = analysis
        context.metadata["byte_analysis_cached"] = False
        
        # Save to cache
        if use_cache and protocol != "unknown":
            analysis["data_fingerprint"] = analyzer.compute_fingerprint()
            save_cache(protocol, analysis)
        
        return {
            "mode": "basic",
            "source": "analyzed",
            **self._format_basic_result(analysis, max_bytes)
        }
    
    def _invoke_pattern(self, analyzer: MessageAnalyzer, kwargs: Dict) -> Dict[str, Any]:
        """Fine-grained field boundary detection"""
        start = kwargs.get("start", 0)
        end = kwargs.get("end", -1)
        max_bytes = kwargs.get("max_bytes", 32)
        
        # If end not specified, use max_bytes
        if end == -1:
            end = start + max_bytes
        
        result = analyzer.detect_field_boundaries(start, end)
        result["mode"] = "pattern"
        
        # Add actionable recommendations
        if "suggested_fields" in result and result["suggested_fields"]:
            recommendations = []
            for field in result["suggested_fields"]:
                if field["size"] >= 8 and not field["is_constant"]:
                    recommendations.append(
                        f"Field at offset {field['offset']} ({field['size']} bytes) may need further analysis"
                    )
            if recommendations:
                result["recommendations"] = recommendations
        
        return result
    
    def _format_basic_result(self, analysis: Dict, max_bytes: int) -> Dict[str, Any]:
        """Format basic analysis result"""
        result = {
            "message_count": analysis.get("message_count", 0),
            "analyzed_bytes": max_bytes,
        }
        
        # Message lengths
        lengths = analysis.get("message_lengths", {})
        if lengths:
            result["message_lengths"] = {
                "min": lengths.get("min"),
                "max": lengths.get("max"),
                "is_fixed": lengths.get("is_fixed", False)
            }
        
        # Constant bytes
        constants = analysis.get("constant_bytes", [])
        if constants:
            result["constant_bytes"] = [
                {"offset": c["offset"], "value": c["hex"]}
                for c in constants
            ]
        
        # Length field candidates
        candidates = analysis.get("length_candidates", [])
        if candidates:
            result["length_field_candidates"] = [
                {"offset": c["offset"], "type": c["type"], "confidence": round(c["confidence"], 2)}
                for c in candidates
            ]
        
        # Entropy analysis
        entropy = analysis.get("entropy_profile", [])
        if entropy:
            result["entropy_profile"] = [round(e, 2) for e in entropy[:max_bytes]]
            
            # Find positions with significant entropy change
            jumps = []
            for i in range(1, min(len(entropy), max_bytes)):
                if abs(entropy[i] - entropy[i-1]) > 1.5:
                    jumps.append({"offset": i, "delta": round(entropy[i] - entropy[i-1], 2)})
            if jumps:
                result["entropy_jumps"] = jumps
            
            # Mark low and high entropy regions
            low_entropy_offsets = [i for i, e in enumerate(entropy[:max_bytes]) if e < 1.0]
            high_entropy_offsets = [i for i, e in enumerate(entropy[:max_bytes]) if e > 6.0]
            if low_entropy_offsets:
                result["low_entropy_offsets"] = low_entropy_offsets
            if high_entropy_offsets:
                result["high_entropy_offsets"] = high_entropy_offsets
        
        # Endianness hints
        endianness = analysis.get("endianness_hints", {})
        if endianness and endianness.get("suggested") != "unknown":
            result["endianness_hints"] = {
                "suggested": endianness.get("suggested"),
                "confidence": endianness.get("confidence"),
                "reasons": endianness.get("reasons", [])
            }
        
        return result
    
    def _invoke_region(self, analyzer: MessageAnalyzer, kwargs: Dict) -> Dict[str, Any]:
        """Region analysis"""
        start = kwargs.get("start", 0)
        end = kwargs.get("end", -1)
        result = analyzer.analyze_region(start, end)
        result["mode"] = "region"
        return result
    
    def _invoke_boundary(self, analyzer: MessageAnalyzer, kwargs: Dict) -> Dict[str, Any]:
        """Boundary search"""
        start = kwargs.get("start", 0)
        end = kwargs.get("end", -1)
        window_size = kwargs.get("window_size", 4)
        result = analyzer.find_structure_boundary(start, end, window_size)
        result["mode"] = "boundary"
        return result
    
    def _invoke_compare(self, analyzer: MessageAnalyzer, kwargs: Dict) -> Dict[str, Any]:
        """Region comparison"""
        start = kwargs.get("start", 0)
        end = kwargs.get("end", -1)
        region2_start = kwargs.get("region2_start")
        region2_end = kwargs.get("region2_end")
        
        if region2_start is None or region2_end is None:
            return {"error": "compare mode requires region2_start and region2_end"}
        
        result = analyzer.compare_regions((start, end), (region2_start, region2_end))
        result["mode"] = "compare"
        return result
    
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
    
    # ========== Phase-based Execution ==========
    
    def execute(self, context: SkillContext, phase: SkillPhase) -> SkillResult:
        if phase == SkillPhase.POST_EXTRACT:
            return self._analyze_or_load_cache(context)
        elif phase == SkillPhase.PRE_ANALYSIS:
            return SkillResult(success=True, modified=False)
        return SkillResult(success=True, modified=False)
    
    def _analyze_or_load_cache(self, context: SkillContext) -> SkillResult:
        """Analyze or load cache"""
        protocol = (context.protocol_type or "unknown").lower()
        
        # Try to load cache
        if self.use_cache:
            cached = load_cache(protocol)
            if cached:
                context.metadata["byte_analysis"] = cached
                context.metadata["byte_analysis_cached"] = True
                logging.info(f"Byte analysis loaded from cache: {protocol}")
                return SkillResult(
                    success=True,
                    modified=True,
                    message=f"Loaded cached byte analysis for {protocol}",
                    data={"cached": True, "protocol": protocol}
                )
        
        # No cache, execute analysis
        messages = context.messages
        if not messages or len(messages) < self.min_messages:
            return SkillResult(
                success=True,
                modified=False,
                message=f"Not enough messages ({len(messages) if messages else 0} < {self.min_messages})"
            )
        
        raw_messages = self._extract_raw_messages(messages)
        if not raw_messages:
            return SkillResult(success=True, modified=False, message="No raw data")
        
        analyzer = MessageAnalyzer(raw_messages, self.max_header_size)
        
        analysis = {
            "protocol": protocol,
            "message_count": analyzer.msg_count,
            "constant_bytes": analyzer.find_constant_bytes(),
            "length_candidates": analyzer.find_length_fields(),
            "entropy_profile": analyzer.calculate_entropy_profile(),
            "message_lengths": analyzer.analyze_lengths(),
            "data_fingerprint": analyzer.compute_fingerprint(),
        }
        
        context.metadata["byte_analysis"] = analysis
        context.metadata["byte_analysis_cached"] = False
        
        if self.use_cache and protocol != "unknown":
            if save_cache(protocol, analysis):
                logging.info(f"Byte analysis cached: {protocol}")
        
        return SkillResult(
            success=True,
            modified=True,
            message=f"Byte analysis complete for {protocol}",
            data={"cached": False, "protocol": protocol}
        )
    
    def get_prompt_enhancement(self, context: SkillContext) -> str:
        """Generate prompt enhancement based on cache/analysis"""
        analysis = context.metadata.get("byte_analysis", {})
        if not analysis:
            return ""
        
        cached = context.metadata.get("byte_analysis_cached", False)
        source = "(cached)" if cached else "(analyzed)"
        
        lines = [f"## Statistical Observations {source}", ""]
        
        lengths = analysis.get("message_lengths", {})
        if lengths:
            if lengths.get("is_fixed"):
                lines.append(f"- Message length: fixed {lengths['min']} bytes")
            else:
                lines.append(f"- Message length: {lengths['min']}-{lengths['max']} bytes ({lengths['unique_count']} unique)")
        
        constants = analysis.get("constant_bytes", [])
        if constants:
            const_str = ", ".join([f"{c['offset']}:{c['hex']}" for c in constants[:6]])
            lines.append(f"- Constant positions: {const_str}")
        
        candidates = analysis.get("length_candidates", [])
        if candidates:
            cand_str = ", ".join([f"@{c['offset']}({c['confidence']:.0%})" for c in candidates[:3]])
            lines.append(f"- Length-correlated: {cand_str}")
        
        entropy = analysis.get("entropy_profile", [])
        if entropy:
            jumps = [str(i) for i in range(1, min(len(entropy), 32))
                    if abs(entropy[i] - entropy[i-1]) > 1.5]
            if jumps:
                lines.append(f"- Entropy changes: offset {', '.join(jumps[:5])}")
        
        return "\n".join(lines)


# Convenience functions
def get_cached_analysis(protocol: str) -> Optional[Dict]:
    """Get cached analysis result"""
    return load_cache(protocol)


def invalidate_cache(protocol: str = None) -> int:
    """Invalidate cache"""
    return clear_cache(protocol)


def analyze_message_region(messages: List[bytes], start: int, end: int = -1) -> Dict[str, Any]:
    """Analyze statistical features of message region"""
    analyzer = MessageAnalyzer(messages)
    return analyzer.analyze_region(start, end)


def find_header_payload_boundary(messages: List[bytes], max_search: int = 64) -> Dict[str, Any]:
    """Search for header/payload boundary"""
    analyzer = MessageAnalyzer(messages)
    return analyzer.find_structure_boundary(0, max_search)
