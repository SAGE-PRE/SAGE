#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Protocol Analysis Tool - Conversational Agent

Performs protocol analysis through multi-turn conversations:
- LLM acts as decision maker, calling Skills (as Tools) on demand
- Dynamically adjusts analysis strategy based on Tool results
- Supports intermediate validation and iterative optimization
"""

import argparse
import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import common message processing module
try:
    from utils.message_processor import (
        PCAPProcessor,
        infer_protocol_from_filename,
        NETZOB_AVAILABLE,
    )
except ImportError:
    # Fallback to direct import
    from utils.pcap_extractor import (
        infer_protocol_from_filename,
        NETZOB_AVAILABLE,
    )
    PCAPProcessor = None

# Import unified LLM client
try:
    from utils.llm_client import (
        LLMClient, GEMINI_AVAILABLE, check_api_key_configured,
        DEFAULT_MODEL_NAME,
        PROVIDER_GEMINI, PROVIDER_DEEPSEEK, detect_provider
    )
except ImportError:
    GEMINI_AVAILABLE = False
    LLMClient = None
    DEFAULT_MODEL_NAME = 'gemini-2.5-pro'
    PROVIDER_GEMINI = "gemini"
    PROVIDER_DEEPSEEK = "deepseek"
    
    def check_api_key_configured(provider=None):
        return bool(os.getenv('GEMINI_API_KEY'))
    
    def detect_provider(model_name):
        return PROVIDER_GEMINI

# Import Skills mechanism
try:
    from skills import SkillManager, SkillContext
    SKILLS_AVAILABLE = True
except ImportError:
    SKILLS_AVAILABLE = False
    SkillManager = None
    SkillContext = None


# ============================================================================
# Convergence Detection
# ============================================================================

class ConvergenceDetector:
    """
    Convergence Detector for Protocol Analysis
    
    Detects when the analysis should stop based on:
    1. Boundary stability: consecutive rounds with same boundary set
    2. Diminishing information gain: tool calls no longer produce new info
    3. Oscillation detection: LLM cycling between 2-3 states
    
    IMPORTANT: Convergence is BLOCKED when payload analysis is pending.
    """
    
    def __init__(self, 
                 stability_window: int = 2,      # Consecutive rounds for stability
                 min_info_gain: float = 0.5,     # Minimum info gain threshold
                 gain_window: int = 3,           # Window for info gain averaging
                 oscillation_window: int = 6,    # Window for oscillation detection
                 max_oscillation_rounds: int = 8):  # Max rounds before forcing convergence
        
        self.boundary_history: List[set] = []
        self.validation_history: List[Dict] = []
        self.info_gains: List[float] = []
        
        # Known information for info gain calculation
        self.known_boundaries: set = set()
        self.known_constants: set = set()
        self._endianness_known: bool = False
        
        # Configuration
        self.stability_window = stability_window
        self.min_info_gain = min_info_gain
        self.gain_window = gain_window
        self.oscillation_window = oscillation_window
        self.max_oscillation_rounds = max_oscillation_rounds
        
        # Oscillation tracking
        self._oscillation_detected_at: Optional[int] = None
        
        # Convergence result
        self.converged: bool = False
        self.convergence_reason: str = ""
        self.final_boundaries: Optional[set] = None
        self.selection_confidence: float = 1.0  # Confidence in selected hypothesis (0-1)
        
        # Payload analysis blocking flag
        self.payload_analysis_required: bool = False
        self.payload_analysis_completed: bool = False
        self.payload_result_reviewed: bool = False  # LLM has seen the payload analysis results
    
    def extract_boundaries(self, hypothesis: Dict) -> set:
        """Extract boundary set from hypothesis (field definitions)"""
        boundaries = set()
        for field in hypothesis.get('fields', []):
            offset = field.get('offset')
            if isinstance(offset, int):
                boundaries.add(offset)
        return boundaries
    
    def compute_info_gain(self, tool_name: str, tool_result: Dict) -> float:
        """Compute information gain from a tool call result
        
        IMPORTANT: When payload analysis is suggested by validation warnings,
        this adds a large info gain to PREVENT early convergence.
        """
        new_info = 0.0
        
        if tool_name == "analyze_bytes":
            # New constant byte positions (constant_bytes is list of dicts with 'offset' key)
            constant_bytes = tool_result.get('constant_bytes', [])
            if constant_bytes and isinstance(constant_bytes[0], dict):
                constants = {c['offset'] for c in constant_bytes}
            else:
                constants = set(constant_bytes) if constant_bytes else set()
            new_constants = constants - self.known_constants
            new_info += len(new_constants)
            self.known_constants.update(constants)
            
            # New length field candidates (higher weight)
            length_candidates = {c['offset'] for c in tool_result.get('length_field_candidates', [])}
            new_boundaries = length_candidates - self.known_boundaries
            new_info += len(new_boundaries) * 2
            self.known_boundaries.update(length_candidates)
            
            # Boundary mode: suggested boundary (highest weight)
            if tool_result.get('mode') == 'boundary':
                suggested = tool_result.get('suggested_boundary')
                if suggested and suggested not in self.known_boundaries:
                    new_info += 3
                    self.known_boundaries.add(suggested)
        
        elif tool_name == "detect_tlv":
            if tool_result.get('is_tlv') and tool_result.get('tlv_structure'):
                tlv_boundaries = set(tool_result['tlv_structure'].get('boundaries', []))
                new_boundaries = tlv_boundaries - self.known_boundaries
                new_info += len(new_boundaries) * 2
                self.known_boundaries.update(tlv_boundaries)
        
        elif tool_name == "detect_endianness":
            # Endianness info only valuable the first time
            if not self._endianness_known:
                self._endianness_known = True
                new_info += 1
        
        elif tool_name == "validate_fields":
            # Check for payload analysis warnings - these indicate MORE work is needed
            warnings = tool_result.get('warnings', [])
            payload_warnings = [w for w in warnings if 
                               'payload' in w.lower() or 
                               ('large' in w.lower() and 'bytes' in w.lower()) or
                               'internal structure' in w.lower()]
            
            if payload_warnings:
                # Add high info gain to PREVENT convergence
                new_info += 5 * len(payload_warnings)
                self.payload_analysis_required = True
                logging.info(f"Payload analysis required: {len(payload_warnings)} warning(s) detected")
        
        return new_info
    
    def mark_payload_analysis_done(self):
        """Mark payload analysis as completed (called after region analysis on payload)"""
        self.payload_analysis_completed = True
        logging.info("Payload analysis marked as completed")
    
    def mark_payload_result_reviewed(self):
        """Mark that LLM has reviewed the payload analysis results"""
        if self.payload_analysis_completed and not self.payload_result_reviewed:
            self.payload_result_reviewed = True
            logging.info("Payload analysis results marked as reviewed by LLM (convergence detector)")
    
    def update(self, hypothesis: Dict = None, 
               validation_result: Dict = None,
               tool_name: str = None, 
               tool_result: Dict = None):
        """Update detector state after each turn"""
        # Record boundary history
        if hypothesis:
            boundaries = self.extract_boundaries(hypothesis)
            self.boundary_history.append(boundaries)
        
        # Record validation history
        if validation_result:
            self.validation_history.append(validation_result)
        
        # Record information gain
        if tool_name and tool_result:
            gain = self.compute_info_gain(tool_name, tool_result)
            self.info_gains.append(gain)
            logging.debug(f"Info gain from {tool_name}: {gain}")
    
    def should_converge(self) -> tuple:
        """
        Check if analysis should converge
        
        IMPORTANT: Convergence is BLOCKED when:
        1. Payload analysis is required but not completed
        2. Payload analysis is completed but LLM hasn't reviewed the results yet
        
        Returns:
            (converged: bool, reason: str, boundaries: set)
        """
        current = self.boundary_history[-1] if self.boundary_history else set()
        
        # BLOCK convergence if payload analysis is required but not completed
        if self.payload_analysis_required and not self.payload_analysis_completed:
            logging.debug("Convergence blocked: payload analysis required but not completed")
            return False, "payload_analysis_pending", current
        
        # BLOCK convergence if payload analysis completed but results not reviewed by LLM
        if self.payload_analysis_required and self.payload_analysis_completed and not self.payload_result_reviewed:
            logging.debug("Convergence blocked: payload results not yet reviewed by LLM")
            return False, "payload_result_pending_review", current
        
        # Condition 1: Stable convergence - consecutive N rounds with same boundaries
        if self._is_stable():
            self.converged = True
            self.convergence_reason = "boundary_stable"
            self.final_boundaries = current
            return True, "boundary_stable", current
        
        # Condition 2: Diminishing information gain
        if self._is_diminishing():
            self.converged = True
            self.convergence_reason = "diminishing_info_gain"
            self.final_boundaries = current
            return True, "diminishing_info_gain", current
        
        # Condition 3: Oscillation detection and resolution
        if self._is_oscillating():
            if self._oscillation_detected_at is None:
                self._oscillation_detected_at = len(self.boundary_history)
                logging.info(f"Oscillation detected at round {self._oscillation_detected_at}")
            
            # Check if oscillation has persisted too long
            rounds_since = len(self.boundary_history) - self._oscillation_detected_at
            if rounds_since >= self.max_oscillation_rounds:
                best, confidence, selection_reason = self._resolve_oscillation()
                self.converged = True
                self.convergence_reason = f"oscillation_resolved|conf={confidence:.2f}|{selection_reason}"
                self.final_boundaries = best
                self.selection_confidence = confidence
                logging.info(f"Oscillation resolved after {rounds_since} rounds, best boundaries: {best}, confidence: {confidence:.2f}")
                return True, "oscillation_resolved", best
        else:
            # Reset oscillation tracking if no longer oscillating
            self._oscillation_detected_at = None
        
        return False, "continue", current
    
    def _is_stable(self) -> bool:
        """Check if boundaries have been stable for N consecutive rounds"""
        if len(self.boundary_history) < self.stability_window:
            return False
        
        recent = self.boundary_history[-self.stability_window:]
        return all(b == recent[0] for b in recent)
    
    def _is_diminishing(self) -> bool:
        """Check if information gain has diminished below threshold"""
        if len(self.info_gains) < self.gain_window:
            return False
        
        avg_gain = sum(self.info_gains[-self.gain_window:]) / self.gain_window
        return avg_gain < self.min_info_gain
    
    def _is_oscillating(self) -> bool:
        """Check if LLM is oscillating between 2-3 states"""
        if len(self.boundary_history) < self.oscillation_window:
            return False
        
        recent = [frozenset(b) for b in self.boundary_history[-self.oscillation_window:]]
        state_counts = {}
        for s in recent:
            state_counts[s] = state_counts.get(s, 0) + 1
        
        num_unique = len(state_counts)
        # Oscillation: 2-3 unique states, each appearing at least twice
        return (num_unique >= 2 and 
                num_unique <= 3 and 
                all(c >= 2 for c in state_counts.values()))
    
    def _resolve_oscillation(self) -> tuple:
        """
        Resolve oscillation by selecting the best candidate using hybrid strategy
        
        Returns:
            (best_boundaries: set, confidence: float, selection_reason: str)
        """
        recent = [frozenset(b) for b in self.boundary_history[-self.oscillation_window:]]
        candidates = list(set(recent))
        
        if len(candidates) == 1:
            return set(candidates[0]), 1.0, "single_candidate"
        
        # Score each candidate using multiple criteria
        candidate_scores = {}
        for c in candidates:
            candidate_scores[c] = {
                'validation_score': 0.0,
                'frequency_score': 0.0,
                'conservatism_score': 0.0,
                'total_score': 0.0,
                'reasons': []
            }
        
        # ============================================================
        # Strategy 1: Validation-based scoring (weight: 0.5)
        # Lower errors = higher score
        # ============================================================
        if self.validation_history:
            window_start = len(self.boundary_history) - self.oscillation_window
            candidate_validation = {c: {'errors': float('inf'), 'warnings': float('inf')} for c in candidates}
            
            for i, b in enumerate(self.boundary_history[-self.oscillation_window:]):
                idx = window_start + i
                if idx < len(self.validation_history):
                    v = self.validation_history[idx]
                    fb = frozenset(b)
                    errors = len(v.get('errors', []))
                    warnings = len(v.get('warnings', []))
                    # Keep the best (lowest) scores for each candidate
                    if errors < candidate_validation[fb]['errors'] or \
                       (errors == candidate_validation[fb]['errors'] and warnings < candidate_validation[fb]['warnings']):
                        candidate_validation[fb] = {'errors': errors, 'warnings': warnings}
            
            # Calculate validation score (normalized)
            max_errors = max(cv['errors'] for cv in candidate_validation.values() if cv['errors'] != float('inf'))
            max_errors = max(max_errors, 1)  # Avoid division by zero
            
            for c in candidates:
                cv = candidate_validation[c]
                if cv['errors'] != float('inf'):
                    # Invert: fewer errors = higher score
                    validation_score = 1.0 - (cv['errors'] / (max_errors + 1))
                    candidate_scores[c]['validation_score'] = validation_score
                    if cv['errors'] == 0:
                        candidate_scores[c]['reasons'].append(f"passed_validation")
                    else:
                        candidate_scores[c]['reasons'].append(f"{cv['errors']}_errors")
        
        # ============================================================
        # Strategy 2: Frequency-based scoring (weight: 0.3)
        # More frequent = more stable hypothesis
        # ============================================================
        counts = {c: recent.count(c) for c in candidates}
        max_count = max(counts.values())
        
        for c in candidates:
            frequency_score = counts[c] / max_count
            candidate_scores[c]['frequency_score'] = frequency_score
            candidate_scores[c]['reasons'].append(f"freq_{counts[c]}/{len(recent)}")
        
        # ============================================================
        # Strategy 3: Conservatism-based scoring (weight: 0.2)
        # Fewer boundaries = more conservative (less likely to over-segment)
        # ============================================================
        boundary_counts = {c: len(c) for c in candidates}
        min_boundaries = min(boundary_counts.values())
        max_boundaries = max(boundary_counts.values())
        boundary_range = max_boundaries - min_boundaries if max_boundaries > min_boundaries else 1
        
        for c in candidates:
            # Prefer fewer boundaries (normalized score where fewer = higher)
            conservatism_score = 1.0 - (boundary_counts[c] - min_boundaries) / boundary_range if boundary_range > 0 else 1.0
            candidate_scores[c]['conservatism_score'] = conservatism_score
            candidate_scores[c]['reasons'].append(f"{boundary_counts[c]}_boundaries")
        
        # ============================================================
        # Calculate weighted total score
        # ============================================================
        WEIGHT_VALIDATION = 0.5
        WEIGHT_FREQUENCY = 0.3
        WEIGHT_CONSERVATISM = 0.2
        
        for c in candidates:
            scores = candidate_scores[c]
            scores['total_score'] = (
                scores['validation_score'] * WEIGHT_VALIDATION +
                scores['frequency_score'] * WEIGHT_FREQUENCY +
                scores['conservatism_score'] * WEIGHT_CONSERVATISM
            )
        
        # Select best candidate
        best_candidate = max(candidates, key=lambda x: candidate_scores[x]['total_score'])
        best_scores = candidate_scores[best_candidate]
        
        # Calculate confidence based on score margin
        sorted_scores = sorted([candidate_scores[c]['total_score'] for c in candidates], reverse=True)
        if len(sorted_scores) > 1:
            score_margin = sorted_scores[0] - sorted_scores[1]
            # Confidence: high margin = high confidence
            confidence = min(0.5 + score_margin, 1.0)
        else:
            confidence = 1.0
        
        # Build selection reason
        selection_reason = f"score={best_scores['total_score']:.2f}|" + "|".join(best_scores['reasons'])
        
        # Log detailed scoring for debugging
        logging.info(f"Oscillation resolution - candidates: {len(candidates)}")
        for c in candidates:
            s = candidate_scores[c]
            logging.info(f"  {set(c)}: total={s['total_score']:.3f} "
                        f"(val={s['validation_score']:.2f}, freq={s['frequency_score']:.2f}, cons={s['conservatism_score']:.2f})")
        logging.info(f"  Selected: {set(best_candidate)} with confidence {confidence:.2f}")
        
        return set(best_candidate), confidence, selection_reason
    
    def get_status_summary(self) -> str:
        """Get a summary of convergence status for logging"""
        lines = [
            f"Boundary history length: {len(self.boundary_history)}",
            f"Info gains: {self.info_gains[-5:] if self.info_gains else []}",
            f"Oscillation detected: {self._oscillation_detected_at is not None}",
            f"Payload analysis: required={self.payload_analysis_required}, completed={self.payload_analysis_completed}, reviewed={self.payload_result_reviewed}",
        ]
        if self.boundary_history:
            lines.append(f"Current boundaries: {self.boundary_history[-1]}")
        return " | ".join(lines)


# ============================================================================
# Analysis State Management
# ============================================================================

class AnalysisState:
    """
    Explicit Analysis State Management
    
    Tracks analysis progress and provides context-aware state information for LLM.
    """
    
    # Analysis stage definitions
    STAGES = [
        ("OBSERVE", "Observe Data", "Review hex messages and understand structure"),
        ("STATISTICS", "Statistical Analysis", "Call analyze_bytes(basic) for patterns"),
        ("DEEP_ANALYSIS", "Deep Analysis", "Optional: boundary/region/TLV analysis"),
        ("HYPOTHESIS", "Form Hypothesis", "Define field structure based on evidence"),
        ("FORMAT_CHECK", "Format Check", "Call get_output_format for spec"),
        ("VALIDATION", "Validate Fields", "Call validate_fields (REQUIRED)"),
        ("PAYLOAD_ANALYSIS", "Payload Analysis", "Optional: Analyze payload if analyzable"),
        ("OUTPUT", "Output Result", "Output final JSON"),
    ]
    
    # Stage index mapping
    STAGE_INDEX = {name: i for i, (name, _, _) in enumerate(STAGES)}
    
    # State transition rules
    TRANSITIONS = {
        "OBSERVE": {
            "next": ["STATISTICS"],
            "auto_advance": True,
        },
        "STATISTICS": {
            "next": ["DEEP_ANALYSIS", "HYPOTHESIS"],
            "trigger_tools": ["analyze_bytes", "detect_endianness"],
        },
        "DEEP_ANALYSIS": {
            "next": ["HYPOTHESIS"],
            "optional_tools": ["analyze_bytes", "detect_tlv", "detect_endianness"],
        },
        "HYPOTHESIS": {
            "next": ["DEEP_ANALYSIS", "FORMAT_CHECK", "VALIDATION"],  # Can go back to DEEP_ANALYSIS for more info
        },
        "FORMAT_CHECK": {
            "next": ["VALIDATION"],
            "trigger_tools": ["get_output_format"],
        },
        "VALIDATION": {
            "next": ["PAYLOAD_ANALYSIS", "OUTPUT", "HYPOTHESIS"],  # Check for payload analysis or output
            "trigger_tools": ["validate_fields"],
            "required": True,
        },
        "PAYLOAD_ANALYSIS": {
            "next": ["HYPOTHESIS", "OUTPUT"],  # Refine hypothesis or output
            "trigger_tools": ["analyze_bytes"],  # Uses region analysis on payload
        },
        "OUTPUT": {
            "next": [],
            "requires": ["validation_passed"],
        }
    }
    
    def __init__(self):
        self.current_stage = "OBSERVE"
        self.completed_stages = set()
        self.tool_history: List[Dict[str, Any]] = []
        self.validation_attempts = 0
        self.validation_passed = False
        self.validation_errors: List[str] = []
        self.validation_warnings: List[str] = []  # Warnings from validation (e.g., large bytes fields)
        self.payload_analysis_suggested = False  # Whether payload analysis is suggested
        self.payload_analysis_required = False   # Whether payload analysis is REQUIRED (not skippable)
        self.payload_analysis_completed = False  # Whether payload analysis has been completed
        self.payload_result_reviewed = False     # Whether LLM has reviewed payload analysis results
        self.payload_fields: List[Dict] = []     # Fields requiring payload analysis
        self.turn_count = 0
    
    def record_tool_call(self, tool_name: str, parameters: Dict, result_summary: str = ""):
        """Record tool call"""
        self.tool_history.append({
            "turn": self.turn_count,
            "tool": tool_name,
            "params": parameters,
            "summary": result_summary
        })
        
        # Update stage based on tool call
        self._update_stage_by_tool(tool_name, parameters)
    
    def _update_stage_by_tool(self, tool_name: str, parameters: Dict):
        """Auto-update stage based on tool call"""
        current_idx = self.STAGE_INDEX.get(self.current_stage, 0)
        
        if tool_name == "analyze_bytes":
            mode = parameters.get("mode", "basic")
            if mode == "basic" and self.current_stage == "OBSERVE":
                self._advance_to("STATISTICS")
            elif mode in ("region", "boundary"):
                # Allow going back to DEEP_ANALYSIS from HYPOTHESIS for iterative analysis
                if self.current_stage in ("STATISTICS", "OBSERVE", "HYPOTHESIS"):
                    self.current_stage = "DEEP_ANALYSIS"
                    self.completed_stages.add("DEEP_ANALYSIS")
                # In PAYLOAD_ANALYSIS, region analysis marks payload as analyzed
                elif self.current_stage == "PAYLOAD_ANALYSIS":
                    # Mark payload analysis as completed
                    self.payload_analysis_completed = True
                    logging.info(f"Payload analysis completed via analyze_bytes(mode={mode})")
                    # Stay in PAYLOAD_ANALYSIS - LLM will decide next step
        
        elif tool_name == "detect_tlv":
            # Allow going back to DEEP_ANALYSIS from HYPOTHESIS for iterative analysis
            if self.current_stage in ("STATISTICS", "OBSERVE", "HYPOTHESIS"):
                self.current_stage = "DEEP_ANALYSIS"
                self.completed_stages.add("DEEP_ANALYSIS")
            elif self.current_stage == "PAYLOAD_ANALYSIS":
                # TLV detection on payload also counts as payload analysis
                self.payload_analysis_completed = True
                logging.info("Payload analysis completed via detect_tlv")
        
        elif tool_name == "detect_endianness":
            # Endianness detection is typically done in STATISTICS or DEEP_ANALYSIS stage
            if self.current_stage == "OBSERVE":
                self._advance_to("STATISTICS")
            elif self.current_stage in ("STATISTICS", "HYPOTHESIS"):
                # Can be called during statistics or when revisiting hypothesis
                pass  # Stay in current stage, this is informational
        
        elif tool_name == "get_output_format":
            if current_idx < self.STAGE_INDEX["FORMAT_CHECK"]:
                self._advance_to("FORMAT_CHECK")
        
        elif tool_name == "validate_fields":
            self.validation_attempts += 1
            if current_idx < self.STAGE_INDEX["VALIDATION"]:
                self._advance_to("VALIDATION")
    
    def record_validation_result(self, passed: bool, errors: List[str] = None, warnings: List[str] = None,
                                   payload_fields: List[Dict] = None):
        """Record validation result with payload analysis requirement detection
        
        Payload analysis is REQUIRED (not skippable) when:
        1. There is a bytes field > PAYLOAD_SIZE_THRESHOLD bytes
        2. The field is the last field or marked as payload/data
        
        Args:
            passed: Whether validation passed
            errors: List of error messages
            warnings: List of warning messages
            payload_fields: List of fields that need payload analysis (from validation)
        """
        PAYLOAD_SIZE_THRESHOLD = 16  # Bytes fields larger than this MUST be analyzed
        
        self.validation_passed = passed
        self.validation_errors = errors or []
        self.validation_warnings = warnings or []
        self.payload_fields = payload_fields or []
        
        # Check if payload analysis is required based on warnings
        payload_warnings = [w for w in self.validation_warnings if 
                          'payload' in w.lower() or 
                          ('large' in w.lower() and 'bytes' in w.lower()) or
                          'internal structure' in w.lower()]
        
        self.payload_analysis_suggested = len(payload_warnings) > 0
        
        # Payload analysis is REQUIRED if warnings suggest large payload fields
        # This is NOT skippable - LLM MUST analyze payload before outputting
        self.payload_analysis_required = len(payload_warnings) > 0
        
        if passed:
            self.completed_stages.add("VALIDATION")
            
            if self.payload_analysis_required and not self.payload_analysis_completed:
                # MUST go to PAYLOAD_ANALYSIS - cannot skip to OUTPUT
                self._advance_to("PAYLOAD_ANALYSIS")
                logging.info(f"Payload analysis REQUIRED: {len(payload_warnings)} large field(s) detected")
            else:
                self._advance_to("OUTPUT")
        else:
            # Validation failed, fall back to HYPOTHESIS
            self.current_stage = "HYPOTHESIS"
            if "VALIDATION" in self.completed_stages:
                self.completed_stages.remove("VALIDATION")
    
    def record_payload_analysis(self, analyzed_region: Dict = None):
        """Record that payload analysis has been performed
        
        Args:
            analyzed_region: Details of the analyzed region (optional)
        """
        self.payload_analysis_completed = True
        logging.info(f"Payload analysis completed: {analyzed_region}")
        
        # If in PAYLOAD_ANALYSIS stage, can now proceed to OUTPUT or back to HYPOTHESIS
        if self.current_stage == "PAYLOAD_ANALYSIS":
            # Stay in current stage - LLM will decide whether to refine hypothesis or output
            pass
        else:
            # Validation failed, fall back to HYPOTHESIS
            self.current_stage = "HYPOTHESIS"
            if "VALIDATION" in self.completed_stages:
                self.completed_stages.remove("VALIDATION")
    
    def mark_payload_result_reviewed(self):
        """Mark that LLM has reviewed the payload analysis results
        
        This is called when a new turn starts after payload analysis was completed.
        It allows the system to know that LLM has seen the results and can now make a decision.
        """
        if self.payload_analysis_completed and not self.payload_result_reviewed:
            self.payload_result_reviewed = True
            logging.info("Payload analysis results marked as reviewed by LLM")
    
    def _advance_to(self, stage: str):
        """Advance to specified stage"""
        if self.current_stage != stage:
            self.completed_stages.add(self.current_stage)
            self.current_stage = stage
    
    def advance_turn(self):
        """Advance turn count"""
        self.turn_count += 1
        
        # OBSERVE stage auto-completes
        if self.current_stage == "OBSERVE" and self.turn_count > 0:
            self._advance_to("STATISTICS")
    
    def can_output(self) -> bool:
        """Check if final result can be output
        
        Output is allowed when:
        1. Validation has passed, AND
        2. Payload analysis is NOT required, OR payload analysis has been completed AND reviewed
        """
        if not self.validation_passed:
            return False
        
        # If payload analysis is required, it MUST be completed AND reviewed before output
        if self.payload_analysis_required:
            if not self.payload_analysis_completed:
                return False
            if not self.payload_result_reviewed:
                return False
        
        return self.current_stage in ("OUTPUT", "PAYLOAD_ANALYSIS")
    
    def get_progress_prompt(self) -> str:
        """Generate progress prompt"""
        current_idx = self.STAGE_INDEX.get(self.current_stage, 0)
        total = len(self.STAGES)
        progress_pct = int((current_idx / (total - 1)) * 100) if total > 1 else 0
        
        # Progress bar
        filled = int(progress_pct / 5)
        bar = "█" * filled + "░" * (20 - filled)
        
        lines = [
            "═" * 65,
            "                    📊 ANALYSIS PROGRESS",
            "═" * 65,
            "",
            f"Current Stage: [{current_idx + 1}/{total}] {self.current_stage}",
            f"Progress: {bar} {progress_pct}%",
            "",
            "Steps:",
        ]
        
        # Stage list
        for i, (name, stage_name, desc) in enumerate(self.STAGES):
            if name in self.completed_stages:
                icon = "✅"
            elif name == self.current_stage:
                icon = "🔄"
            else:
                icon = "⬚ "
            
            required = " (REQUIRED)" if name == "VALIDATION" else ""
            lines.append(f"  {icon} [{i+1}] {name}: {stage_name}{required}")
        
        # Tool call history (last 5)
        if self.tool_history:
            lines.extend(["", "Recent Tool Calls:"])
            for call in self.tool_history[-5:]:
                params_str = ", ".join(f"{k}={v}" for k, v in call["params"].items()) if call["params"] else ""
                summary = f" → {call['summary']}" if call.get("summary") else ""
                lines.append(f"  • {call['tool']}({params_str}){summary}")
        
        # Suggestions
        lines.extend(["", "💡 Suggested Actions:"])
        suggestions = self._get_suggestions()
        for s in suggestions:
            lines.append(f"  - {s}")
        
        # Warnings
        warnings = self._get_warnings()
        if warnings:
            lines.append("")
            for w in warnings:
                lines.append(f"⚠️  {w}")
        
        lines.append("═" * 65)
        
        return "\n".join(lines)
    
    def _get_suggestions(self) -> List[str]:
        """Generate suggestions based on current state"""
        suggestions = []
        
        if self.current_stage == "OBSERVE":
            suggestions.append("Review the message data, then call analyze_bytes()")
        
        elif self.current_stage == "STATISTICS":
            # Check if basic mode has been called
            has_basic = any(
                c["tool"] == "analyze_bytes" and c["params"].get("mode", "basic") == "basic"
                for c in self.tool_history
            )
            has_endianness = any(
                c["tool"] == "detect_endianness"
                for c in self.tool_history
            )
            if not has_basic:
                suggestions.append("Call analyze_bytes() to get statistical patterns")
            else:
                if not has_endianness:
                    suggestions.append("If unsure about byte order → Call detect_endianness() to determine LE/BE")
                suggestions.append("If patterns are clear → Proceed to define fields (HYPOTHESIS)")
                suggestions.append("If need deeper analysis → analyze_bytes(mode=boundary) or detect_tlv")
        
        elif self.current_stage == "DEEP_ANALYSIS":
            suggestions.append("Available tools: analyze_bytes(mode=region/boundary/compare), detect_tlv, detect_endianness")
            suggestions.append("  - region: Analyze specific byte range (start, end)")
            suggestions.append("  - boundary: Find header/payload delimiter")
            suggestions.append("  - detect_tlv: Detect TLV structures")
            suggestions.append("  - detect_endianness: Determine byte order (little/big-endian)")
            suggestions.append("When you have enough evidence → Proceed to HYPOTHESIS")
        
        elif self.current_stage == "HYPOTHESIS":
            suggestions.append("Define field boundaries based on analysis results")
            suggestions.append("If uncertain about a region → analyze_bytes(mode=region, start=X, end=Y)")
            suggestions.append("If need to find header/payload boundary → analyze_bytes(mode=boundary)")
            suggestions.append("When confident → Call get_output_format, then validate_fields")
        
        elif self.current_stage == "FORMAT_CHECK":
            suggestions.append("Review output format, then call validate_fields")
        
        elif self.current_stage == "VALIDATION":
            if self.validation_errors:
                suggestions.append(f"Fix validation errors and call validate_fields again")
            elif self.validation_passed:
                suggestions.append("Validation passed! Output the final JSON now")
            else:
                suggestions.append("Call validate_fields to verify your field definitions")
        
        elif self.current_stage == "PAYLOAD_ANALYSIS":
            if self.payload_analysis_required and not self.payload_analysis_completed:
                suggestions.append("🚨 REQUIRED: Large bytes field detected - you MUST analyze payload before output")
                suggestions.append("")
                suggestions.append("Steps to complete payload analysis:")
                suggestions.append("  1. Call analyze_bytes(mode=region, start=<payload_offset>, end=-1)")
                suggestions.append("  2. Look for: constant bytes, length fields, nested structures, ASCII strings")
                suggestions.append("  3. If structure found → Refine field definitions and validate again")
                suggestions.append("  4. If NO structure (encrypted/compressed) → Document and output")
                suggestions.append("")
                suggestions.append("You CANNOT skip this step. Payload must be analyzed before final output.")
            else:
                suggestions.append("✅ Payload region analysis completed. Now examine the results:")
                suggestions.append("")
                suggestions.append("  **If structure found** (constant bytes, low entropy, length patterns):")
                suggestions.append("    → Refine your field definitions to break down the payload")
                suggestions.append("    → Call validate_fields again with the refined fields")
                suggestions.append("")
                suggestions.append("  **If NO structure** (high entropy, random data, encrypted/compressed):")
                suggestions.append("    → Keep payload as single bytes field")
                suggestions.append("    → Output the final JSON result")
                suggestions.append("")
                suggestions.append("⚠️ Do NOT output until you've made a decision based on the payload analysis!")
        
        elif self.current_stage == "OUTPUT":
            suggestions.append("Output the final JSON result (start with '{')")
        
        return suggestions
    
    def _get_warnings(self) -> List[str]:
        """Generate warning messages"""
        warnings = []
        
        # Validation failure warning
        if self.validation_errors:
            warnings.append(f"Last validation failed with {len(self.validation_errors)} error(s):")
            for err in self.validation_errors[:3]:
                warnings.append(f"   - {err}")
        
        # Payload analysis REQUIRED warning - show prominently in PAYLOAD_ANALYSIS stage
        if self.payload_analysis_required and not self.payload_analysis_completed:
            if self.current_stage == "PAYLOAD_ANALYSIS":
                warnings.append("🚨 MANDATORY: Large payload field detected - MUST analyze before output:")
                for w in self.validation_warnings[:3]:
                    warnings.append(f"   - {w}")
                warnings.append("   → Call analyze_bytes(mode=region, start=<payload_offset>, end=-1)")
            elif self.current_stage == "OUTPUT":
                warnings.append("🚨 BLOCKED: Cannot output - payload analysis required but not completed!")
                warnings.append("   → Go back to PAYLOAD_ANALYSIS stage and analyze the payload first.")
        
        # Attempting to output without validation
        if self.current_stage == "OUTPUT" and not self.validation_passed:
            warnings.append("You MUST pass validation before outputting!")
        
        # Multiple validation failures
        if self.validation_attempts >= 3 and not self.validation_passed:
            warnings.append(f"Validation attempted {self.validation_attempts} times. Review your field definitions carefully.")
        
        return warnings


# ============================================================================
# Conversational Protocol Analysis Agent
# ============================================================================

class ProtocolAnalyzerAgent:
    """
    Conversational Protocol Analysis Agent
    
    Performs protocol analysis through multi-turn conversations:
    1. Send message data to LLM
    2. LLM decides which Tools (Skills) to call
    3. Continue reasoning based on Tool results
    4. Output final protocol structure definition
    """
    
    # System Prompt template
    SYSTEM_PROMPT = """# Role

You are a Senior Network Protocol Reverse Engineer. Your task is to analyze binary protocol messages and produce a structured JSON description of the protocol format.

# Analysis Stages

Your analysis follows these stages (you will see your progress at each turn):

```
[1] OBSERVE      → Review hex messages
[2] STATISTICS   → Call analyze_bytes(basic) for patterns  
[3] DEEP_ANALYSIS→ Optional: boundary/region/TLV analysis
[4] HYPOTHESIS   → Define field structure
[5] FORMAT_CHECK → Call get_output_format (REQUIRED!)
[6] VALIDATION   → Call validate_fields (REQUIRED!)
[7] PAYLOAD_ANALYSIS → Analyze large payload fields (REQUIRED if detected!)
[8] OUTPUT       → Output final JSON
```

**Stage Rules:**
- Follow the suggested actions shown in your progress
- You CANNOT skip VALIDATION - it is mandatory
- If validation fails, fix errors and validate again
- **CRITICAL**: If validation warns about large bytes fields (>16 bytes), you MUST:
  1. Call analyze_bytes(mode=region, start=<offset>, end=<end>) on each large field
  2. Examine the results for patterns: constant bytes, length fields, ASCII strings
  3. If structure found → refine your fields and validate again
  4. Only output after payload analysis is complete
- Only output final JSON after ALL required analysis is complete

# Available Tools

You have access to the following tools to assist your analysis:

{tools_description}

# How to Call Tools

To call a tool, output a JSON object with the following format:

```json
{{"action": "tool_name", "parameters": {{"param1": value1, "param2": value2}}}}
```

Example:
```json
{{"action": "analyze_bytes", "parameters": {{"max_bytes": 32}}}}
```

**IMPORTANT**: 
- You MUST include the `"action"` field with the tool name
- Parameters go inside the `"parameters"` object
- Do NOT output only the parameters without specifying the tool name

# Important Rules

- Use tools to gather evidence before making decisions
- **MANDATORY**: You MUST call `validate_fields` before outputting your final result
- **MANDATORY**: If validation shows large bytes fields, you MUST analyze their internal structure
- If validation fails, fix the issues and validate again
- Express your reasoning briefly before each tool call
- When ready to output (after validation AND payload analysis complete), provide ONLY the JSON object (no markdown, no explanation)
- Start final output directly with `{{`
"""
    
    def __init__(
        self,
        model_name: str = None,
        enable_skills: bool = True,
        use_cache: bool = True,
        max_turns: int = 10,
        log_dir: str = None
    ):
        """
        Initialize Agent
        
        Args:
            model_name: LLM model name
            enable_skills: Whether to enable Skills
            use_cache: Whether to use cache
            max_turns: Maximum conversation turns
            log_dir: Log directory
        """
        if not GEMINI_AVAILABLE or LLMClient is None:
            raise ImportError("LLMClient is required")
        
        self.model_name = model_name or DEFAULT_MODEL_NAME
        self.max_turns = max_turns
        self.log_dir = log_dir
        
        # Initialize LLM client
        self.llm_client = LLMClient(model_name=self.model_name)
        
        # Initialize Skill Manager
        self.skill_manager = None
        self.context = None
        
        if enable_skills and SKILLS_AVAILABLE:
            self.skill_manager = SkillManager()
            self.skill_manager.discover_and_load()
            self.skill_manager.set_skill_config("header_analysis", "use_cache", use_cache)
            logging.info(f"Agent initialized with {len(self.skill_manager.list_skills())} skills")
        
        # Analysis state management
        self.analysis_state: Optional[AnalysisState] = None
        
        # Convergence detector
        self.convergence_detector: Optional[ConvergenceDetector] = None
    
    def _build_system_prompt(self) -> str:
        """Build System Prompt"""
        # Get Tools description
        tools_desc = ""
        if self.skill_manager:
            tools_desc = self.skill_manager.get_tools_description(self.context)
        
        return self.SYSTEM_PROMPT.format(
            tools_description=tools_desc or "No tools available."
        )
    
    def _analyze_message_distribution(self, messages: List[bytes]) -> Dict[str, Any]:
        """Analyze message length distribution for intelligent grouping"""
        lengths = []
        for msg in messages:
            if hasattr(msg, 'data'):
                lengths.append(len(msg.data))
            elif isinstance(msg, bytes):
                lengths.append(len(msg))
            else:
                lengths.append(len(bytes(msg)))
        
        # Count length distribution
        from collections import Counter
        length_counts = Counter(lengths)
        
        # Group by length
        groups = {}
        for i, msg in enumerate(messages):
            if hasattr(msg, 'data'):
                msg_len = len(msg.data)
            elif isinstance(msg, bytes):
                msg_len = len(msg)
            else:
                msg_len = len(bytes(msg))
            
            if msg_len not in groups:
                groups[msg_len] = []
            groups[msg_len].append((i, msg))
        
        return {
            "total_messages": len(messages),
            "unique_lengths": len(length_counts),
            "min_length": min(lengths) if lengths else 0,
            "max_length": max(lengths) if lengths else 0,
            "length_distribution": dict(sorted(length_counts.items())),
            "groups": groups
        }
    
    def _format_messages_for_prompt(self, messages: List[bytes], max_messages: int = 100) -> str:
        """Format messages for prompt - intelligent grouped sampling"""
        # Analyze message distribution
        dist = self._analyze_message_distribution(messages)
        
        lines = []
        
        # Add statistical summary
        lines.append("## Message Statistics")
        lines.append(f"- Total messages: {dist['total_messages']}")
        lines.append(f"- Length range: {dist['min_length']} - {dist['max_length']} bytes")
        lines.append(f"- Unique lengths: {dist['unique_lengths']}")
        lines.append("")
        
        # Length distribution table
        lines.append("## Length Distribution")
        for length, count in sorted(dist['length_distribution'].items()):
            pct = count * 100 / dist['total_messages']
            lines.append(f"- {length} bytes: {count} messages ({pct:.1f}%)")
        lines.append("")
        
        # Sample messages grouped by length
        lines.append("## Sample Messages (grouped by length)")
        
        groups = dist['groups']
        samples_per_group = max(1, max_messages // len(groups)) if groups else max_messages
        total_sampled = 0
        
        for length in sorted(groups.keys()):
            group_msgs = groups[length]
            # Sample from each group
            sample_count = min(samples_per_group, len(group_msgs), max_messages - total_sampled)
            if sample_count <= 0:
                break
            
            lines.append(f"")
            lines.append(f"### Length {length} bytes ({len(group_msgs)} messages, showing {sample_count})")
            
            # Select samples: distributed from start, middle, end
            if sample_count >= len(group_msgs):
                samples = group_msgs
            else:
                # Uniform sampling
                step = len(group_msgs) / sample_count
                indices = [int(i * step) for i in range(sample_count)]
                samples = [group_msgs[i] for i in indices]
            
            for idx, msg in samples:
                if hasattr(msg, 'data'):
                    hex_str = msg.data.hex()
                elif isinstance(msg, bytes):
                    hex_str = msg.hex()
                else:
                    hex_str = bytes(msg).hex()
                lines.append(f"{idx+1}. {hex_str}")
                total_sampled += 1
        
        return "\n".join(lines)
    
    def _get_known_tool_names(self) -> List[str]:
        """Dynamically get names of all registered tools"""
        if self.skill_manager:
            tools = self.skill_manager.get_available_tools(self.context)
            return [t.get_tool_schema().name for t in tools if t.get_tool_schema()]
        # Fallback: hardcoded list (excluding oracle tools)
        return ['analyze_bytes', 'validate_fields', 'detect_tlv']
    
    def _summarize_tool_result(self, tool_name: str, result: Dict) -> str:
        """Generate tool result summary (for state tracking)"""
        if tool_name == "analyze_bytes":
            mode = result.get("mode", "basic")
            if mode == "basic":
                constants = len(result.get("constant_bytes", []))
                length_candidates = len(result.get("length_field_candidates", []))
                return f"Found {constants} constant bytes, {length_candidates} length candidates"
            elif mode == "boundary":
                boundary = result.get("suggested_boundary")
                return f"Suggested boundary at offset {boundary}" if boundary else "No clear boundary"
            elif mode == "region":
                score = result.get("structure_assessment", {}).get("score", "?")
                return f"Structure score: {score}"
            else:
                return f"Mode: {mode}"
        
        elif tool_name == "validate_fields":
            valid = result.get("valid", False)
            errors = len(result.get("errors", []))
            return f"{'✓ Valid' if valid else f'✗ {errors} errors'}"
        
        elif tool_name == "detect_tlv":
            detected = result.get("is_tlv", False)
            return f"TLV: {'detected' if detected else 'not detected'}"
        
        elif tool_name == "get_output_format":
            return "Format spec retrieved"
        
        return "Completed"
    
    def _parse_tool_calls(self, response: str) -> List[Dict[str, Any]]:
        """
        Parse Tool calls from LLM response
        
        Supports multiple formats:
        1. [TOOL_CALL: tool_name(param=value)]
        2. {"action": "tool_name", "parameters": {...}}
        3. {"action": "tool_name", "action_input": {...}}
        4. {"tool": "tool_name", "params": {...}}
        5. {"tool_name": {...}}  (tool name as key directly)
        """
        tool_calls = []
        known_tools = self._get_known_tool_names()
        
        def parse_json_tool_call(obj: Dict) -> Optional[Dict]:
            """Parse tool call from a single JSON object"""
            # Format: {"action": "tool_name", ...}
            if 'action' in obj and obj['action'] in known_tools:
                return {
                    "name": obj['action'],
                    "params": obj.get('parameters', obj.get('action_input', {}))
                }
            # Format: {"tool": "tool_name", "params": {...}}
            if 'tool' in obj and obj['tool'] in known_tools:
                return {
                    "name": obj['tool'],
                    "params": obj.get('params', obj.get('parameters', {}))
                }
            # Format: {"tool_name": {...}}
            for tool_name in known_tools:
                if tool_name in obj and isinstance(obj[tool_name], dict):
                    return {
                        "name": tool_name,
                        "params": obj[tool_name]
                    }
            return None
        
        # Format 1: [TOOL_CALL: xxx]
        pattern = r'\[TOOL_CALL:\s*(\w+)(?:\(([^)]*)\))?\]'
        for match in re.finditer(pattern, response):
            tool_name = match.group(1)
            params_str = match.group(2) or ""
            
            params = {}
            if params_str:
                for param in params_str.split(','):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        key = key.strip()
                        value = value.strip()
                        try:
                            params[key] = json.loads(value)
                        except json.JSONDecodeError:
                            params[key] = value.strip('"\'')
            
            tool_calls.append({
                "name": tool_name,
                "params": params
            })
        
        # JSON format (in code block)
        json_pattern = r'```(?:json)?\s*(\{[^`]*\})\s*```'
        for match in re.finditer(json_pattern, response, re.DOTALL):
            try:
                obj = json.loads(match.group(1))
                tc = parse_json_tool_call(obj)
                if tc:
                    tool_calls.append(tc)
            except json.JSONDecodeError:
                pass
        
        # JSON format (not in code block)
        if not tool_calls:
            for match in re.finditer(r'\{', response):
                start = match.start()
                depth = 0
                end = start
                for i, c in enumerate(response[start:], start):
                    if c == '{':
                        depth += 1
                    elif c == '}':
                        depth -= 1
                        if depth == 0:
                            end = i + 1
                            break
                try:
                    obj = json.loads(response[start:end])
                    tc = parse_json_tool_call(obj)
                    if tc:
                        tool_calls.append(tc)
                except json.JSONDecodeError:
                    pass
        
        return tool_calls
    
    def _extract_json_result(self, response: str) -> Optional[Dict[str, Any]]:
        """Extract JSON result from response
        
        Only accepts JSON containing 'fields' or 'boundary_type' as valid final result.
        Ignores tool call parameters and other JSON.
        """
        def is_valid_result(obj: Dict) -> bool:
            """Check if it's a valid protocol analysis result"""
            return isinstance(obj, dict) and ('fields' in obj or 'boundary_type' in obj)
        
        # Try entire response
        try:
            obj = json.loads(response.strip())
            if is_valid_result(obj):
                return obj
        except json.JSONDecodeError:
            pass
        
        # Try to find all JSON objects
        start_idx = 0
        while True:
            start_idx = response.find('{', start_idx)
            if start_idx == -1:
                break
            
            # Find matching }
            depth = 0
            for i, c in enumerate(response[start_idx:], start_idx):
                if c == '{':
                    depth += 1
                elif c == '}':
                    depth -= 1
                    if depth == 0:
                        try:
                            obj = json.loads(response[start_idx:i+1])
                            if is_valid_result(obj):
                                return obj
                        except json.JSONDecodeError:
                            pass
                        break
            
            start_idx += 1
        
        return None
    
    def analyze(
        self,
        messages: List[bytes],
        protocol_type: str = None,
        sessions: Dict = None
    ) -> Dict[str, Any]:
        """
        Execute conversational analysis
        
        Args:
            messages: Protocol message list
            protocol_type: Protocol type
            sessions: Session information
            
        Returns:
            Analysis result
        """
        # Create context
        self.context = SkillContext(
            protocol_type=protocol_type or "unknown",
            messages=messages,
            sessions=sessions or {}
        ) if SkillContext else None
        
        # Initialize analysis state
        self.analysis_state = AnalysisState()
        
        # Initialize convergence detector
        self.convergence_detector = ConvergenceDetector(
            stability_window=2,          # Consecutive 2 rounds with same boundaries
            min_info_gain=0.5,           # Minimum average info gain
            gain_window=3,               # Window for info gain averaging
            oscillation_window=6,        # Window for oscillation detection
            max_oscillation_rounds=8     # Max rounds before forcing convergence
        )
        
        # Track current hypothesis for convergence detection
        current_hypothesis: Optional[Dict] = None
        
        # Build System Prompt
        system_prompt = self._build_system_prompt()
        
        # Log System Prompt
        logging.info("=" * 80)
        logging.info("SYSTEM PROMPT:")
        logging.info("=" * 80)
        logging.info(f"\n{system_prompt}")
        logging.info("=" * 80)
        
        # Start chat session
        self.llm_client.start_chat(system_prompt=system_prompt)
        
        # Format message data (intelligent grouped sampling)
        messages_text = self._format_messages_for_prompt(messages)
        
        # Initial message - don't reveal protocol type to avoid LLM "cheating" with prior knowledge
        # Add initial state info
        initial_progress = self.analysis_state.get_progress_prompt()
        user_message = f"""{initial_progress}

Analyze the following binary protocol messages and determine their structure.

{messages_text}

**Notes:**
- Messages are grouped by length for easier pattern recognition
- Different lengths may indicate different message types or variable-length payloads
- Use `analyze_bytes` tool to get statistical patterns (constant bytes, length field candidates)

Start by calling analyze_bytes() to gather evidence.
"""
        
        # Conversation loop
        conversation_log = []
        final_result = None
        
        def _split_message(msg: str) -> List[str]:
            """Split long message by lines for better JSON readability"""
            return msg.split('\n') if '\n' in msg else [msg]
        
        # Console progress display (protocol_type only for internal identification, not passed to LLM)
        print(f"\n{'='*60}")
        print(f"Starting analysis | Messages: {len(messages)}")
        print(f"{'='*60}")
        
        for turn in range(self.max_turns):
            # Advance state turn
            self.analysis_state.advance_turn()
            
            print(f"\n[Turn {turn + 1}/{self.max_turns}] Stage: {self.analysis_state.current_stage}")
            logging.info(f"=== Turn {turn + 1}/{self.max_turns} | Stage: {self.analysis_state.current_stage} ===")
            
            # Send message
            response = self.llm_client.chat(user_message)
            conversation_log.append({
                "turn": turn + 1,
                "stage": self.analysis_state.current_stage,
                "user": _split_message(user_message),      # Split by lines for readability
                "assistant": _split_message(response)      # Split by lines for readability
            })
            
            logging.debug(f"Assistant: {response}")
            
            # If LLM has received payload analysis results, mark them as reviewed
            # This happens when the previous turn completed payload analysis
            if (self.analysis_state.current_stage == "PAYLOAD_ANALYSIS" and 
                self.analysis_state.payload_analysis_completed and
                not self.analysis_state.payload_result_reviewed):
                self.analysis_state.mark_payload_result_reviewed()
                self.convergence_detector.mark_payload_result_reviewed()
            
            # Check for Tool calls
            tool_calls = self._parse_tool_calls(response)
            
            if tool_calls:
                # Execute Tools
                tool_results = []
                for tc in tool_calls:
                    print(f"  -> Calling tool: {tc['name']}")
                    logging.info(f"Executing tool: {tc['name']} with {tc['params']}")
                    
                    if self.skill_manager:
                        try:
                            result = self.skill_manager.invoke_tool(
                                tc['name'],
                                self.context,
                                **tc['params']
                            )
                            tool_results.append({
                                "tool": tc['name'],
                                "result": result
                            })
                            print(f"     ✓ Tool executed successfully")
                            # Record Tool result (full record)
                            logging.info(f"Tool result ({tc['name']}):")
                            logging.info(json.dumps(result, indent=2, ensure_ascii=False))
                            
                            # Update analysis state
                            result_summary = self._summarize_tool_result(tc['name'], result)
                            self.analysis_state.record_tool_call(tc['name'], tc['params'], result_summary)
                            
                            # Special handling: validate_fields result
                            if tc['name'] == 'validate_fields':
                                is_valid = result.get('valid', False)
                                errors = result.get('errors', [])
                                warnings = result.get('warnings', [])
                                self.analysis_state.record_validation_result(is_valid, errors, warnings)
                                
                                # Extract hypothesis from validate_fields input for convergence tracking
                                if 'fields' in tc['params']:
                                    current_hypothesis = {'fields': tc['params']['fields']}
                                    # Update convergence detector
                                    self.convergence_detector.update(
                                        hypothesis=current_hypothesis,
                                        validation_result={'errors': errors, 'warnings': warnings},
                                        tool_name=tc['name'],
                                        tool_result=result
                                    )
                                
                                if is_valid:
                                    if warnings:
                                        print(f"     ✅ Validation passed with {len(warnings)} warning(s)")
                                        # Check for payload analysis requirement
                                        if self.analysis_state.payload_analysis_required:
                                            print(f"     🚨 Payload analysis REQUIRED - cannot skip!")
                                    else:
                                        print(f"     ✅ Validation passed!")
                                else:
                                    print(f"     ❌ Validation failed: {len(errors)} error(s)")
                            
                            # Track payload analysis completion (analyze_bytes with region mode)
                            elif tc['name'] == 'analyze_bytes' and tc['params'].get('mode') in ('region', 'boundary'):
                                if self.analysis_state.current_stage == "PAYLOAD_ANALYSIS":
                                    # Mark payload analysis completed in convergence detector too
                                    self.convergence_detector.mark_payload_analysis_done()
                                    print(f"     📊 Payload region analyzed")
                                
                                # Update convergence detector for other tools
                                self.convergence_detector.update(
                                    tool_name=tc['name'],
                                    tool_result=result
                                )
                            else:
                                # Update convergence detector for other tools
                                self.convergence_detector.update(
                                    tool_name=tc['name'],
                                    tool_result=result
                                )
                            
                        except Exception as e:
                            print(f"     ✗ Tool execution failed: {e}")
                            logging.error(f"Tool error ({tc['name']}): {e}")
                            tool_results.append({
                                "tool": tc['name'],
                                "error": str(e)
                            })
                    else:
                        tool_results.append({
                            "tool": tc['name'],
                            "error": "Skill manager not available"
                        })
                
                # Check convergence after tool execution
                # IMPORTANT: Do NOT converge immediately after payload analysis
                # We need to let LLM see the results first and decide next steps
                just_completed_payload_analysis = (
                    self.analysis_state.current_stage == "PAYLOAD_ANALYSIS" and
                    self.analysis_state.payload_analysis_completed and
                    any(tc['name'] == 'analyze_bytes' and tc['params'].get('mode') in ('region', 'boundary') 
                        for tc in tool_calls)
                )
                
                if not just_completed_payload_analysis:
                    converged, reason, best_boundaries = self.convergence_detector.should_converge()
                    if converged and self.analysis_state.validation_passed:
                        print(f"  -> 🎯 Convergence detected: {reason}")
                        logging.info(f"Convergence detected: {reason}, boundaries: {best_boundaries}")
                        
                        # Build final result from current hypothesis
                        if current_hypothesis:
                            final_result = current_hypothesis.copy()
                            final_result['convergence_reason'] = reason
                            print(f"  -> ✅ Analysis converged with validated result")
                            break
                else:
                    print(f"  -> 📊 Payload analysis completed, waiting for LLM to review results")
                
                # Check if oscillation detected (but not yet resolved)
                if self.convergence_detector._oscillation_detected_at is not None:
                    rounds_since = len(self.convergence_detector.boundary_history) - self.convergence_detector._oscillation_detected_at
                    print(f"  -> ⚡ Oscillation detected ({rounds_since}/{self.convergence_detector.max_oscillation_rounds} rounds)")
                
                # Build next turn message (with state info)
                progress_prompt = self.analysis_state.get_progress_prompt()
                user_message = f"{progress_prompt}\n\nTool Results:\n\n"
                for tr in tool_results:
                    user_message += f"### {tr['tool']}\n"
                    if 'error' in tr:
                        user_message += f"Error: {tr['error']}\n"
                    else:
                        user_message += f"```json\n{json.dumps(tr['result'], indent=2)}\n```\n"
                    user_message += "\n"
                
                user_message += "Continue your analysis based on these results and the suggested actions above."
                continue
            
            # No Tool call, try to extract JSON result
            result = self._extract_json_result(response)
            if result:
                # Update convergence detector with the hypothesis
                current_hypothesis = result
                self.convergence_detector.update(hypothesis=result)
                
                # Check if output is allowed (validation passed AND payload analysis done if required)
                if not self.analysis_state.can_output():
                    # Determine specific blocking reason
                    if not self.analysis_state.validation_passed:
                        print(f"  -> ⚠️ JSON output detected but validation not passed!")
                        logging.warning("JSON output detected but validation not passed")
                        progress_prompt = self.analysis_state.get_progress_prompt()
                        user_message = f"""{progress_prompt}

⚠️ You attempted to output the final JSON, but validation has NOT passed yet.

You MUST call `validate_fields` and fix any errors before outputting.

Please call validate_fields with your field definitions first."""
                    elif self.analysis_state.payload_analysis_required and not self.analysis_state.payload_analysis_completed:
                        print(f"  -> 🚨 JSON output BLOCKED - payload analysis required!")
                        logging.warning("JSON output blocked: payload analysis required but not completed")
                        progress_prompt = self.analysis_state.get_progress_prompt()
                        user_message = f"""{progress_prompt}

🚨 OUTPUT BLOCKED: Payload analysis is REQUIRED but not completed.

You have a large bytes field that likely contains internal structure.
You MUST analyze it before outputting:

1. Call analyze_bytes(mode=region, start=<payload_offset>, end=-1)
2. Examine the results for patterns, constants, length fields
3. If structure found: refine your fields and validate again
4. If NO structure (encrypted/compressed): you can document this and output

DO NOT attempt to output until payload analysis is complete."""
                    else:
                        # Generic blocking
                        print(f"  -> ⚠️ JSON output detected but cannot output yet!")
                        progress_prompt = self.analysis_state.get_progress_prompt()
                        user_message = f"""{progress_prompt}

⚠️ Cannot output yet. Please check the warnings above and complete required steps."""
                    continue
                
                # Check convergence
                converged, reason, _ = self.convergence_detector.should_converge()
                
                final_result = result
                if converged:
                    final_result['convergence_reason'] = reason
                    print(f"  -> ✅ JSON result extracted (validation passed, converged: {reason})")
                else:
                    print(f"  -> ✅ JSON result extracted (validation passed)")
                logging.info("Successfully extracted JSON result (validation passed)")
                break
            
            # Neither Tool call nor JSON, prompt to continue
            print(f"  -> No tool call or result detected, continuing...")
            progress_prompt = self.analysis_state.get_progress_prompt()
            user_message = f"""{progress_prompt}

Please follow the suggested actions above. Either:
1. Call a tool for more information
2. Or output the final JSON result (only after validation passes)"""
        
        # Handle case where max_turns reached but oscillation can be resolved
        if final_result is None and self.convergence_detector.converged:
            logging.info(f"Max turns reached, using converged result: {self.convergence_detector.convergence_reason}")
            if current_hypothesis:
                final_result = current_hypothesis.copy()
                final_result['convergence_reason'] = self.convergence_detector.convergence_reason
                final_result['forced_convergence'] = True
        
        # Clear chat session
        self.llm_client.clear_chat()
        
        # Save conversation log to file (for debugging only)
        if self.log_dir:
            log_path = Path(self.log_dir)
            log_path.mkdir(parents=True, exist_ok=True)
            
            # Save full conversation record (for debugging/review)
            conversation_file = log_path / "conversation.json"
            with open(conversation_file, 'w', encoding='utf-8') as f:
                json.dump({
                    "system_prompt": system_prompt.split('\n'),  # Split by lines for readability
                    "turns": conversation_log,
                    "final_result": final_result
                }, f, indent=2, ensure_ascii=False)
            logging.info(f"Conversation saved to: {conversation_file}")
        
        # Return result (without conversation details to avoid duplication)
        if final_result:
            return {
                "success": True,
                "result": final_result,
                "turns": len(conversation_log),
                "convergence": {
                    "converged": self.convergence_detector.converged,
                    "reason": self.convergence_detector.convergence_reason,
                    "confidence": self.convergence_detector.selection_confidence,
                    "boundary_history_length": len(self.convergence_detector.boundary_history),
                    "info_gains": self.convergence_detector.info_gains[-5:] if self.convergence_detector.info_gains else []
                }
            }
        else:
            return {
                "success": False,
                "error": "Failed to extract valid JSON result",
                "turns": len(conversation_log),
                "convergence": {
                    "converged": self.convergence_detector.converged,
                    "reason": self.convergence_detector.convergence_reason,
                    "confidence": self.convergence_detector.selection_confidence,
                    "status": self.convergence_detector.get_status_summary()
                }
            }
    
    def analyze_pcap(self, pcap_path: str, protocol_type: str = None) -> Dict[str, Any]:
        """Analyze PCAP file"""
        if not PCAPProcessor:
            return {"error": "PCAPProcessor not available"}
        
        processor = PCAPProcessor(pcap_path, protocol_type=protocol_type)
        
        if not processor.messages:
            return {"error": "No messages extracted from PCAP"}
        
        return self.analyze(
            messages=processor.messages,
            protocol_type=protocol_type or processor.protocol_type,
            sessions=processor.sessions
        )


class TeeStream:
    """Stream class that writes to both console and file"""
    def __init__(self, console_stream, file_path):
        self.console = console_stream
        self.file = open(file_path, 'w', encoding='utf-8')
    
    def write(self, data):
        self.console.write(data)
        self.file.write(data)
        self.file.flush()
    
    def flush(self):
        self.console.flush()
        self.file.flush()
    
    def close(self):
        self.file.close()


def main():
    """Main function"""
    # Configure logging (will be reconfigured later if log_dir is specified)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )
    
    parser = argparse.ArgumentParser(
        description="Protocol Analysis Agent - Multi-turn conversational protocol analysis tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        "-f", "--pcap",
        help="PCAP file path (required for analysis)"
    )
    parser.add_argument(
        "-p", "--protocol", 
        help="Protocol type hint (auto-inferred from filename if not specified)",
        choices=['modbus', 'icmp', 'smb', 'smb2', 'dhcp', 'dnp3', 's7comm', 's7comm_plus', 
                 'ntp', 'omron_fins', 'custom_iot', 'game_sync', 'heart_beat', 'hollysys',
                 'secure_chat', 'time_sync', 'dns_ictf', 'generic'],
        default=None
    )
    parser.add_argument(
        "-m", "--model",
        help="LLM model name (default: gemini-2.5-pro, optional: deepseek-chat)",
        default=None
    )
    parser.add_argument(
        "--max-turns",
        type=int,
        default=30,
        help="Maximum conversation turns (default: 30)"
    )
    parser.add_argument(
        "--log-dir", 
        help="Log output directory (default: auto-generated)"
    )
    parser.add_argument(
        "--no-skills",
        action="store_true",
        help="Disable Skills mechanism (enabled by default)"
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable header analysis cache (force re-analysis)"
    )
    parser.add_argument(
        "--list-skills",
        action="store_true",
        help="List all available Skills"
    )
    parser.add_argument(
        "--list-cache",
        action="store_true",
        help="List cached protocol header analyses"
    )
    parser.add_argument(
        "--clear-cache",
        type=str,
        nargs="?",
        const="__all__",
        metavar="PROTOCOL",
        help="Clear cache (no argument clears all, with protocol name clears specific)"
    )
    
    args = parser.parse_args()
    
    # Cache management commands
    if args.list_cache:
        try:
            from skills.builtin.header_analysis import list_cached_protocols, CACHE_DIR
            protocols = list_cached_protocols()
            print(f"\nCached Header Analyses ({CACHE_DIR}):")
            print("=" * 40)
            if protocols:
                for p in sorted(protocols):
                    print(f"  - {p}")
            else:
                print("  (no cache)")
            print("=" * 40)
        except ImportError:
            print("Skills module not available")
        return 0
    
    if args.clear_cache:
        try:
            from skills.builtin.header_analysis import clear_cache
            if args.clear_cache == "__all__":
                count = clear_cache()
                print(f"Cleared all cache ({count} items)")
            else:
                count = clear_cache(args.clear_cache)
                if count:
                    print(f"Cleared cache for {args.clear_cache}")
                else:
                    print(f"No cache found for {args.clear_cache}")
        except ImportError:
            print("Skills module not available")
        return 0
    
    # List available Skills
    if args.list_skills:
        if not SKILLS_AVAILABLE:
            print("Skills mechanism not available")
            return 1
        manager = SkillManager()
        manager.discover_and_load()
        skills = manager.list_skills()
        print(f"\n{'='*60}")
        print("Available Skills")
        print(f"{'='*60}")
        for skill in skills:
            print(f"\n[{skill['name']}] v{skill['version']}")
            print(f"  Description: {skill['description']}")
            print(f"  Phases: {', '.join(skill['phases'])}")
            if skill['protocols']:
                print(f"  Protocols: {', '.join(skill['protocols'])}")
            print(f"  Priority: {skill['priority']}")
            # Show Tool info
            if skill.get('is_tool'):
                print(f"  🔧 Can be called as Tool")
        print(f"\n{'='*60}")
        return 0
    
    # Following commands require -f argument
    if not args.pcap:
        parser.error("Analysis mode requires -f/--pcap argument")
    
    # Setup stdout logging to file if log_dir is specified
    tee_stream = None
    original_stdout = sys.stdout
    if args.log_dir:
        log_path = Path(args.log_dir)
        log_path.mkdir(parents=True, exist_ok=True)
        stdout_log_path = log_path / "stdout.log"
        tee_stream = TeeStream(original_stdout, stdout_log_path)
        sys.stdout = tee_stream
        logging.info(f"Stdout will be logged to: {stdout_log_path}")
    
    # Check dependencies
    if not NETZOB_AVAILABLE:
        print("Error: PCAP processing requires Netzob library")
        print("Install command: pip install netzob")
        return 1
    
    if not GEMINI_AVAILABLE:
        print("Error: LLMClient module required")
        print("Please check if utils/llm_client.py exists")
        return 1
    
    # Detect provider and verify API key
    model_name = args.model
    if model_name:
        provider = detect_provider(model_name)
    else:
        provider = PROVIDER_GEMINI
    
    if not check_api_key_configured(provider):
        if provider == PROVIDER_DEEPSEEK:
            print("Error: Please set DEEPSEEK_API_KEY environment variable")
        else:
            print("Error: Please set GEMINI_API_KEY environment variable")
        return 1
    
    try:
        # Determine protocol type
        if args.protocol:
            protocol_type = args.protocol
            logging.info(f"Using user-specified protocol: {protocol_type}")
        else:
            protocol_type = infer_protocol_from_filename(args.pcap)
            logging.info(f"Inferred protocol from filename: {protocol_type}")
        
        # Create Agent
        agent = ProtocolAnalyzerAgent(
            model_name=model_name,
            enable_skills=not args.no_skills,
            use_cache=not args.no_cache,
            max_turns=args.max_turns,
            log_dir=args.log_dir
        )
        
        # Execute analysis
        result = agent.analyze_pcap(args.pcap, protocol_type)
        
        # Output result
        print(f"\n{'='*80}")
        print("Protocol Analysis Complete")
        print(f"{'='*80}")
        
        if result.get('success'):
            print(f"✅ Analysis successful")
            print(f"Conversation turns: {result.get('turns', '?')}")
            
            analysis_result = result.get('result', {})
            print(f"\nProtocol Analysis Result:")
            print(f"Boundary type: {analysis_result.get('boundary_type', 'N/A')}")
            
            if 'fields' in analysis_result:
                fields = analysis_result['fields']
                print(f"\nIdentified {len(fields)} fields:")
                for i, field in enumerate(fields, 1):
                    offset = field.get('offset', '?')
                    size = field.get('size', '?')
                    offset_str = str(offset) if isinstance(offset, int) else f'"{offset}"'
                    size_str = str(size) if isinstance(size, int) else f'"{size}"'
                    print(f"  {i}. {field.get('name', 'unknown'):<20} "
                          f"type={field.get('type', '?'):<12} "
                          f"offset={offset_str:<15} "
                          f"size={size_str}")
            
            # Save result
            if args.log_dir:
                log_path = Path(args.log_dir)
                log_path.mkdir(parents=True, exist_ok=True)
                
                # Save full agent result (including success/turns metadata)
                result_path = log_path / "agent_result.json"
                with open(result_path, 'w') as f:
                    json.dump(result, f, indent=2, ensure_ascii=False)
                print(f"\n📁 Result saved: {result_path}")
                
                # Save analysis result for evaluation (directly contains fields and boundary_type)
                if analysis_result.get('fields'):
                    eval_result_path = log_path / "analysis_result.json"
                    with open(eval_result_path, 'w') as f:
                        json.dump(analysis_result, f, indent=2, ensure_ascii=False)
                    print(f"📁 Evaluation result: {eval_result_path}")
                    
                    # Auto-evaluate (if ground truth exists)
                    gt_dir = Path(__file__).parent / "ground_truth" / "boundaries"
                    # Use pcap filename (without extension) to find ground truth
                    pcap_stem = Path(args.pcap).stem
                    gt_file = gt_dir / f"{pcap_stem}_boundaries.json"
                    if gt_file.exists():
                        try:
                            from tools.evaluate_boundaries import BoundaryEvaluator
                            evaluator = BoundaryEvaluator()
                            eval_output = log_path / "evaluation_report.json"
                            report = evaluator.evaluate(
                                str(eval_result_path), 
                                str(gt_file), 
                                str(eval_output)
                            )
                            metrics = report['overall_metrics']
                            print(f"\n{'='*60}")
                            print(f"Boundary Evaluation Results")
                            print(f"{'='*60}")
                            print(f"  Precision: {metrics['precision']:.4f}")
                            print(f"  Recall:    {metrics['recall']:.4f}")
                            print(f"  F1-Score:  {metrics['f1_score']:.4f}")
                            print(f"📁 Evaluation report: {eval_output}")
                        except ImportError:
                            print("⚠️ Evaluation module not available, skipping auto-evaluation")
                        except Exception as e:
                            print(f"⚠️ Evaluation failed: {e}")
                    else:
                        print(f"⚠️ Ground Truth not found: {gt_file}")
        else:
            print(f"❌ Analysis failed: {result.get('error', 'Unknown error')}")
            print(f"Conversation turns: {result.get('turns', '?')}")
        
        print(f"{'='*80}")
        
        # Restore stdout and close log file
        if tee_stream:
            sys.stdout = original_stdout
            tee_stream.close()
        
        return 0
    
    except Exception as e:
        logging.error(f"Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        
        # Restore stdout and close log file
        if tee_stream:
            sys.stdout = original_stdout
            tee_stream.close()
        
        return 1


if __name__ == "__main__":
    sys.exit(main())