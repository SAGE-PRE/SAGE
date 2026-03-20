#!/usr/bin/env python3
"""
Boundary Recognition Evaluation Script
Evaluate protocol analysis results against Ground Truth for boundary recognition accuracy
"""

import json
import logging
import argparse
import sys
import re
from pathlib import Path
from typing import Dict, List, Set, Any, Tuple
from collections import defaultdict
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns


# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.field_boundary import FieldBoundaryCalculator


class BoundaryEvaluator:
    """Boundary Evaluator"""
    
    def __init__(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    def load_analysis_result(self, filepath: str) -> Dict[str, Any]:
        """Load analysis result"""
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def load_ground_truth(self, filepath: str) -> Dict[str, Any]:
        """Load Ground Truth"""
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def generate_boundaries_for_message(
        self, 
        fields: List[Dict[str, Any]], 
        packet_hex: str
    ) -> Tuple[Set[int], int]:
        """Generate boundary set for single packet
        
        Uses FieldBoundaryCalculator for consistent parsing logic.
        
        Args:
            fields: Field definition list
            packet_hex: Packet hex string
        
        Returns:
            (boundary position set, packet length) - excluding 0 and packet_length as inherent boundaries
        
        Raises:
            ValueError: When field definition has boundary errors
        """
        return FieldBoundaryCalculator.generate_boundaries_for_message(fields, packet_hex)
    
    def evaluate_single_message(
        self, 
        inferred_boundaries: Set[int], 
        ground_truth_boundaries: Set[int],
        packet_length: int
    ) -> Dict[str, Any]:
        """Evaluate boundary recognition result for single packet
        
        Args:
            inferred_boundaries: Inferred boundary set I (excluding inherent boundaries)
            ground_truth_boundaries: Ground Truth boundary set G (may contain inherent boundaries)
            packet_length: Packet length, for excluding inherent boundaries
        
        Returns:
            Evaluation metrics dictionary
        """
        # Exclude inherent boundaries (0 and packet_length) from ground_truth
        gt_boundaries = ground_truth_boundaries - {0, packet_length}
        
        # Calculate intersection and difference
        tp_boundaries = inferred_boundaries & gt_boundaries
        fp_boundaries = inferred_boundaries - gt_boundaries
        fn_boundaries = gt_boundaries - inferred_boundaries
        
        tp = len(tp_boundaries)
        fp = len(fp_boundaries)
        fn = len(fn_boundaries)
        
        # Calculate metrics
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        return {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "tp_boundaries": sorted(list(tp_boundaries)),
            "fp_boundaries": sorted(list(fp_boundaries)),
            "fn_boundaries": sorted(list(fn_boundaries)),
            "inferred_boundaries": sorted(list(inferred_boundaries)),
            "ground_truth_boundaries": sorted(list(gt_boundaries))  # GT after excluding inherent boundaries
        }
    
    def evaluate(
        self, 
        analysis_result_path: str, 
        ground_truth_path: str,
        output_path: str = None
    ) -> Dict[str, Any]:
        """Execute complete evaluation workflow
        
        Args:
            analysis_result_path: Analysis result file path
            ground_truth_path: Ground Truth file path
            output_path: Evaluation report output path (optional)
        
        Returns:
            Evaluation report dictionary
        
        Raises:
            ValueError: When field definition has boundary errors
        """
        logging.info(f"Loading analysis result from: {analysis_result_path}")
        analysis_result = self.load_analysis_result(analysis_result_path)
        
        logging.info(f"Loading ground truth from: {ground_truth_path}")
        ground_truth = self.load_ground_truth(ground_truth_path)
        
        fields = analysis_result['fields']
        messages = ground_truth['messages']
        
        logging.info(f"Evaluating {len(messages)} messages...")
        
        # Per-message evaluation
        message_results = []
        total_tp = 0
        total_fp = 0
        total_fn = 0
        boundary_errors = []  # Record boundary errors
        
        for msg in messages:
            msg_id = msg['message_id']
            packet_hex = msg['packet_hex']
            gt_boundaries = set(msg['boundaries'])
            packet_length = msg['packet_length']
            
            # Generate inferred boundaries
            try:
                inferred_boundaries, pkt_len = self.generate_boundaries_for_message(fields, packet_hex)
            except ValueError as e:
                # Field boundary error, record and continue checking other messages
                boundary_errors.append({
                    'message_id': msg_id,
                    'error': str(e)
                })
                continue
            except Exception as e:
                logging.error(f"Failed to generate boundaries for message {msg_id}: {e}")
                inferred_boundaries = set()
                pkt_len = packet_length
            
            # Evaluate (excluding inherent boundaries 0 and packet_length)
            result = self.evaluate_single_message(inferred_boundaries, gt_boundaries, pkt_len)
            result['message_id'] = msg_id
            result['packet_hex'] = packet_hex
            result['packet_length'] = packet_length
            
            message_results.append(result)
            
            total_tp += result['tp']
            total_fp += result['fp']
            total_fn += result['fn']
        
        # If boundary errors exist, raise exception and skip this run
        if boundary_errors:
            error_count = len(boundary_errors)
            first_error = boundary_errors[0]['error']
            raise ValueError(f"Field boundary errors in {error_count} message(s): {first_error}")
        
        # Calculate overall metrics
        overall_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
        overall_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
        overall_f1 = 2 * (overall_precision * overall_recall) / (overall_precision + overall_recall) \
                     if (overall_precision + overall_recall) > 0 else 0.0
        
        # Build evaluation report
        report = {
            "analysis_result_file": analysis_result_path,
            "ground_truth_file": ground_truth_path,
            "boundary_type": analysis_result.get('boundary_type', 'unknown'),
            "total_messages": len(messages),
            "total_fields": len(fields),
            "overall_metrics": {
                "total_tp": total_tp,
                "total_fp": total_fp,
                "total_fn": total_fn,
                "precision": round(overall_precision, 4),
                "recall": round(overall_recall, 4),
                "f1_score": round(overall_f1, 4)
            },
            "message_details": message_results
        }
        
        # Save report
        if output_path:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            logging.info(f"Evaluation report saved to: {output_path}")
        
        return report
    
    def batch_evaluate(
        self,
        log_dir: str,
        ground_truth_dir: str,
        output_path: str = None
    ) -> Dict[str, Any]:
        """Batch evaluate all analysis results in directory
        
        Args:
            log_dir: Log directory (e.g., logs/20260113)
            ground_truth_dir: Ground Truth directory (e.g., ground_truth/boundaries)
            output_path: Summary report output path (optional)
        
        Returns:
            Batch evaluation summary report
        """
        log_path = Path(log_dir)
        gt_path = Path(ground_truth_dir)
        
        results = []
        
        # Find all analysis_result.json
        for analysis_file in log_path.rglob('analysis_result.json'):
            # Infer protocol name from path
            # Support two directory structures:
            # 1. logs/{runN}/{protocol_100}/analysis_result.json (new structure)
            # 2. logs/{runN}/{protocol_100_runN}/analysis_result.json (repeated runs)
            # 3. logs/{date}/{protocol}/{run_id}/analysis_result.json (old structure)
            run_dir = analysis_file.parent
            protocol_dir_name = run_dir.name  # e.g., "custom_iot_100" or "smb_100_run8"
            
            # Extract protocol name from directory name
            # Handle _runN suffix from repeated runs (e.g., smb_100_run8 -> smb_100)
            run_suffix_match = re.match(r'^(.+_100)_run\d+$', protocol_dir_name)
            if run_suffix_match:
                protocol = run_suffix_match.group(1)  # e.g., "smb_100"
                protocol_base = protocol[:-4]  # Remove _100, e.g., "smb"
            elif protocol_dir_name.endswith('_100'):
                protocol = protocol_dir_name  # Keep full name like custom_iot_100
                protocol_base = protocol_dir_name[:-4]  # Remove _100
            else:
                protocol = protocol_dir_name
                protocol_base = protocol_dir_name
            
            # Find corresponding Ground Truth
            # Try multiple naming patterns
            possible_gt_names = [
                f"{protocol}_boundaries.json",           # custom_iot_100_boundaries.json
                f"{protocol_base}_100_boundaries.json",  # custom_iot_100_boundaries.json (from base)
                f"{protocol_base}_boundaries.json",      # custom_iot_boundaries.json
            ]
            
            gt_file = None
            for name in possible_gt_names:
                candidate = gt_path / name
                if candidate.exists():
                    gt_file = candidate
                    break
            
            if gt_file is None:
                logging.warning(f"No ground truth found for {protocol}, skipping {analysis_file}")
                continue
            
            logging.info(f"Evaluating: {run_dir.name}")
            
            try:
                # Evaluate single file
                eval_output = run_dir / "evaluation_report.json"
                report = self.evaluate(str(analysis_file), str(gt_file), str(eval_output))
                
                results.append({
                    "protocol": protocol,
                    "run_id": run_dir.name,
                    "analysis_file": str(analysis_file),
                    "ground_truth_file": str(gt_file),
                    "total_messages": report['total_messages'],
                    "total_fields": report['total_fields'],
                    "precision": report['overall_metrics']['precision'],
                    "recall": report['overall_metrics']['recall'],
                    "f1_score": report['overall_metrics']['f1_score'],
                })
            except Exception as e:
                logging.error(f"Error evaluating {analysis_file}: {e}")
                results.append({
                    "protocol": protocol,
                    "run_id": run_dir.name,
                    "analysis_file": str(analysis_file),
                    "error": str(e),
                })
        
        # Calculate summary statistics
        valid_results = [r for r in results if 'error' not in r]
        
        if valid_results:
            avg_precision = sum(r['precision'] for r in valid_results) / len(valid_results)
            avg_recall = sum(r['recall'] for r in valid_results) / len(valid_results)
            # Directly average F1 scores (more accurate than recalculating from avg P/R)
            avg_f1 = sum(r['f1_score'] for r in valid_results) / len(valid_results)
        else:
            avg_precision = avg_recall = avg_f1 = 0.0
        
        # Aggregate statistics by protocol
        protocol_stats = self._compute_protocol_stats(results)
        
        # Calculate overall stability metrics across all runs
        overall_stability = self._compute_overall_stability(valid_results)
        
        summary = {
            "log_dir": str(log_path),
            "ground_truth_dir": str(gt_path),
            "total_evaluated": len(valid_results),
            "total_errors": len(results) - len(valid_results),
            "average_metrics": {
                "precision": round(avg_precision, 4),
                "recall": round(avg_recall, 4),
                "f1_score": round(avg_f1, 4),
            },
            "overall_stability": overall_stability,
            "protocol_summary": protocol_stats,
            "results": results,
        }
        
        # Print protocol summary (sorted by F1 descending)
        self._print_protocol_summary(protocol_stats)
        
        # Print overall stability
        self._print_overall_stability(overall_stability)
        
        # Print detailed results (sorted by F1 descending, errors at bottom)
        print(f"\n{'='*70}")
        print("Detailed Run Results")
        print(f"{'='*70}")
        print(f"{'Protocol':<30} {'Precision':>12} {'Recall':>12} {'F1':>12}")
        print(f"{'-'*70}")
        
        # Separate successful and failed results
        error_details = [r for r in results if 'error' in r]
        success_results = [r for r in results if 'error' not in r]
        
        # Sort successful results by F1 descending
        success_results.sort(key=lambda x: x.get('f1_score', 0), reverse=True)
        
        for r in success_results:
            print(f"{r['protocol']:<30} {r['precision']:>12.4f} {r['recall']:>12.4f} {r['f1_score']:>12.4f}")
        
        # Print failed results at the end
        for r in error_details:
            print(f"{r['protocol']:<30} {'ERROR':>12} {'-':>12} {'-':>12}")
        
        print(f"{'-'*70}")
        print(f"{'Overall Average':<30} {avg_precision:>12.4f} {avg_recall:>12.4f} {avg_f1:>12.4f}")
        print(f"{'='*70}")
        print(f"Evaluation succeeded: {len(valid_results)}, Evaluation failed: {len(results) - len(valid_results)}")
        
        # Print error details
        if error_details:
            print(f"\n{'='*100}")
            print("Error Details")
            print(f"{'='*100}")
            for r in error_details:
                print(f"\n📛 {r['run_id']}")
                error_msg = r.get('error', 'Unknown error')
                # Truncate long error messages
                if len(error_msg) > 200:
                    error_msg = error_msg[:200] + "..."
                print(f"   Reason: {error_msg}")
        
        # Save summary report
        if output_path:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)
            print(f"\n📁 Summary report saved to: {output_path}")
        
        if valid_results and output_path:
            output_dir = Path(output_path).parent
            self.plot_results(valid_results, str(output_dir))
        return summary
    
    def _compute_protocol_stats(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Compute aggregated statistics and stability metrics by protocol
        
        Args:
            results: List of all run results
        
        Returns:
            Statistics aggregated by protocol
        """
        import math
        
        # Group by protocol
        protocol_results = defaultdict(list)
        protocol_errors = defaultdict(int)
        
        for r in results:
            protocol = r['protocol']
            if 'error' in r:
                protocol_errors[protocol] += 1
            else:
                protocol_results[protocol].append(r)
        
        protocol_stats = {}
        
        for protocol in sorted(set(r['protocol'] for r in results)):
            valid = protocol_results[protocol]
            errors = protocol_errors[protocol]
            total = len(valid) + errors
            
            if not valid:
                protocol_stats[protocol] = {
                    "total_runs": total,
                    "successful_runs": 0,
                    "failed_runs": errors,
                    "success_rate": 0.0,
                    "metrics": None,
                    "stability": None,
                }
                continue
            
            # Calculate averages
            precisions = [r['precision'] for r in valid]
            recalls = [r['recall'] for r in valid]
            f1_scores = [r['f1_score'] for r in valid]
            
            avg_precision = sum(precisions) / len(precisions)
            avg_recall = sum(recalls) / len(recalls)
            # Directly average F1 scores (more accurate)
            avg_f1 = sum(f1_scores) / len(f1_scores)
            
            # Calculate standard deviation (stability metric)
            def std_dev(values):
                if len(values) < 2:
                    return 0.0
                mean = sum(values) / len(values)
                variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
                return math.sqrt(variance)
            
            std_precision = std_dev(precisions)
            std_recall = std_dev(recalls)
            std_f1 = std_dev(f1_scores)
            
            # Calculate coefficient of variation (CV = std/mean) for relative stability
            cv_precision = std_precision / avg_precision if avg_precision > 0 else 0.0
            cv_recall = std_recall / avg_recall if avg_recall > 0 else 0.0
            cv_f1 = std_f1 / avg_f1 if avg_f1 > 0 else 0.0
            
            # Calculate min/max
            min_precision, max_precision = min(precisions), max(precisions)
            min_recall, max_recall = min(recalls), max(recalls)
            min_f1, max_f1 = min(f1_scores), max(f1_scores)
            
            protocol_stats[protocol] = {
                "total_runs": total,
                "successful_runs": len(valid),
                "failed_runs": errors,
                "success_rate": round(len(valid) / total, 4) if total > 0 else 0.0,
                "metrics": {
                    "precision": {
                        "mean": round(avg_precision, 4),
                        "std": round(std_precision, 4),
                        "cv": round(cv_precision, 4),
                        "min": round(min_precision, 4),
                        "max": round(max_precision, 4),
                    },
                    "recall": {
                        "mean": round(avg_recall, 4),
                        "std": round(std_recall, 4),
                        "cv": round(cv_recall, 4),
                        "min": round(min_recall, 4),
                        "max": round(max_recall, 4),
                    },
                    "f1_score": {
                        "mean": round(avg_f1, 4),
                        "std": round(std_f1, 4),
                        "cv": round(cv_f1, 4),
                        "min": round(min_f1, 4),
                        "max": round(max_f1, 4),
                    },
                },
                "stability": {
                    "avg_cv": round((cv_precision + cv_recall + cv_f1) / 3, 4),
                    "stability_score": round(1 - min((cv_precision + cv_recall + cv_f1) / 3, 1.0), 4),
                    "interpretation": self._interpret_stability((cv_precision + cv_recall + cv_f1) / 3),
                },
            }
        
        return protocol_stats
    
    def _interpret_stability(self, avg_cv: float) -> str:
        """Interpret stability score"""
        if avg_cv < 0.05:
            return "Very Stable"
        elif avg_cv < 0.10:
            return "Stable"
        elif avg_cv < 0.20:
            return "Fairly Stable"
        elif avg_cv < 0.30:
            return "Moderate"
        else:
            return "Unstable"
    
    def _compute_overall_stability(self, valid_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Compute overall stability metrics across all runs
        
        Args:
            valid_results: List of successful evaluation results
        
        Returns:
            Overall stability metrics
        """
        import math
        
        if not valid_results:
            return {
                "total_runs": 0,
                "metrics": None,
                "stability": None,
            }
        
        precisions = [r['precision'] for r in valid_results]
        recalls = [r['recall'] for r in valid_results]
        f1_scores = [r['f1_score'] for r in valid_results]
        
        # Calculate averages
        avg_precision = sum(precisions) / len(precisions)
        avg_recall = sum(recalls) / len(recalls)
        avg_f1 = sum(f1_scores) / len(f1_scores)
        
        # Calculate standard deviation
        def std_dev(values):
            if len(values) < 2:
                return 0.0
            mean = sum(values) / len(values)
            variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
            return math.sqrt(variance)
        
        std_precision = std_dev(precisions)
        std_recall = std_dev(recalls)
        std_f1 = std_dev(f1_scores)
        
        # Calculate coefficient of variation (CV = std/mean)
        cv_precision = std_precision / avg_precision if avg_precision > 0 else 0.0
        cv_recall = std_recall / avg_recall if avg_recall > 0 else 0.0
        cv_f1 = std_f1 / avg_f1 if avg_f1 > 0 else 0.0
        
        # Calculate min/max
        min_precision, max_precision = min(precisions), max(precisions)
        min_recall, max_recall = min(recalls), max(recalls)
        min_f1, max_f1 = min(f1_scores), max(f1_scores)
        
        avg_cv = (cv_precision + cv_recall + cv_f1) / 3
        
        return {
            "total_runs": len(valid_results),
            "metrics": {
                "precision": {
                    "mean": round(avg_precision, 4),
                    "std": round(std_precision, 4),
                    "cv": round(cv_precision, 4),
                    "min": round(min_precision, 4),
                    "max": round(max_precision, 4),
                },
                "recall": {
                    "mean": round(avg_recall, 4),
                    "std": round(std_recall, 4),
                    "cv": round(cv_recall, 4),
                    "min": round(min_recall, 4),
                    "max": round(max_recall, 4),
                },
                "f1_score": {
                    "mean": round(avg_f1, 4),
                    "std": round(std_f1, 4),
                    "cv": round(cv_f1, 4),
                    "min": round(min_f1, 4),
                    "max": round(max_f1, 4),
                },
            },
            "stability": {
                "avg_cv": round(avg_cv, 4),
                "stability_score": round(1 - min(avg_cv, 1.0), 4),
                "interpretation": self._interpret_stability(avg_cv),
            },
        }
    
    def _print_overall_stability(self, overall_stability: Dict[str, Any]):
        """Print overall stability metrics"""
        if not overall_stability or not overall_stability.get('metrics'):
            return
        
        print(f"\n{'='*90}")
        print("Overall Stability Metrics (Across All Runs)")
        print(f"{'='*90}")
        print(f"Total Runs: {overall_stability['total_runs']}")
        print(f"\n{'Metric':<12} {'Mean':>10} {'Std':>10} {'CV':>10} {'Min':>10} {'Max':>10}")
        print(f"{'-'*62}")
        
        metrics = overall_stability['metrics']
        for name in ['precision', 'recall', 'f1_score']:
            m = metrics[name]
            print(f"{name:<12} {m['mean']:>10.4f} {m['std']:>10.4f} {m['cv']:>10.4f} {m['min']:>10.4f} {m['max']:>10.4f}")
        
        print(f"{'-'*62}")
        stab = overall_stability['stability']
        print(f"Stability Score: {stab['stability_score']:.4f} ({stab['interpretation']})")
        print(f"Average CV: {stab['avg_cv']:.4f}")
        print(f"{'='*90}")

    def _print_protocol_summary(self, protocol_stats: Dict[str, Any]):
        """Print protocol summary statistics"""
        
        def get_display_width(s: str) -> int:
            """Calculate display width of string (Chinese characters count as 2)"""
            width = 0
            for char in s:
                if '\u4e00' <= char <= '\u9fff' or '\u3000' <= char <= '\u303f':
                    width += 2
                else:
                    width += 1
            return width
        
        def pad_to_width(s: str, width: int, align: str = 'left') -> str:
            """Pad string to specified display width"""
            current_width = get_display_width(s)
            padding = width - current_width
            if padding <= 0:
                return s
            if align == 'left':
                return s + ' ' * padding
            elif align == 'right':
                return ' ' * padding + s
            else:  # center
                left_pad = padding // 2
                right_pad = padding - left_pad
                return ' ' * left_pad + s + ' ' * right_pad
        
        # Define column widths
        col_widths = {
            'protocol': 15,
            'success': 12,
            'rate': 8,
            'precision': 13,
            'recall': 13,
            'f1': 13,
            'evaluation': 12,
        }
        total_width = sum(col_widths.values()) + 6  # 6 spaces between columns
        
        print(f"\n{'=' * total_width}")
        print("Protocol Summary Statistics")
        print(f"{'=' * total_width}")
        
        # Header
        header = (
            f"{pad_to_width('Protocol', col_widths['protocol'], 'left')}"
            f" {pad_to_width('Success/Total', col_widths['success'], 'right')}"
            f" {pad_to_width('Rate', col_widths['rate'], 'right')}"
            f" {pad_to_width('Precision', col_widths['precision'], 'right')}"
            f" {pad_to_width('Recall', col_widths['recall'], 'right')}"
            f" {pad_to_width('F1', col_widths['f1'], 'right')}"
            f" {pad_to_width('Stability', col_widths['evaluation'], 'right')}"
        )
        print(header)
        print(f"{'-' * total_width}")
        
        total_success = 0
        total_runs = 0
        
        # Sort by F1 mean descending, protocols with no metrics go to the end
        def get_f1_mean(item):
            protocol, stats = item
            if stats['metrics'] is None:
                return -1  # Put failed protocols at the end
            return stats['metrics']['f1_score']['mean']
        
        sorted_protocols = sorted(protocol_stats.items(), key=get_f1_mean, reverse=True)
        
        for protocol, stats in sorted_protocols:
            total_success += stats['successful_runs']
            total_runs += stats['total_runs']
            
            success_str = f"{stats['successful_runs']}/{stats['total_runs']}"
            rate_str = f"{stats['success_rate']*100:.1f}%"
            
            if stats['metrics'] is None:
                row = (
                    f"{pad_to_width(protocol, col_widths['protocol'], 'left')}"
                    f" {pad_to_width(success_str, col_widths['success'], 'right')}"
                    f" {pad_to_width(rate_str, col_widths['rate'], 'right')}"
                    f" {pad_to_width('N/A', col_widths['precision'], 'right')}"
                    f" {pad_to_width('N/A', col_widths['recall'], 'right')}"
                    f" {pad_to_width('N/A', col_widths['f1'], 'right')}"
                    f" {pad_to_width('All Failed', col_widths['evaluation'], 'right')}"
                )
            else:
                m = stats['metrics']
                s = stats['stability']
                # Display mean ± std format
                prec_str = f"{m['precision']['mean']:.3f}±{m['precision']['std']:.3f}"
                rec_str = f"{m['recall']['mean']:.3f}±{m['recall']['std']:.3f}"
                f1_str = f"{m['f1_score']['mean']:.3f}±{m['f1_score']['std']:.3f}"
                
                row = (
                    f"{pad_to_width(protocol, col_widths['protocol'], 'left')}"
                    f" {pad_to_width(success_str, col_widths['success'], 'right')}"
                    f" {pad_to_width(rate_str, col_widths['rate'], 'right')}"
                    f" {pad_to_width(prec_str, col_widths['precision'], 'right')}"
                    f" {pad_to_width(rec_str, col_widths['recall'], 'right')}"
                    f" {pad_to_width(f1_str, col_widths['f1'], 'right')}"
                    f" {pad_to_width(s['interpretation'], col_widths['evaluation'], 'right')}"
                )
            print(row)
        
        print(f"{'-' * total_width}")
        total_str = f"{total_success}/{total_runs}"
        total_rate = f"{total_success/total_runs*100:.1f}%" if total_runs > 0 else "0.0%"
        footer = (
            f"{pad_to_width('Total', col_widths['protocol'], 'left')}"
            f" {pad_to_width(total_str, col_widths['success'], 'right')}"
            f" {pad_to_width(total_rate, col_widths['rate'], 'right')}"
        )
        print(footer)
        print(f"{'=' * total_width}")
    def plot_results(self, valid_results: List[Dict[str, Any]], output_dir: str):
        """
        Draw box plots for evaluation results (F1 only) and generate accompanying text statistics report
        """
        if not valid_results:
            logging.warning("No valid results to plot/analyze.")
            return

        # 1. Prepare data
        df = pd.DataFrame(valid_results)
        output_path_img = Path(output_dir) / "evaluation_boxplot_f1.png"
        output_path_txt = Path(output_dir) / "evaluation_statistics.txt"

        # ---------------------------------------------------------
        # Part A: Draw boxplot
        # ---------------------------------------------------------
        sns.set_theme(style="whitegrid")
        plt.figure(figsize=(12, 8))

        # Sort by F1 median to make chart ordered from high to low
        sorted_indices = df.groupby('protocol')['f1_score'].median().sort_values(ascending=False).index

        ax = sns.boxplot(
            data=df, 
            x='protocol', 
            y='f1_score', 
            order=sorted_indices,  # Apply sorting
            palette="Blues",
            showfliers=False      # Hide outliers in plot for clarity (text report will include statistics)
        )

        plt.title('Boundary Recognition F1-Score Distribution', fontsize=15)
        plt.ylim(0, 1.05)
        plt.ylabel('F1 Score')
        plt.xlabel('Protocol')
        plt.xticks(rotation=45, ha='right') # Tilt labels to prevent overlap
        plt.tight_layout()

        plt.savefig(output_path_img, dpi=300)
        logging.info(f"Boxplot image saved to: {output_path_img}")
        plt.close()

        # ---------------------------------------------------------
        # Part B: Generate text statistics report
        # ---------------------------------------------------------
        stats_list = []
        
        # Calculate statistics for each protocol
        for protocol, group in df.groupby('protocol'):
            scores = group['f1_score']
            desc = scores.describe()
            
            # Calculate IQR (interquartile range)
            q1 = desc['25%']
            q3 = desc['75%']
            iqr = q3 - q1
            
            # Count outliers (Tukey's method)
            lower_bound = q1 - 1.5 * iqr
            upper_bound = q3 + 1.5 * iqr
            outliers = scores[(scores < lower_bound) | (scores > upper_bound)]
            
            stats_list.append({
                'Protocol': protocol,
                'Count': int(desc['count']),
                'Median': desc['50%'],     # Median (box center line)
                'Mean': desc['mean'],      # Mean value
                'Std': desc['std'],        # Standard deviation
                'Min': desc['min'],        # Minimum (worst performance)
                'Max': desc['max'],        # Maximum
                'IQR': iqr,                # Box height (smaller = more stable)
                'Outliers': len(outliers)  # Number of outliers
            })

        # Sort by median descending
        stats_df = pd.DataFrame(stats_list).set_index('Protocol')
        stats_df = stats_df.sort_values(by='Median', ascending=False)

        # Write TXT file
        with open(output_path_txt, 'w', encoding='utf-8') as f:
            f.write("=========================================================\n")
            f.write("        Boundary Recognition Statistical Report          \n")
            f.write("=========================================================\n\n")
            f.write("Metric Definitions:\n")
            f.write("  - Median (50%): The most representative score (middle line of the box).\n")
            f.write("  - IQR (Q3-Q1): Box height. Smaller = More Stable.\n")
            f.write("  - Outliers: Number of runs with extreme deviation.\n\n")
            
            f.write("Detailed Statistics (Sorted by Performance):\n")
            f.write("-" * 105 + "\n")
            # Formatted printing: name takes 20 chars, numbers with decimals
            header = f"{'Protocol':<20} | {'Count':<5} | {'Median':<8} | {'Mean':<8} | {'Min':<8} | {'Max':<8} | {'IQR(Stab)':<10} | {'Outliers':<8}"
            f.write(header + "\n")
            f.write("-" * 105 + "\n")
            
            for protocol, row in stats_df.iterrows():
                line = (f"{str(protocol):<20} | {int(row['Count']):<5} | "
                        f"{row['Median']:.4f}   | {row['Mean']:.4f}   | "
                        f"{row['Min']:.4f}   | {row['Max']:.4f}   | "
                        f"{row['IQR']:.4f}     | {int(row['Outliers']):<8}")
                f.write(line + "\n")
            
            f.write("-" * 105 + "\n")
            
        logging.info(f"Statistical report saved to: {output_path_txt}")
def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Boundary Recognition Evaluation Tool - Evaluate protocol analysis accuracy"
    )
    
    # Create subcommands
    subparsers = parser.add_subparsers(dest='command', help='Evaluation mode')
    
    # Single file evaluation
    single_parser = subparsers.add_parser('single', help='Single file evaluation')
    single_parser.add_argument(
        "-a", "--analysis",
        required=True,
        help="Analysis result file path (analysis_result.json)"
    )
    single_parser.add_argument(
        "-g", "--ground-truth",
        required=True,
        help="Ground Truth file path (*_boundaries.json)"
    )
    single_parser.add_argument(
        "-o", "--output",
        help="Evaluation report output path (default: evaluation_report.json in same directory as analysis result)"
    )
    
    # Batch evaluation
    batch_parser = subparsers.add_parser('batch', help='Batch evaluation')
    batch_parser.add_argument(
        "-l", "--log-dir",
        required=True,
        help="Log directory path (e.g., logs/20260113)"
    )
    batch_parser.add_argument(
        "-g", "--ground-truth-dir",
        default="ground_truth/boundaries",
        help="Ground Truth directory path (default: ground_truth/boundaries)"
    )
    batch_parser.add_argument(
        "-o", "--output",
        help="Summary report output path (optional)"
    )
    
    # Backward compatible command line arguments (no subcommand)
    parser.add_argument("-a", "--analysis", help="Analysis result file path")
    parser.add_argument("-g", "--ground-truth", help="Ground Truth file path")
    parser.add_argument("-o", "--output", help="Output path")
    
    args = parser.parse_args()
    
    evaluator = BoundaryEvaluator()
    
    try:
        if args.command == 'batch':
            # Batch evaluation
            evaluator.batch_evaluate(
                args.log_dir,
                args.ground_truth_dir,
                args.output
            )
        elif args.command == 'single' or (args.analysis and args.ground_truth):
            # Single file evaluation
            if args.command == 'single':
                analysis_path = args.analysis
                gt_path = args.ground_truth
                output = args.output
            else:
                analysis_path = args.analysis
                gt_path = args.ground_truth
                output = args.output
            
            if output:
                output_path = output
            else:
                analysis_dir = Path(analysis_path).parent
                output_path = analysis_dir / "evaluation_report.json"
            
            report = evaluator.evaluate(analysis_path, gt_path, str(output_path))
            
            # Print overall results
            print(f"\n{'='*80}")
            print("Boundary Recognition Evaluation Results")
            print(f"{'='*80}")
            print(f"Boundary type: {report['boundary_type']}")
            print(f"Total messages: {report['total_messages']}")
            print(f"Total fields: {report['total_fields']}")
            print(f"\nOverall metrics:")
            metrics = report['overall_metrics']
            print(f"  TP (Correct): {metrics['total_tp']}")
            print(f"  FP (False):   {metrics['total_fp']}")
            print(f"  FN (Missed):  {metrics['total_fn']}")
            print(f"  Precision:    {metrics['precision']:.4f}")
            print(f"  Recall:       {metrics['recall']:.4f}")
            print(f"  F1-Score:     {metrics['f1_score']:.4f}")
            print(f"\n📁 Detailed report saved to: {output_path}")
            print(f"{'='*80}\n")
        else:
            parser.print_help()
            return 1
            
    except Exception as e:
        logging.error(f"Evaluation failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
