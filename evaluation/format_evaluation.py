#!/usr/bin/env python3
"""
Parse evaluation_summary.json and generate human-readable tables
"""

import json
import sys
import argparse
from pathlib import Path


def format_percent(value):
    """Format percentage"""
    if value is None:
        return "N/A"
    return f"{value * 100:.1f}%"


def format_table(summary_path: str):
    """Generate formatted table"""
    with open(summary_path, 'r') as f:
        data = json.load(f)
    
    # Extract results and sort by F1 score
    results = data.get("results", [])
    successful = [r for r in results if "error" not in r]
    failed = [r for r in results if "error" in r]
    
    # Sort by F1 score descending
    successful.sort(key=lambda x: x.get("f1_score", 0), reverse=True)
    
    # Print summary information
    print("=" * 90)
    print("Protocol Analysis Evaluation Report")
    print("=" * 90)
    print(f"Log directory: {data.get('log_dir', 'N/A')}")
    print(f"Total evaluated: {data.get('total_evaluated', 0)}")
    print(f"Error count: {data.get('total_errors', 0)}")
    print()
    
    # Average metrics
    avg = data.get("average_metrics", {})
    print("Average metrics:")
    print(f"  Precision: {format_percent(avg.get('precision'))}")
    print(f"  Recall:    {format_percent(avg.get('recall'))}")
    print(f"  F1 Score:  {format_percent(avg.get('f1_score'))}")
    print()
    
    # Successful results table
    if successful:
        print("-" * 90)
        print("Successfully analyzed protocols (sorted by F1 score)")
        print("-" * 90)
        
        # Header
        header = f"{'Protocol':<20} {'Messages':>8} {'Fields':>8} {'Precision':>10} {'Recall':>10} {'F1':>10}"
        print(header)
        print("-" * 90)
        
        for r in successful:
            protocol = r.get("protocol", "N/A")
            msgs = r.get("total_messages", 0)
            fields = r.get("total_fields", 0)
            precision = format_percent(r.get("precision"))
            recall = format_percent(r.get("recall"))
            f1 = format_percent(r.get("f1_score"))
            
            row = f"{protocol:<20} {msgs:>8} {fields:>8} {precision:>10} {recall:>10} {f1:>10}"
            print(row)
        
        print("-" * 90)
    
    # Failed results
    if failed:
        print()
        print("-" * 90)
        print("Failed protocol analyses")
        print("-" * 90)
        
        for r in failed:
            protocol = r.get("protocol", "N/A")
            error = r.get("error", "Unknown error")
            # Truncate long error messages
            if len(error) > 70:
                error = error[:67] + "..."
            print(f"{protocol:<20} Error: {error}")
        
        print("-" * 90)
    
    # Performance tiers
    print()
    print("-" * 90)
    print("Performance tier statistics")
    print("-" * 90)
    
    excellent = [r for r in successful if r.get("f1_score", 0) >= 0.8]
    good = [r for r in successful if 0.6 <= r.get("f1_score", 0) < 0.8]
    fair = [r for r in successful if 0.4 <= r.get("f1_score", 0) < 0.6]
    poor = [r for r in successful if r.get("f1_score", 0) < 0.4]
    
    print(f"  Excellent (F1 >= 80%): {len(excellent)}")
    for r in excellent:
        print(f"    - {r['protocol']}: {format_percent(r['f1_score'])}")
    
    print(f"  Good (60% <= F1 < 80%): {len(good)}")
    for r in good:
        print(f"    - {r['protocol']}: {format_percent(r['f1_score'])}")
    
    print(f"  Fair (40% <= F1 < 60%): {len(fair)}")
    for r in fair:
        print(f"    - {r['protocol']}: {format_percent(r['f1_score'])}")
    
    print(f"  Poor (F1 < 40%): {len(poor)}")
    for r in poor:
        print(f"    - {r['protocol']}: {format_percent(r['f1_score'])}")
    
    print(f"  Failed: {len(failed)}")
    for r in failed:
        print(f"    - {r['protocol']}")
    
    print("=" * 90)


def main():
    parser = argparse.ArgumentParser(description="Parse evaluation_summary.json and generate tables")
    parser.add_argument("file", nargs="?", default="logs/run4/evaluation_summary.json",
                        help="Path to evaluation_summary.json file")
    args = parser.parse_args()
    
    summary_path = Path(args.file)
    if not summary_path.exists():
        print(f"Error: File does not exist: {summary_path}")
        sys.exit(1)
    
    format_table(str(summary_path))


if __name__ == "__main__":
    main()
