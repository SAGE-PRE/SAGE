#!/usr/bin/env python3
"""Aggregate evaluation results from a specified directory"""

import json
import os
import re
import statistics
from collections import defaultdict
import sys

def aggregate_results(log_dir, detail=False):
    results_by_protocol = defaultdict(list)
    
    # Detect directory structure type
    # Type 1: log_dir/protocol/run_dir/evaluation_report.json (nested structure)
    # Type 2: log_dir/protocol_run/evaluation_report.json (flat structure)
    
    for item in os.listdir(log_dir):
        item_path = os.path.join(log_dir, item)
        if not os.path.isdir(item_path):
            continue
        
        # Check if evaluation_report.json exists directly (flat structure)
        eval_file = os.path.join(item_path, 'evaluation_report.json')
        if os.path.exists(eval_file):
            # Flat structure: extract protocol name from directory name
            # e.g.: smb_100_run1 -> smb_100, custom_iot_100_run3 -> custom_iot_100
            match = re.match(r'^(.+_100)_run\d+$', item)
            if match:
                protocol = match.group(1)
            else:
                protocol = item
            
            with open(eval_file) as f:
                data = json.load(f)
                if 'error' not in data and 'overall_metrics' in data:
                    metrics = data['overall_metrics']
                    results_by_protocol[protocol].append({
                        'precision': metrics.get('precision', 0),
                        'recall': metrics.get('recall', 0),
                        'f1_score': metrics.get('f1_score', 0),
                        'run': item
                    })
        else:
            # Nested structure: traverse subdirectories
            protocol_name = item
            for run_dir in os.listdir(item_path):
                run_path = os.path.join(item_path, run_dir)
                if not os.path.isdir(run_path):
                    continue
                
                eval_file = os.path.join(run_path, 'evaluation_report.json')
                if os.path.exists(eval_file):
                    with open(eval_file) as f:
                        data = json.load(f)
                        if 'error' not in data and 'overall_metrics' in data:
                            metrics = data['overall_metrics']
                            results_by_protocol[protocol_name].append({
                                'precision': metrics.get('precision', 0),
                                'recall': metrics.get('recall', 0),
                                'f1_score': metrics.get('f1_score', 0),
                                'run': run_dir
                            })

    # Print results
    print('=' * 90)
    print(f'Evaluation summary: {log_dir}')
    print('=' * 90)
    
    all_results = []
    
    if detail:
        # Detailed mode: show results for each run
        print(f'\n{"Run Directory":<45} {"Precision":<12} {"Recall":<12} {"F1":<12}')
        print('-' * 90)
        
        for protocol, results in sorted(results_by_protocol.items()):
            for r in sorted(results, key=lambda x: x['run']):
                print(f'{r["run"]:<45} {r["precision"]:<12.4f} {r["recall"]:<12.4f} {r["f1_score"]:<12.4f}')
            all_results.extend(results)
    else:
        # Summary mode: aggregate by protocol
        print(f'\n{"Protocol":<20} {"Runs":<6} {"Precision":<18} {"Recall":<18} {"F1":<18}')
        print('-' * 90)
        
        for protocol, results in sorted(results_by_protocol.items()):
            if len(results) < 2:
                p = results[0]['precision'] if results else 0
                r = results[0]['recall'] if results else 0
                f1 = results[0]['f1_score'] if results else 0
                print(f'{protocol:<20} {len(results):<6} {p:<18.4f} {r:<18.4f} {f1:<18.4f}')
            else:
                precisions = [r['precision'] for r in results]
                recalls = [r['recall'] for r in results]
                f1s = [r['f1_score'] for r in results]
                
                p_str = f'{statistics.mean(precisions):.4f}±{statistics.stdev(precisions):.3f}'
                r_str = f'{statistics.mean(recalls):.4f}±{statistics.stdev(recalls):.3f}'
                f1_str = f'{statistics.mean(f1s):.4f}±{statistics.stdev(f1s):.3f}'
                
                print(f'{protocol:<20} {len(results):<6} {p_str:<18} {r_str:<18} {f1_str:<18}')
            
            all_results.extend(results)
    
    # Overall statistics
    if len(all_results) >= 2:
        print('-' * 90)
        
        precisions = [r['precision'] for r in all_results]
        recalls = [r['recall'] for r in all_results]
        f1s = [r['f1_score'] for r in all_results]
        
        print(f'\nTotal: {len(all_results)} experiments')
        print(f'\nOverall metrics:')
        print(f'  Precision: {statistics.mean(precisions):.4f} ± {statistics.stdev(precisions):.4f}')
        print(f'  Recall:    {statistics.mean(recalls):.4f} ± {statistics.stdev(recalls):.4f}')
        print(f'  F1:        {statistics.mean(f1s):.4f} ± {statistics.stdev(f1s):.4f}')
        
        print(f'\nRange:')
        print(f'  Precision: [{min(precisions):.4f}, {max(precisions):.4f}]')
        print(f'  Recall:    [{min(recalls):.4f}, {max(recalls):.4f}]')
        print(f'  F1:        [{min(f1s):.4f}, {max(f1s):.4f}]')
        
        # Stability
        cv_p = statistics.stdev(precisions) / statistics.mean(precisions) if statistics.mean(precisions) > 0 else 0
        cv_r = statistics.stdev(recalls) / statistics.mean(recalls) if statistics.mean(recalls) > 0 else 0
        cv_f1 = statistics.stdev(f1s) / statistics.mean(f1s) if statistics.mean(f1s) > 0 else 0
        
        print(f'\nStability (1-CV):')
        print(f'  Precision: {1-cv_p:.4f}')
        print(f'  Recall:    {1-cv_r:.4f}')
        print(f'  F1:        {1-cv_f1:.4f}')

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Aggregate evaluation results')
    parser.add_argument('log_dir', help='Path to log directory')
    parser.add_argument('--detail', action='store_true', help='Show detailed results for each run')
    args = parser.parse_args()
    aggregate_results(args.log_dir, detail=args.detail)
