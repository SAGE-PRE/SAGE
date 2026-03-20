
# SAGE: Skill-Augmented Generative Explorer for Hypothesis-Driven Protocol Reverse Engineering

> Replication package for the paper: *"SAGE: Skill-Augmented Generative Explorer for Hypothesis-Driven Protocol Reverse Engineering"* (ASE 2026)

## Repository Structure

```
sage-framework/
├── README.md                          # This file
├── src/                               # SAGE source code
│   ├── protocol_analyzer.py           # Main agent loop & FSM controller
│   ├── run.sh                         # Entry script for running SAGE
│   ├── __init__.py
│   ├── skills/                        # Skill framework
│   │   ├── base.py                    # Base skill class
│   │   ├── manager.py                 # SkillManager (skill dispatch)
│   │   └── builtin/                   # Built-in verification skills
│   │       ├── byte_analysis.py       # StatisticalProfiling skill
│   │       ├── endianness_detection.py# detect_endianness skill
│   │       ├── field_validation.py    # validate_fields skill
│   │       ├── output_format.py       # Schema output formatter
│   │       └── tlv_detection.py       # TLV structure detection
│   └── utils/                         # Utility modules
│       ├── llm_client.py              # LLM API client (DeepSeek)
│       ├── pcap_extractor.py          # PCAP message extraction
│       ├── message_processor.py       # Message preprocessing & anonymization
│       ├── protocol_format.py         # Protocol format data structures
│       └── field_boundary.py          # Boundary representation
│
├── data/                              # Datasets
│   ├── pcap/                          # PCAP network traces (13 protocols)
│   │   ├── modbus_100.pcap
│   │   ├── dnp3_100.pcap
│   │   ├── s7comm_100.pcap
│   │   ├── s7comm_plus_100.pcap
│   │   ├── omron_fins_100.pcap
│   │   ├── hollysys_100.pcap
│   │   ├── dns_ictf_100.pcap
│   │   ├── dhcp_100.pcap
│   │   ├── ntp_100.pcap
│   │   ├── smb_100.pcap
│   │   ├── smb2_100.pcap
│   │   ├── custom_iot_100.pcap        # Proprietary (designed by authors)
│   │   └── time_sync_100.pcap         # Proprietary (designed by authors)
│   └── ground_truth/
│       ├── boundaries/                # Per-message ground truth boundaries
│       └── templates/                 # Protocol field templates (16 protocols)
│
├── evaluation/                        # Evaluation scripts
│   ├── evaluate_boundaries.py         # Boundary-level P/R/F1 computation
│   ├── aggregate_results.py           # Aggregate multi-run results
│   ├── boundary_generator.py          # Ground truth boundary generator
│   └── format_evaluation.py           # Format & display evaluation results
│
├── scripts/                           # Auxiliary scripts
│   └── generate_custom_protocols.py   # Generator for Custom IoT & Time Sync PCAPs
│
└── appendix/                          # Supplementary appendices (referenced in paper)
    ├── detailed_results/
    │   ├── chat_mode/
    │   │   ├── evaluation_summary.json    # Aggregated statistics (Chat mode)
    │   │   └── per_run_results.json       # Per-run P/R/F1, wall-clock time, turns
    │   └── reasoning_mode/
    │       ├── evaluation_summary.json    # Aggregated statistics (Reasoning mode)
    │       └── per_run_results.json       # Per-run P/R/F1, wall-clock time, turns
    └── protocol_specifications/
        ├── custom_iot.json                # Full spec of Custom IoT protocol
        └── time_sync.json                 # Full spec of Time Sync protocol
```

## Contents Description

### 1. SAGE Source Code (`src/`)

The complete source code of the SAGE framework, including:
- **FSM-governed agent loop** (`protocol_analyzer.py`): Implements the Observe → Hypothesize → Validate → Converge workflow.
- **Skill framework** (`skills/`): The `SkillManager` and five built-in verification skills (`analyze_bytes`, `detect_endianness`, `validate_fields`, `output_format`, `detect_tlv`).
- **Utilities** (`utils/`): LLM client, PCAP extraction, message preprocessing with signature anonymization, and protocol format data structures.

### 2. PCAP Datasets (`data/pcap/`)

Network traces for all 13 protocols evaluated in the paper:
- **ICS Protocols** (6): Modbus/TCP, DNP3, S7Comm, S7Comm Plus, Omron FINS, HollySys
- **IT Infrastructure** (3): DNS, DHCP, NTP
- **File Sharing** (2): SMB, SMB2
- **Proprietary** (2): Custom IoT, Time Sync

Each file contains the first 100 messages used in the evaluation. Public protocol traces are sourced from the NetPlier dataset and the dataset by Qin et al. The two proprietary protocols were generated using `scripts/generate_custom_protocols.py`.

### 3. Evaluation Scripts (`evaluation/`)

Scripts to reproduce the evaluation results reported in the paper, including boundary-level Precision/Recall/F1 computation and multi-run aggregation.

### 4. Supplementary Appendices (`appendix/`)

As referenced in Section 7 (Data Availability) of the paper:

- **(1) Detailed Per-Run Results**: `appendix/detailed_results/{chat_mode,reasoning_mode}/per_run_results.json` — Per-run Precision, Recall, and F1-Score for all 13 protocols under both Chat and Reasoning modes of DeepSeek-V3.2 (10 runs × 13 protocols × 2 modes = 260 data points).

- **(2) Execution Statistics**: Included in the same `per_run_results.json` files — wall-clock execution time (seconds) and FSM reasoning turn counts for each run.

- **(3) Proprietary Protocol Specifications**: `appendix/protocol_specifications/` — Complete specifications of Custom IoT and Time Sync, the two zero-knowledge protocols designed for this evaluation.

## Quick Start

### Prerequisites

- Python 3.10+
- A DeepSeek API key (set as environment variable `DEEPSEEK_API_KEY`)
- `tshark` (Wireshark CLI) for PCAP processing

### Installation

```bash
# Clone the repository
git clone https://github.com/anonymous/sage-framework.git
cd sage-framework

# Install dependencies
pip install -r requirements.txt
```

### Running SAGE

```bash
# Set your API key
export DEEPSEEK_API_KEY="your-api-key-here"

# Analyze a single protocol (e.g., Modbus)
python src/protocol_analyzer.py -f data/pcap/modbus_100.pcap --max-turns 30

# Run all 13 protocols with the batch script
bash src/run.sh

# Run a specific protocol 10 times (for statistical evaluation)
bash src/run.sh -n 10 modbus

# Use reasoning mode (DeepSeek-R1)
bash src/run.sh -m deepseek-reasoner modbus
```

### Evaluation

```bash
# Evaluate a single run against ground truth
python evaluation/evaluate_boundaries.py single \
  -r logs/run1/modbus_100/analysis_result.json \
  -g data/ground_truth/boundaries/modbus_100_boundaries.json

# Batch evaluate all runs in a directory
python evaluation/evaluate_boundaries.py batch \
  -l logs/run1 \
  -g data/ground_truth/boundaries \
  -o logs/run1/evaluation_summary.json
```

## License

This project is licensed under the GNU General Public License v3.0 — see the [LICENSE](LICENSE) file for details.
