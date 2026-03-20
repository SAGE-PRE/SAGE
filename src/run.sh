#!/bin/bash
# Navigate to the project root directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${SCRIPT_DIR}/.."

# Display help information
show_help() {
  echo "Usage: $0 [OPTIONS] [PROTOCOLS...]"
  echo ""
  echo "Options:"
  echo "  -h, --help       Show this help message"
  echo "  -d, --dir DIR    Specify output directory name (default: auto-increment runN)"
  echo "  -n, --repeat N   Run each protocol N times concurrently (default: 1)"
  echo "  -m, --model M    Specify the model to use (default: deepseek-chat)"
  echo ""
  echo "Arguments:"
  echo "  PROTOCOLS        One or more protocol names to run (e.g., smb smb2 modbus)"
  echo "                   If not specified, runs all protocols in data/*_100.pcap"
  echo ""
  echo "Examples:"
  echo "  $0                        # Run all protocols once"
  echo "  $0 smb smb2               # Run only smb and smb2"
  echo "  $0 -d test_smb smb        # Run smb, output to logs/test_smb"
  echo "  $0 -n 10 smb              # Run smb 10 times concurrently"
  echo "  $0 -n 5 -d exp1 modbus    # Run modbus 5 times, output to logs/exp1"
  echo "  $0 -m deepseek-reasoner   # Run with reasoner model"
  echo "  $0 modbus s7comm dnp3     # Run modbus, s7comm, and dnp3"
}

# Parse arguments
protocols=()
custom_dir=""
repeat_count=1
model="deepseek-chat"

while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help)
      show_help
      exit 0
      ;;
    -d|--dir)
      custom_dir="$2"
      shift 2
      ;;
    -n|--repeat)
      repeat_count="$2"
      if ! [[ "$repeat_count" =~ ^[0-9]+$ ]] || [ "$repeat_count" -lt 1 ]; then
        echo "Error: -n/--repeat must be a positive integer"
        exit 1
      fi
      shift 2
      ;;
    -m|--model)
      model="$2"
      shift 2
      ;;
    -*)
      echo "Unknown option: $1"
      show_help
      exit 1
      ;;
    *)
      protocols+=("$1")
      shift
      ;;
  esac
done

# Determine output directory
if [ -n "$custom_dir" ]; then
  run_dir="logs/${custom_dir}"
else
  # Auto-determine next run directory number
  run_num=1
  while [ -d "logs/run${run_num}" ]; do
    run_num=$((run_num + 1))
  done
  run_dir="logs/run${run_num}"
fi

echo "Creating run directory: $run_dir"
mkdir -p "$run_dir"

# Determine pcap file list to process
if [ ${#protocols[@]} -eq 0 ]; then
  # No protocol specified, run all
  pcap_files=(data/*_100.pcap)
else
  # Build pcap file list by protocol name
  pcap_files=()
  for proto in "${protocols[@]}"; do
    pcap_file="data/${proto}_100.pcap"
    if [ -f "$pcap_file" ]; then
      pcap_files+=("$pcap_file")
    else
      echo "Warning: pcap file not found: $pcap_file"
    fi
  done
  
  if [ ${#pcap_files[@]} -eq 0 ]; then
    echo "Error: No valid pcap files found for specified protocols"
    exit 1
  fi
fi

echo "Protocols to run: ${#pcap_files[@]}"
echo "Repeat count: ${repeat_count}"
echo "Model: ${model}"
total_jobs=$((${#pcap_files[@]} * repeat_count))
echo "Total jobs: ${total_jobs}"

job_count=0
for pcap in "${pcap_files[@]}"; do
  name=$(basename "$pcap" .pcap)
  
  for ((i=1; i<=repeat_count; i++)); do
    if [ "$repeat_count" -eq 1 ]; then
      # Single run, use protocol name as directory
      proto_dir="${run_dir}/${name}"
    else
      # Multiple runs, use protocol_runN format
      proto_dir="${run_dir}/${name}_run${i}"
    fi
    mkdir -p "$proto_dir"
    
    echo "Starting: $name (run $i/$repeat_count) -> $proto_dir"
    python src/protocol_analyzer.py \
      -f "$pcap" \
      --log-dir "$proto_dir" \
      --max-turns 30 \
      -m "$model" \
      > "${proto_dir}/run.log" 2>&1 &
    
    job_count=$((job_count + 1))
  done
done

echo ""
echo "All ${job_count} jobs started in $run_dir"
echo "Use 'jobs' or 'ps aux | grep protocol_analyzer' to monitor."
wait
echo "All jobs completed."

# Generate aggregated evaluation report
echo ""
echo "Generating evaluation summary..."
python evaluation/evaluate_boundaries.py batch \
  -l "$run_dir" \
  -g data/ground_truth/boundaries \
  -o "${run_dir}/evaluation_summary.json"

echo ""
echo "Summary saved to: ${run_dir}/evaluation_summary.json"
