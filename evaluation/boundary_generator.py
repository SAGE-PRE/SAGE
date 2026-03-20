#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Protocol Field Boundary Generation Algorithm

Generate boundary sets from protocol definition templates and PCAP files for boundary evaluation tasks.
Supports static and dynamic boundary protocols, including variable reference system.
"""

import json
import os
import struct
import logging
from typing import Dict, List, Set, Any, Union, Optional, Tuple
from pathlib import Path
import re

# Import unified PCAP extraction module
try:
    from utils.pcap_extractor import PCAPExtractor, infer_protocol_from_filename, NETZOB_AVAILABLE
except ImportError:
    # If running as standalone script
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from utils.pcap_extractor import PCAPExtractor, infer_protocol_from_filename, NETZOB_AVAILABLE


class BoundaryGenerator:
    """Boundary Generator: Generate boundary sets from protocol definitions and packet instances"""
    
    def __init__(self, protocol_def: Dict[str, Any]):
        """
        Initialize boundary generator
        
        Args:
            protocol_def: Protocol definition dictionary
        """
        self.protocol_def = protocol_def
        self.protocol_name = protocol_def.get('protocol', 'Unknown')
        self.boundary_type = protocol_def.get('boundary_type', 'dynamic')
        self.fields = protocol_def.get('fields', [])
        self.skip_bytes = protocol_def.get('skip_bytes', 0)  # Support skipping encapsulation headers
        
        logging.info(f"Initialized boundary generator for {self.protocol_name} ({self.boundary_type}, skip_bytes={self.skip_bytes})")
    
    def generate_boundaries(self, packet_bytes: bytes) -> List[int]:
        """
        Generate boundary set from protocol definition and packet instance
        
        Args:
            packet_bytes: Packet byte array (data after skipping encapsulation header)
            
        Returns:
            boundaries: Field boundary set (sorted list, excluding 0 and packet_length)
        """
        packet_length = len(packet_bytes)
        
        if self.boundary_type == 'static':
            static_bounds = self.protocol_def.get('static_boundaries', [])
            # Filter out 0, packet_length, and boundaries exceeding packet length
            return [b for b in static_bounds if 0 < b < packet_length]
        
        boundaries = set()
        context = {}  # Context for storing field information
        
        try:
            for field in self.fields:
                field_name = field.get('name', 'unknown')
                
                # Calculate field offset
                offset = self._evaluate_offset(field['offset'], context, packet_bytes)
                if offset is None or offset < 0 or offset > packet_length:
                    logging.debug(f"Skipping field {field_name}: invalid offset {offset}")
                    continue
                
                # Don't add 0 and packet_length as boundaries (inherent boundaries)
                if 0 < offset < packet_length:
                    boundaries.add(offset)
                
                # Calculate field size
                size = self._evaluate_size(field['size'], context, packet_bytes, offset)
                if size is None or size < 0:
                    logging.debug(f"Skipping field {field_name}: invalid size {size}")
                    continue
                
                # Ensure not exceeding packet length
                if offset + size > packet_length:
                    size = packet_length - offset
                
                # Parse field value and save to context
                field_value = self._parse_field_value(
                    packet_bytes[offset:offset+size], 
                    field.get('type', 'bytes')
                )
                
                context[field_name] = {
                    'offset': offset,
                    'size': size,
                    'end': offset + size,
                    'value': field_value
                }
                
                logging.debug(f"Field {field_name}: offset={offset}, size={size}, end={offset+size}, value={field_value}")
                
        except Exception as e:
            logging.error(f"Error generating boundaries for {self.protocol_name}: {e}")
            
        return sorted(list(boundaries))
    
    def _evaluate_offset(self, offset_rule: Union[int, str], context: Dict, packet_bytes: bytes) -> Optional[int]:
        """Parse offset expression"""
        packet_length = len(packet_bytes)
        
        if isinstance(offset_rule, int):
            return offset_rule
        
        if isinstance(offset_rule, str):
            # Handle position reference: $field_name or $field_name#
            if offset_rule.startswith('$'):
                field_ref = offset_rule[1:]
                if field_ref.endswith('#'):
                    # $field_name# means field end position
                    field_name = field_ref[:-1]
                    if field_name in context:
                        logging.debug(f"Found field reference ${field_name}# = {context[field_name]['end']}")
                        return context[field_name]['end']
                    else:
                        logging.debug(f"Field reference ${field_name}# not found in context: {list(context.keys())}")
                else:
                    # $field_name means field start position
                    if field_ref in context:
                        return context[field_ref]['offset']
            
            # Handle simple value reference: @field_name (no spaces or operators)
            elif offset_rule.startswith('@') and ' ' not in offset_rule and '-' not in offset_rule and '+' not in offset_rule:
                field_name = offset_rule[1:]
                # Check built-in length aliases first
                length_aliases = ['total_length', 'total_len', 'message_length', 'packet_length', 'msg_len']
                if field_name in length_aliases:
                    return packet_length
                if field_name in context:
                    return context[field_name]['value']
            
            # Handle expression evaluation
            else:
                return self._evaluate_expression(offset_rule, context, packet_length)
        
        return None
    
    def _evaluate_size(self, size_rule: Union[int, str], context: Dict, packet_bytes: bytes, current_offset: int) -> Optional[int]:
        """Parse size expression"""
        packet_length = len(packet_bytes)
        
        if isinstance(size_rule, int):
            return size_rule
        
        if isinstance(size_rule, str):
            # Special keyword: remaining
            if size_rule == 'remaining':
                return packet_length - current_offset
            
            # Special keyword: variable (skip size calculation for this field)
            if size_rule == 'variable':
                return 0
            
            # Handle simple value reference: @field_name (no spaces or operators)
            elif size_rule.startswith('@') and ' ' not in size_rule and '-' not in size_rule and '+' not in size_rule:
                field_name = size_rule[1:]
                # Check built-in length aliases first
                length_aliases = ['total_length', 'total_len', 'message_length', 'packet_length', 'msg_len']
                if field_name in length_aliases:
                    return packet_length
                if field_name in context:
                    return context[field_name]['value']
            
            # Handle expression evaluation (including complex @ references)
            else:
                return self._evaluate_expression(size_rule, context, packet_length)
        
        return None
    
    def _evaluate_expression(self, expression: str, context: Dict, packet_length: int = None) -> Optional[int]:
        """Evaluate expression (e.g., "@length - 2", "12 + @param_len", "@total_length - 8")"""
        try:
            # Replace variable references
            expr = expression
            
            # Replace built-in @total_length with packet length
            if packet_length is not None:
                length_aliases = ['@total_length', '@total_len', '@message_length', '@packet_length', '@msg_len']
                for alias in length_aliases:
                    expr = expr.replace(alias, str(packet_length))
            
            # Replace @field_name with actual value
            for field_name, field_info in context.items():
                if 'value' in field_info:
                    expr = expr.replace(f'@{field_name}', str(field_info['value']))
            
            # Replace $field_name with field start position
            for field_name, field_info in context.items():
                if 'offset' in field_info:
                    expr = expr.replace(f'${field_name}', str(field_info['offset']))
            
            # Replace $field_name# with field end position
            for field_name, field_info in context.items():
                if 'end' in field_info:
                    expr = expr.replace(f'${field_name}#', str(field_info['end']))
            
            logging.debug(f"Expression '{expression}' -> '{expr}'")
            
            # Safe expression evaluation (only allow basic math operations)
            if re.match(r'^[\d\s+\-*/()]+$', expr):
                result = int(eval(expr))
                logging.debug(f"Expression result: {result}")
                return result
            else:
                logging.debug(f"Expression '{expr}' contains invalid characters")
            
        except Exception as e:
            logging.error(f"Failed to evaluate expression '{expression}': {e}")
        
        return None
    
    def _parse_field_value(self, data: bytes, field_type: str) -> int:
        """Parse field value"""
        if not data:
            return 0
        
        try:
            if field_type == 'uint8':
                return struct.unpack('B', data[:1])[0]
            elif field_type == 'uint16_be':
                return struct.unpack('>H', data[:2])[0]
            elif field_type == 'uint16_le':
                return struct.unpack('<H', data[:2])[0]
            elif field_type == 'uint32_be':
                return struct.unpack('>I', data[:4])[0]
            elif field_type == 'uint32_le':
                return struct.unpack('<I', data[:4])[0]
            elif field_type == 'uint64_be':
                return struct.unpack('>Q', data[:8])[0]
            elif field_type == 'uint64_le':
                return struct.unpack('<Q', data[:8])[0]
            elif field_type in ['bytes', 'string', 'timestamp_64']:
                return len(data)  # For byte arrays, return length
            else:
                return len(data)
        except struct.error:
            return len(data)


class PCAPBoundaryProcessor:
    """PCAP File Boundary Processor"""
    
    def __init__(self, ground_truth_dir: str, data_dir: str, output_dir: str):
        """
        Initialize PCAP boundary processor
        
        Args:
            ground_truth_dir: Protocol definition directory
            data_dir: PCAP file directory
            output_dir: Output result directory
        """
        self.ground_truth_dir = Path(ground_truth_dir)
        self.data_dir = Path(data_dir)
        self.output_dir = Path(output_dir)
        
        # Create output directory
        self.output_dir.mkdir(exist_ok=True)
        
        # Load protocol definitions
        self.protocols = self._load_protocols()
        
        # Initialize PCAP extractor
        self.pcap_extractor = PCAPExtractor(use_netzob=True)
        
        logging.info(f"Loaded {len(self.protocols)} protocol definitions")
        logging.info(f"Data directory: {self.data_dir}")
        logging.info(f"Output directory: {self.output_dir}")
    
    def _load_protocols(self) -> Dict[str, Dict]:
        """Load all protocol definitions"""
        protocols = {}
        
        for json_file in self.ground_truth_dir.glob('*.json'):
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    protocol_def = json.load(f)
                    protocol_name = protocol_def.get('protocol', json_file.stem)
                    protocols[json_file.stem] = protocol_def
                    logging.info(f"Loaded protocol: {protocol_name}")
            except Exception as e:
                logging.error(f"Failed to load {json_file}: {e}")
        
        return protocols
    
    def _extract_messages_from_pcap(self, pcap_path: Path, protocol_type: str) -> List[bytes]:
        """Extract messages from PCAP file - using unified pcap_extractor module"""
        if not NETZOB_AVAILABLE:
            logging.error("Netzob is required for PCAP processing")
            return []
        
        try:
            # Get skip_bytes from protocol definition
            protocol_def = self.protocols.get(protocol_type, {})
            skip_bytes = protocol_def.get('skip_bytes', 0)
            
            # Use unified extractor
            return self.pcap_extractor.extract_raw_bytes(
                str(pcap_path), 
                protocol_type, 
                skip_bytes=skip_bytes
            )
            
        except Exception as e:
            logging.error(f"Failed to process {pcap_path}: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def process_all_pcaps(self, pattern: str = '*_100.pcap'):
        """Process PCAP files matching pattern
        
        Args:
            pattern: File pattern, default '*_100.pcap'
        """
        for pcap_file in sorted(self.data_dir.glob(pattern)):
            # Infer protocol type from filename, e.g., "ntp_100.pcap" -> "ntp", "s7comm_plus_100.pcap" -> "s7comm_plus"
            stem = pcap_file.stem
            # Try to remove trailing number part
            parts = stem.rsplit('_', 1)
            if len(parts) == 2 and parts[1].isdigit():
                protocol_type = parts[0]
            else:
                protocol_type = stem.split('_')[0]
            
            if protocol_type not in self.protocols:
                # Try using first part separated by underscore
                alt_type = stem.split('_')[0]
                if alt_type in self.protocols:
                    protocol_type = alt_type
                else:
                    logging.warning(f"No protocol definition found for {protocol_type}, skipping {pcap_file.name}")
                    continue
            
            logging.info(f"\n{'='*60}")
            logging.info(f"Processing {pcap_file.name} ({protocol_type})")
            logging.info(f"{'='*60}")
            
            # Extract messages
            messages = self._extract_messages_from_pcap(pcap_file, protocol_type)
            if not messages:
                logging.warning(f"No messages extracted from {pcap_file.name}")
                continue
            
            # Generate boundaries
            self._generate_boundaries_for_protocol(protocol_type, messages, pcap_file.stem)
    
    def _generate_boundaries_for_protocol(self, protocol_type: str, messages: List[bytes], pcap_stem: str = None):
        """Generate boundaries for specific protocol"""
        protocol_def = self.protocols[protocol_type]
        generator = BoundaryGenerator(protocol_def)
        
        results = []
        
        for i, msg_bytes in enumerate(messages):
            try:
                boundaries = generator.generate_boundaries(msg_bytes)
                
                result = {
                    'message_id': i,
                    'packet_hex': msg_bytes.hex().upper(),
                    'packet_length': len(msg_bytes),
                    'boundaries': boundaries,
                    'boundary_count': len(boundaries)
                }
                
                results.append(result)
                
                if i < 5:  # Show details for first 5 messages
                    logging.info(f"Message {i}: {len(msg_bytes)} bytes, {len(boundaries)} boundaries")
                    logging.info(f"  Hex: {msg_bytes.hex()[:60]}...")
                    logging.info(f"  Boundaries: {boundaries}")
                
            except Exception as e:
                logging.error(f"Failed to process message {i}: {e}")
        
        # Save results - use pcap filename as output filename
        output_name = pcap_stem if pcap_stem else protocol_type
        output_file = self.output_dir / f"{output_name}_boundaries.json"
        
        output_data = {
            'protocol': protocol_def.get('protocol', protocol_type),
            'boundary_type': protocol_def.get('boundary_type', 'dynamic'),
            'total_messages': len(results),
            'messages': results
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        logging.info(f"Saved {len(results)} message boundaries to {output_file}")
        
        # Statistics
        boundary_counts = [r['boundary_count'] for r in results]
        logging.info(f"Boundary statistics:")
        logging.info(f"  Min boundaries: {min(boundary_counts) if boundary_counts else 0}")
        logging.info(f"  Max boundaries: {max(boundary_counts) if boundary_counts else 0}")
        logging.info(f"  Avg boundaries: {sum(boundary_counts)/len(boundary_counts):.1f}" if boundary_counts else 0)


def main():
    """Main function"""
    # Get parent directory of script as project root
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(project_root / 'boundary_generation.log')
        ]
    )
    
    # Check Netzob availability
    if not NETZOB_AVAILABLE:
        logging.error("Netzob library is required. Install with: pip install netzob")
        return
    
    # Initialize processor - use paths relative to project root
    processor = PCAPBoundaryProcessor(
        ground_truth_dir=str(project_root / 'ground_truth' / 'templates'),
        data_dir=str(project_root / 'data'),
        output_dir=str(project_root / 'ground_truth' / 'boundaries')
    )
    
    # Process all PCAP files
    processor.process_all_pcaps()
    
    logging.info("\n" + "="*60)
    logging.info("Boundary generation completed!")
    logging.info("="*60)


if __name__ == "__main__":
    main()