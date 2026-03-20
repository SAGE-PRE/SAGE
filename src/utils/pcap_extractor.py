#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PCAP Protocol Data Extraction Module

Unified PCAP reading and protocol data extraction logic, supporting various protocol encapsulation header handling.
Can be reused by boundary_generator.py, llm_boundary_detection_enhanced.py,
single_agent, multi_agent, etc.

Supported protocols:
- SMB/SMB2: Skip 4-byte NetBIOS Session header
- S7comm/S7comm_plus: Skip TPKT(4B) + COTP header
- OMRON FINS: Skip 16-byte FINS/TCP encapsulation header
- CIP: Skip EtherNet/IP + CPF header
- Modbus: Truncate based on length field
- Other protocols: Generic handling
"""

import logging
from typing import List, Dict, Any, Optional, Tuple, Callable
from pathlib import Path
from dataclasses import dataclass
import argparse

# Try import Netzob
try:
    from netzob.Import.PCAPImporter.PCAPImporter import PCAPImporter
    NETZOB_AVAILABLE = True
except ImportError:
    NETZOB_AVAILABLE = False

# Try import Scapy
try:
    from scapy.all import rdpcap, Raw, TCP, UDP, DNS
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


@dataclass
class ExtractedMessage:
    """Extracted message data"""
    data: bytes                    # Protocol data (after skipping encapsulation header)
    original_data: bytes           # Original data
    index: int                     # Message index
    protocol: str                  # Protocol type
    skip_bytes: int = 0            # Skipped bytes count
    
    def to_hex(self) -> str:
        """Convert to hex string"""
        return self.data.hex().upper()
    
    def __len__(self) -> int:
        return len(self.data)


class ProtocolExtractor:
    """Protocol data extractor base class"""
    
    def __init__(self, protocol_name: str):
        self.protocol_name = protocol_name
        self.logger = logging.getLogger(__name__)
    
    def extract(self, data: bytes) -> Optional[bytes]:
        """
        Extract protocol data from raw data
        
        Args:
            data: Raw packet data
            
        Returns:
            Extracted protocol data, None if doesn't match protocol signature
        """
        raise NotImplementedError
    
    def get_skip_bytes(self, data: bytes) -> int:
        """Return number of skipped bytes"""
        return 0


class ModbusExtractor(ProtocolExtractor):
    """Modbus TCP protocol extractor"""
    
    def __init__(self):
        super().__init__('modbus')
    
    def extract(self, data: bytes) -> Optional[bytes]:
        if len(data) < 6:
            return None
        # Truncate based on length field
        length = int.from_bytes(data[4:6], byteorder='big')
        expected_len = 6 + length
        if len(data) > expected_len:
            return data[:expected_len]
        return data
    
    def get_skip_bytes(self, data: bytes) -> int:
        return 0


class SMBExtractor(ProtocolExtractor):
    """SMB protocol extractor - Skip 4-byte NetBIOS Session header"""
    
    def __init__(self):
        super().__init__('smb')
    
    def extract(self, data: bytes) -> Optional[bytes]:
        if len(data) < 8:
            return None
        # Check SMB signature: 0xFF 'SMB' at offset 4
        if data[4:8] != b'\xffSMB':
            return None
        return data[4:]  # Skip NetBIOS header
    
    def get_skip_bytes(self, data: bytes) -> int:
        return 4


class SMB2Extractor(ProtocolExtractor):
    """SMB2 protocol extractor - Skip 4-byte NetBIOS Session header"""
    
    def __init__(self):
        super().__init__('smb2')
    
    def extract(self, data: bytes) -> Optional[bytes]:
        if len(data) < 8:
            return None
        # Check SMB2 signature: 0xFE 'SMB' at offset 4
        if data[4:8] != b'\xfeSMB':
            return None
        return data[4:]  # Skip NetBIOS header
    
    def get_skip_bytes(self, data: bytes) -> int:
        return 4


class S7commExtractor(ProtocolExtractor):
    """S7comm protocol extractor - Skip TPKT(4B) + COTP header"""
    
    def __init__(self):
        super().__init__('s7comm')
        self._last_skip = 0
    
    def extract(self, data: bytes) -> Optional[bytes]:
        if len(data) < 7:
            return None
        # Check TPKT header (0x03, 0x00)
        if data[0:2] != b'\x03\x00':
            return None
        # COTP length at byte 4 (index 4)
        cotp_len = data[4] + 1  # COTP header length = LI + 1
        skip = 4 + cotp_len  # TPKT(4) + COTP
        if len(data) <= skip:
            return None
        # Check S7comm protocol identifier (0x32)
        if data[skip] != 0x32:
            return None
        self._last_skip = skip
        return data[skip:]
    
    def get_skip_bytes(self, data: bytes) -> int:
        return self._last_skip


class S7commPlusExtractor(ProtocolExtractor):
    """S7comm Plus protocol extractor - Skip TPKT(4B) + COTP header"""
    
    def __init__(self):
        super().__init__('s7comm_plus')
        self._last_skip = 0
    
    def extract(self, data: bytes) -> Optional[bytes]:
        if len(data) < 7:
            return None
        # Check TPKT header (0x03, 0x00)
        if data[0:2] != b'\x03\x00':
            return None
        # COTP length at byte 4 (index 4)
        cotp_len = data[4] + 1  # COTP header length = LI + 1
        skip = 4 + cotp_len  # TPKT(4) + COTP
        if len(data) <= skip:
            return None
        # Check S7comm Plus protocol identifier (0x72)
        if data[skip] != 0x72:
            return None
        self._last_skip = skip
        return data[skip:]
    
    def get_skip_bytes(self, data: bytes) -> int:
        return self._last_skip


class OmronFinsExtractor(ProtocolExtractor):
    """OMRON FINS protocol extractor - Skip 16-byte FINS/TCP encapsulation header"""
    
    def __init__(self):
        super().__init__('omron_fins')
    
    def extract(self, data: bytes) -> Optional[bytes]:
        if len(data) < 16:
            return None
        # Check FINS magic (0x46494E53 = "FINS")
        if data[0:4] != b'FINS':
            return None
        return data[16:]  # Skip encapsulation header
    
    def get_skip_bytes(self, data: bytes) -> int:
        return 16


class CIPExtractor(ProtocolExtractor):
    """CIP protocol extractor - Skip EtherNet/IP + CPF header"""
    
    def __init__(self):
        super().__init__('cip')
        self._last_skip = 0
    
    def extract(self, data: bytes) -> Optional[bytes]:
        if len(data) <= 32:
            return None
        
        # Skip 24-byte EtherNet/IP encapsulation
        cip_data = data[24:]
        
        if len(cip_data) < 8:
            return None
        
        # Parse CPF Header: IntfHandle(4) + Timeout(2) + ItemCount(2)
        item_count = int.from_bytes(cip_data[6:8], 'little')
        offset = 8  # Skip CPF Header
        
        # Iterate CPF Items
        for i in range(item_count):
            if offset + 4 > len(cip_data):
                break
            # Item: Type(2) + Length(2) + Data(Length bytes)
            item_type = int.from_bytes(cip_data[offset:offset+2], 'little')
            item_length = int.from_bytes(cip_data[offset+2:offset+4], 'little')
            
            # 0x00B2 = Unconnected Data Item, 0x00B1 = Connected Data Item
            if item_type in [0x00B1, 0x00B2]:
                cip_service_start = offset + 4
                if item_type == 0x00B1:
                    # Connected Data Item: first 2 bytes are Sequence Count
                    cip_service_start += 2
                if cip_service_start < len(cip_data):
                    self._last_skip = 24 + cip_service_start
                    return cip_data[cip_service_start:]
                break
            else:
                offset += 4 + item_length
        
        return None
    
    def get_skip_bytes(self, data: bytes) -> int:
        return self._last_skip


class NTPExtractor(ProtocolExtractor):
    """NTP protocol extractor - Truncate to standard 48 bytes"""
    
    NTP_STANDARD_LENGTH = 48
    
    def __init__(self):
        super().__init__('ntp')
    
    def extract(self, data: bytes) -> Optional[bytes]:
        if len(data) < self.NTP_STANDARD_LENGTH:
            return None
        # NTP standard packet is 48 bytes, extension fields not analyzed
        return data[:self.NTP_STANDARD_LENGTH]
    
    def get_skip_bytes(self, data: bytes) -> int:
        return 0


class GenericExtractor(ProtocolExtractor):
    """Generic protocol extractor"""
    
    def __init__(self, protocol_name: str = 'generic', skip_bytes: int = 0, min_length: int = 4):
        super().__init__(protocol_name)
        self.skip_bytes = skip_bytes
        self.min_length = min_length
    
    def extract(self, data: bytes) -> Optional[bytes]:
        if len(data) < self.min_length:
            return None
        if self.skip_bytes > 0:
            if len(data) <= self.skip_bytes:
                return None
            return data[self.skip_bytes:]
        return data
    
    def get_skip_bytes(self, data: bytes) -> int:
        return self.skip_bytes


# Protocol extractor registry
PROTOCOL_EXTRACTORS: Dict[str, ProtocolExtractor] = {
    'modbus': ModbusExtractor(),
    'smb': SMBExtractor(),
    'smb2': SMB2Extractor(),
    's7comm': S7commExtractor(),
    's7comm_plus': S7commPlusExtractor(),
    'omron_fins': OmronFinsExtractor(),
    'cip': CIPExtractor(),
    'ntp': NTPExtractor(),
}


# ============================================================================
# Protocol Signature Removal Module
# ============================================================================

# Protocol signature anonymization configuration
# Implements the uniform additive shift: f_anon(b) = b + delta (mod 256)
# Each protocol has a fixed delta value applied to ALL bytes in the signature region.
# This preserves structural byte-positional relationships (length-value dependencies,
# field boundaries) while masking protocol fingerprints.
SIGNATURE_CONFIGS: Dict[str, Dict[str, Any]] = {
    'modbus': {
        # Modbus TCP: Apply uniform shift to function code byte region
        'signature_positions': [7],  # Function code position (first byte of PDU)
        'delta': 0x50,               # Fixed additive offset
    },
    'smb': {
        # SMB: Apply uniform shift to 0xFF 'SMB' signature at bytes 0-3
        'signature_positions': [0, 1, 2, 3],
        'original': [0xFF, 0x53, 0x4D, 0x42],  # Signature bytes to verify before shifting
        'delta': 0x12,               # Fixed additive offset: 0xFF->0x11, 0x53->0x65, etc.
    },
    'smb2': {
        # SMB2: Apply uniform shift to 0xFE 'SMB' signature at bytes 0-3
        'signature_positions': [0, 1, 2, 3],
        'original': [0xFE, 0x53, 0x4D, 0x42],  # Signature bytes to verify before shifting
        'delta': 0x12,               # Same delta as SMB for consistency
    },
    'dnp3': {
        # DNP3: Apply uniform shift to start bytes 0x05 0x64
        'signature_positions': [0, 1],
        'original': [0x05, 0x64],
        'delta': 0x12,               # Fixed additive offset
    },
    'omron_fins': {
        # OMRON FINS: Apply uniform shift to 'FINS' ASCII signature
        'signature_positions': [0, 1, 2, 3],
        'original': [0x46, 0x49, 0x4E, 0x53],  # "FINS"
        'delta': 0x01,               # Fixed additive offset: F->G, I->J, N->O, S->T
    }
}


def remove_protocol_signature(data: bytes, protocol_name: str) -> bytes:
    """
    Remove protocol signature via uniform additive shift: f_anon(b) = b + delta (mod 256)
    
    Applies a fixed, protocol-specific constant delta to all signature bytes.
    This preserves structural byte-positional relationships (length-value dependencies,
    field boundaries) while preventing the model from triggering its internal knowledge
    base via known magic bytes.
    
    Args:
        data: Original protocol data
        protocol_name: Protocol name
        
    Returns:
        Data with signature bytes shifted by delta (mod 256)
    """
    protocol_key = protocol_name.lower()
    if protocol_key not in SIGNATURE_CONFIGS:
        return data
    
    config = SIGNATURE_CONFIGS[protocol_key]
    data_list = list(data)
    delta = config['delta']
    positions = config['signature_positions']
    
    # If original signature values are specified, verify they match before applying shift
    if 'original' in config:
        for i, pos in enumerate(positions):
            if pos >= len(data_list) or data_list[pos] != config['original'][i]:
                return data  # Signature doesn't match, don't modify
    
    # Apply uniform additive shift: f_anon(b) = (b + delta) mod 256
    for pos in positions:
        if pos < len(data_list):
            data_list[pos] = (data_list[pos] + delta) % 256
    
    return bytes(data_list)


def has_signature_config(protocol_name: str) -> bool:
    """
    Check if protocol has signature anonymization configuration
    
    Args:
        protocol_name: Protocol name
        
    Returns:
        Whether configuration exists
    """
    return protocol_name.lower() in SIGNATURE_CONFIGS


def get_signature_protocols() -> List[str]:
    """
    Get list of all protocols with signature anonymization configured
    
    Returns:
        Protocol name list
    """
    return list(SIGNATURE_CONFIGS.keys())


def get_extractor(protocol_type: str, skip_bytes: int = 0) -> ProtocolExtractor:
    """
    Get protocol extractor
    
    Args:
        protocol_type: Protocol type
        skip_bytes: Generic skip bytes count (for unregistered protocols)
        
    Returns:
        Protocol extractor instance
    """
    protocol_type = protocol_type.lower()
    
    if protocol_type in PROTOCOL_EXTRACTORS:
        return PROTOCOL_EXTRACTORS[protocol_type]
    
    # Protocol alias mapping
    protocol_aliases = {
        'omron': 'omron_fins',
        'fins': 'omron_fins',
        's7': 's7comm',
        's7plus': 's7comm_plus',
    }
    
    if protocol_type in protocol_aliases:
        return PROTOCOL_EXTRACTORS[protocol_aliases[protocol_type]]
    
    return GenericExtractor(protocol_type, skip_bytes)


class PCAPExtractor:
    """PCAP file extractor"""
    
    def __init__(self, use_netzob: bool = True, layer: int = 5, max_length: int = 500):
        """
        Initialize PCAP extractor
        
        Args:
            use_netzob: Whether to prioritize Netzob (better for complex protocol stacks)
            layer: Network layer (5=application layer)
            max_length: Maximum message length
        """
        self.use_netzob = use_netzob and NETZOB_AVAILABLE
        self.layer = layer
        self.max_length = max_length
        self.logger = logging.getLogger(__name__)
        
        if not NETZOB_AVAILABLE and not SCAPY_AVAILABLE:
            raise ImportError("Either Netzob or Scapy is required for PCAP processing")
    
    def extract_messages(
        self, 
        pcap_path: str, 
        protocol_type: str,
        max_messages: int = None,
        skip_bytes: int = 0
    ) -> List[ExtractedMessage]:
        """
        Extract protocol messages from PCAP file
        
        Args:
            pcap_path: PCAP file path
            protocol_type: Protocol type
            max_messages: Maximum message count
            skip_bytes: Additional bytes to skip
            
        Returns:
            List of extracted messages
        """
        pcap_path = Path(pcap_path)
        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        
        protocol_type = protocol_type.lower()
        extractor = get_extractor(protocol_type, skip_bytes)
        
        if self.use_netzob:
            return self._extract_with_netzob(pcap_path, protocol_type, extractor, max_messages)
        else:
            return self._extract_with_scapy(pcap_path, protocol_type, extractor, max_messages)
    
    def _extract_with_netzob(
        self, 
        pcap_path: Path, 
        protocol_type: str,
        extractor: ProtocolExtractor,
        max_messages: int = None
    ) -> List[ExtractedMessage]:
        """Extract messages using Netzob"""
        try:
            messages = PCAPImporter.readFile(str(pcap_path), importLayer=self.layer).values()
            extracted = []
            
            for idx, msg in enumerate(messages):
                if max_messages and len(extracted) >= max_messages:
                    break
                
                if not msg.data:
                    continue
                
                original_data = bytes(msg.data)
                
                # Process using protocol extractor
                data = extractor.extract(original_data)
                if data is None:
                    continue
                
                # Limit length
                if self.max_length and len(data) > self.max_length:
                    data = data[:self.max_length]
                
                extracted.append(ExtractedMessage(
                    data=data,
                    original_data=original_data,
                    index=idx,
                    protocol=protocol_type,
                    skip_bytes=extractor.get_skip_bytes(original_data)
                ))
            
            self.logger.info(f"Extracted {len(extracted)} messages from {pcap_path.name} using Netzob")
            return extracted
            
        except Exception as e:
            self.logger.error(f"Failed to extract with Netzob: {e}")
            if SCAPY_AVAILABLE:
                self.logger.info("Falling back to Scapy")
                return self._extract_with_scapy(pcap_path, protocol_type, extractor, max_messages)
            raise
    
    def _extract_with_scapy(
        self, 
        pcap_path: Path, 
        protocol_type: str,
        extractor: ProtocolExtractor,
        max_messages: int = None
    ) -> List[ExtractedMessage]:
        """Extract messages using Scapy"""
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for this operation")
        
        try:
            packets = rdpcap(str(pcap_path))
            extracted = []
            
            for idx, pkt in enumerate(packets):
                if max_messages and len(extracted) >= max_messages:
                    break
                
                # Extract application layer data
                original_data = None
                if Raw in pkt:
                    original_data = bytes(pkt[Raw].load)
                elif DNS in pkt:
                    original_data = bytes(pkt[UDP].payload)
                elif TCP in pkt:
                    tcp_payload = bytes(pkt[TCP].payload)
                    if len(tcp_payload) >= 4:
                        original_data = tcp_payload
                elif UDP in pkt:
                    original_data = bytes(pkt[UDP].payload)
                
                if not original_data:
                    continue
                
                # Process using protocol extractor
                data = extractor.extract(original_data)
                if data is None:
                    continue
                
                # Limit length
                if self.max_length and len(data) > self.max_length:
                    data = data[:self.max_length]
                
                extracted.append(ExtractedMessage(
                    data=data,
                    original_data=original_data,
                    index=idx,
                    protocol=protocol_type,
                    skip_bytes=extractor.get_skip_bytes(original_data)
                ))
            
            self.logger.info(f"Extracted {len(extracted)} messages from {pcap_path.name} using Scapy")
            return extracted
            
        except Exception as e:
            self.logger.error(f"Failed to extract with Scapy: {e}")
            raise
    
    def extract_raw_bytes(
        self, 
        pcap_path: str, 
        protocol_type: str,
        max_messages: int = None,
        skip_bytes: int = 0
    ) -> List[bytes]:
        """
        Extract raw byte data (simplified interface)
        
        Args:
            pcap_path: PCAP file path
            protocol_type: Protocol type
            max_messages: Maximum message count
            skip_bytes: Additional bytes to skip
            
        Returns:
            List of byte data
        """
        messages = self.extract_messages(pcap_path, protocol_type, max_messages, skip_bytes)
        return [msg.data for msg in messages]


def infer_protocol_from_filename(filepath: str) -> str:
    """
    Infer protocol type from filename
    
    Args:
        filepath: File path
        
    Returns:
        Protocol type string
    """
    filename = Path(filepath).stem.lower()
    
    # Protocol keyword mapping (order matters: more specific patterns first)
    protocol_keywords = {
        's7comm_plus': ['s7comm_plus', 's7plus'],
        's7comm': ['s7comm', 's7'],
        'smb2': ['smb2'],
        'smb': ['smb', 'cifs'],
        'modbus': ['modbus', 'mbtcp', 'modbustcp'],
        'omron_fins': ['omron_fins', 'fins', 'omron'],
        'cip': ['cip', 'enip'],
        'dnp3': ['dnp3', 'dnp'],
        'ntp': ['ntp'],
        'dhcp': ['dhcp', 'bootp'],
        'icmp': ['icmp', 'ping'],
        'dns_ictf': ['dns_ictf'],
        'dns': ['dns'],
        'custom_iot': ['custom_iot'],
        'game_sync': ['game_sync', 'gamesync'],
        'heart_beat': ['heart_beat', 'heartbeat'],
        'hollysys': ['hollysys'],
        'secure_chat': ['secure_chat', 'securechat'],
        'time_sync': ['time_sync', 'timesync'],
        'mavlink': ['mavlink'],
        'mirai': ['mirai'],
    }
    
    for protocol, keywords in protocol_keywords.items():
        for keyword in keywords:
            if keyword in filename:
                return protocol
    
    return 'generic'


# Convenience function
def extract_protocol_messages(
    pcap_path: str,
    protocol_type: str = None,
    max_messages: int = None,
    use_netzob: bool = True
) -> List[bytes]:
    """
    Convenience function: Extract protocol messages from PCAP
    
    Args:
        pcap_path: PCAP file path
        protocol_type: Protocol type (auto-infer if not specified)
        max_messages: Maximum message count
        use_netzob: Whether to use Netzob
        
    Returns:
        List of byte data
    """
    if protocol_type is None:
        protocol_type = infer_protocol_from_filename(pcap_path)
    
    extractor = PCAPExtractor(use_netzob=use_netzob)
    return extractor.extract_raw_bytes(pcap_path, protocol_type, max_messages)


def main():
    """Traverse data directory and save extraction results"""
    parser = argparse.ArgumentParser(description="PCAP Protocol Batch Processor")
    parser.add_argument("--save", action="store_true", help="Save extracted data to /tmp/data/")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    # Path configuration
    input_dir = Path("data")
    save_dir = Path("/tmp/data")

    if not input_dir.exists():
        print(f"Error: Input directory '{input_dir}' does not exist.")
        return

    if args.save and not save_dir.exists():
        save_dir.mkdir(parents=True, exist_ok=True)
        print(f"Created output directory: {save_dir}")

    extractor = PCAPExtractor(use_netzob=True)
    
    # Get all files ending with _100.pcap
    pcap_files = list(input_dir.glob("*_100.pcap"))
    
    if not pcap_files:
        print("No files matching '{protocol}_100.pcap' found in data directory.")
        return

    print(f"Found {len(pcap_files)} matching files. Starting extraction...")

    for pcap_path in pcap_files:
        # Parse protocol name from filename (e.g., 'modbus_100.pcap' -> 'modbus')
        protocol = pcap_path.name.replace("_100.pcap", "").lower()
        
        print(f"\nProcessing: {pcap_path.name} (Inferred Protocol: {protocol})")
        
        try:
            # Extract all messages from this file
            messages = extractor.extract_messages(str(pcap_path), protocol)
            
            if not messages:
                print(f"  [!] No valid {protocol} messages extracted.")
                continue

            print(f"  [+] Extracted {len(messages)} messages.")

            # Save to /tmp/data/{protocol}.txt
            if args.save:
                output_file = save_dir / f"{protocol}.txt"
                with open(output_file, 'w', encoding='utf-8') as f:
                    for msg in messages:
                        # One hex string per line
                        f.write(msg.to_hex() + "\n")
                print(f"  [OK] Results saved to {output_file}")
            else:
                # If --save not enabled, print first two as preview
                for msg in messages[:2]:
                    print(f"  Preview: {msg.to_hex()[:50]}...")

        except Exception as e:
            print(f"  [X] Failed to process {pcap_path.name}: {e}")

    print("\nBatch processing complete.")


if __name__ == "__main__":
    main()
