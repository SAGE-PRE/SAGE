#!/usr/bin/env python3
"""
Custom Protocol PCAP File Generator
For testing LLM's protocol reverse engineering ability (non-public protocols)

Protocol 1: CustomIoT (CIOT) - IoT sensor protocol, big-endian, dynamic length field
Protocol 2: GameSync (GSYNC) - Game state sync protocol, little-endian, TLV encoding, CRC32 checksum
Protocol 3: SecureChat (SCHAT) - Encrypted chat protocol, multi-TLV blocks, timestamp, session ID
Protocol 4: TimeSync (TSYNC) - Time sync protocol, fixed 32 bytes
Protocol 5: HeartBeat (HBEAT) - Heartbeat monitoring protocol, fixed 24 bytes
"""

import struct
import random
import json
import os
import time
from datetime import datetime
from binascii import crc32

# Try import scapy
try:
    from scapy.all import Ether, IP, UDP, Raw, wrpcap, rdpcap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not installed, will use simplified PCAP generation method")
    print("Install: pip install scapy")


class CustomIoTProtocol:
    """Custom IoT Sensor Protocol (CIOT)"""
    
    MAGIC = 0xCAFE
    VERSION = 0x01
    
    # Message types
    MSG_TYPE_TEMP_REQ = 0x10
    MSG_TYPE_TEMP_RESP = 0x11
    MSG_TYPE_HUMID_REQ = 0x20
    MSG_TYPE_HUMID_RESP = 0x21
    MSG_TYPE_STATUS_REQ = 0x30
    MSG_TYPE_STATUS_RESP = 0x31
    
    def __init__(self):
        self.sequence = 0
    
    def calculate_checksum(self, data: bytes) -> int:
        """Calculate checksum (XOR all bytes)"""
        checksum = 0
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                word = (data[i] << 8) | data[i+1]
            else:
                word = data[i] << 8
            checksum ^= word
        return checksum & 0xFFFF
    
    def build_packet(self, msg_type: int, payload: bytes) -> bytes:
        """Build protocol packet"""
        # Header
        header = struct.pack(
            '>HBB',  # Big-endian: magic(2), version(1), msg_type(1)
            self.MAGIC,
            self.VERSION,
            msg_type
        )
        
        # Sequence number
        seq = struct.pack('>I', self.sequence)
        self.sequence += 1
        
        # Length
        length = struct.pack('>H', len(payload))
        
        # Assemble (without checksum)
        packet_without_checksum = header + seq + length + payload
        
        # Calculate checksum
        checksum = self.calculate_checksum(packet_without_checksum)
        checksum_bytes = struct.pack('>H', checksum)
        
        # Complete packet
        return packet_without_checksum + checksum_bytes
    
    def build_temp_request(self, sensor_id: int) -> bytes:
        """Build temperature read request"""
        payload = struct.pack('>H', sensor_id)
        return self.build_packet(self.MSG_TYPE_TEMP_REQ, payload)
    
    def build_temp_response(self, sensor_id: int, temperature: float) -> bytes:
        """Build temperature read response"""
        # Convert temperature to integer in 0.01°C unit
        temp_int = int(temperature * 100)
        payload = struct.pack('>Hh', sensor_id, temp_int)
        return self.build_packet(self.MSG_TYPE_TEMP_RESP, payload)
    
    def build_humid_request(self, sensor_id: int) -> bytes:
        """Build humidity read request"""
        payload = struct.pack('>H', sensor_id)
        return self.build_packet(self.MSG_TYPE_HUMID_REQ, payload)
    
    def build_humid_response(self, sensor_id: int, humidity: int) -> bytes:
        """Build humidity read response"""
        payload = struct.pack('>HB', sensor_id, humidity)
        return self.build_packet(self.MSG_TYPE_HUMID_RESP, payload)
    
    def build_status_request(self, sensor_id: int) -> bytes:
        """Build status query request"""
        payload = struct.pack('>H', sensor_id)
        return self.build_packet(self.MSG_TYPE_STATUS_REQ, payload)
    
    def build_status_response(self, sensor_id: int, status: int, battery: int) -> bytes:
        """Build status query response"""
        payload = struct.pack('>HBB', sensor_id, status, battery)
        return self.build_packet(self.MSG_TYPE_STATUS_RESP, payload)


def generate_ciot_pcap(output_file: str, num_packets: int = 100):
    """Generate CustomIoT protocol PCAP file"""
    print(f"Generating CustomIoT protocol PCAP file: {output_file}")
    
    if not SCAPY_AVAILABLE:
        print("❌ Scapy required: pip install scapy")
        return
    
    protocol = CustomIoTProtocol()
    packets = []
    
    # Simulate multiple sensors
    sensor_ids = [0x1001, 0x1002, 0x1003, 0x1004, 0x1005]
    
    for i in range(num_packets):
        sensor_id = random.choice(sensor_ids)
        
        # Randomly select request type
        req_type = random.choice(['temp', 'humid', 'status'])
        
        if req_type == 'temp':
            # Temperature request-response
            req_data = protocol.build_temp_request(sensor_id)
            resp_data = protocol.build_temp_response(
                sensor_id,
                random.uniform(15.0, 35.0)  # 15-35°C
            )
        elif req_type == 'humid':
            # Humidity request-response
            req_data = protocol.build_humid_request(sensor_id)
            resp_data = protocol.build_humid_response(
                sensor_id,
                random.randint(30, 90)  # 30-90%
            )
        else:
            # Status request-response
            req_data = protocol.build_status_request(sensor_id)
            resp_data = protocol.build_status_response(
                sensor_id,
                random.choice([0, 1, 2]),  # 0=idle, 1=active, 2=error
                random.randint(10, 100)  # 10-100% battery
            )
        
        # Create UDP packets (client -> server)
        src_ip = "192.168.1.100"
        dst_ip = "192.168.1.200"
        src_mac = "00:11:22:33:44:55"
        dst_mac = "aa:bb:cc:dd:ee:ff"
        src_port = 50000 + i
        dst_port = 9876
        
        # Request packet (add Ethernet layer)
        req_pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / Raw(load=req_data)
        packets.append(req_pkt)
        
        # Response packet (add Ethernet layer)
        resp_pkt = Ether(src=dst_mac, dst=src_mac) / IP(src=dst_ip, dst=src_ip) / UDP(sport=dst_port, dport=src_port) / Raw(load=resp_data)
        packets.append(resp_pkt)
    
    # Write PCAP file
    wrpcap(output_file, packets)
    print(f"✅ Generation complete: {len(packets)} packets")
    
    # Print hex data of first 3 packets
    print(f"\nHex data of first 3 packets:")
    for i, pkt in enumerate(packets[:3]):
        if Raw in pkt:
            print(f"  {i+1}. {pkt[Raw].load.hex()}")
    
    return packets


def generate_ground_truth_ciot(output_file: str, pcap_file: str = None, packets: list = None):
    """Generate Ground Truth boundary definitions"""
    print(f"\nGenerating Ground Truth: {output_file}")
    
    if packets is None:
        if not SCAPY_AVAILABLE or pcap_file is None:
            print("❌ Scapy required or provide packets parameter")
            return
        packets = rdpcap(pcap_file)
    
    messages = []
    for i, pkt in enumerate(packets):
        # Extract raw data
        if SCAPY_AVAILABLE and Raw in pkt:
            raw_data = bytes(pkt[Raw].load)
        elif hasattr(pkt, 'load'):
            raw_data = bytes(pkt.load)
        else:
            continue
        
        # Define boundaries based on protocol format
        # Magic(2) | Version(1) | MsgType(1) | Seq(4) | Length(2) | Payload(N) | Checksum(2)
        boundaries = [0, 2, 3, 4, 8, 10]
        
        # Extract Length field
        if len(raw_data) >= 10:
            payload_len = struct.unpack('>H', raw_data[8:10])[0]
            # Add Payload end boundary and Checksum end boundary
            boundaries.append(10 + payload_len)
            # Note: last boundary is packet end, no need to add explicitly
        
        messages.append({
            "message_id": i,
            "packet_hex": raw_data.hex(),
            "boundaries": boundaries,
            "packet_length": len(raw_data)
        })
    
    ground_truth = {
        "protocol": "CustomIoT (CIOT)",
        "description": "Virtual IoT sensor data transmission protocol",
        "boundary_type": "dynamic",
        "total_messages": len(messages),
        "messages": messages
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(ground_truth, f, indent=2, ensure_ascii=False)
    
    print(f"✅ Ground Truth generation complete: {len(messages)} messages")


# ==================== Protocol 2: GameSync (GSYNC) ====================

class GameSyncProtocol:
    """Game State Sync Protocol (GSYNC) - using TLV encoding"""
    
    SYNC_WORD = 0xDEAD  # Sync word (little-endian)
    PROTOCOL_VERSION = 0x02
    
    # TLV types
    TLV_PLAYER_POS = 0x01      # Player position (x, y, z: float32 x 3)
    TLV_PLAYER_HEALTH = 0x02   # Player health (uint16)
    TLV_PLAYER_SCORE = 0x03    # Player score (uint32)
    TLV_GAME_EVENT = 0x04      # Game event (event_id: uint8, data: variable)
    TLV_TIMESTAMP = 0x05       # Timestamp (uint32)
    
    def __init__(self):
        self.packet_id = 0
    
    def calculate_crc32(self, data: bytes) -> int:
        """Calculate CRC32 checksum"""
        return crc32(data) & 0xFFFFFFFF
    
    def build_tlv(self, tlv_type: int, value: bytes) -> bytes:
        """Build single TLV block"""
        length = len(value)
        return struct.pack('<BH', tlv_type, length) + value
    
    def build_packet(self, tlvs: list) -> bytes:
        """Build protocol packet"""
        # Header: SyncWord(2) | Version(1) | PacketID(2) | TLVCount(1)
        header = struct.pack(
            '<HBHB',
            self.SYNC_WORD,
            self.PROTOCOL_VERSION,
            self.packet_id,
            len(tlvs)
        )
        self.packet_id += 1
        
        # Assemble all TLVs
        tlv_data = b''.join(tlvs)
        
        # Calculate CRC32 (header + TLV data)
        packet_without_crc = header + tlv_data
        crc = self.calculate_crc32(packet_without_crc)
        crc_bytes = struct.pack('<I', crc)
        
        return packet_without_crc + crc_bytes
    
    def build_position_update(self, player_id: int, x: float, y: float, z: float) -> bytes:
        """Build position update packet"""
        tlvs = [
            self.build_tlv(self.TLV_PLAYER_POS, 
                          struct.pack('<Bfff', player_id, x, y, z)),
            self.build_tlv(self.TLV_TIMESTAMP, 
                          struct.pack('<I', int(time.time())))
        ]
        return self.build_packet(tlvs)
    
    def build_status_update(self, player_id: int, health: int, score: int) -> bytes:
        """Build status update packet"""
        tlvs = [
            self.build_tlv(self.TLV_PLAYER_HEALTH, 
                          struct.pack('<BH', player_id, health)),
            self.build_tlv(self.TLV_PLAYER_SCORE, 
                          struct.pack('<BI', player_id, score)),
            self.build_tlv(self.TLV_TIMESTAMP, 
                          struct.pack('<I', int(time.time())))
        ]
        return self.build_packet(tlvs)
    
    def build_event_message(self, event_id: int, event_data: bytes) -> bytes:
        """Build game event packet"""
        tlvs = [
            self.build_tlv(self.TLV_GAME_EVENT, 
                          struct.pack('<B', event_id) + event_data),
            self.build_tlv(self.TLV_TIMESTAMP, 
                          struct.pack('<I', int(time.time())))
        ]
        return self.build_packet(tlvs)


def generate_gsync_pcap(output_file: str, num_packets: int = 100):
    """Generate GameSync protocol PCAP file"""
    print(f"\nGenerating GameSync protocol PCAP file: {output_file}")
    
    if not SCAPY_AVAILABLE:
        print("❌ Scapy required")
        return None
    
    protocol = GameSyncProtocol()
    packets = []
    
    # Simulate multiple players
    player_ids = [1, 2, 3, 4]
    
    for i in range(num_packets):
        player_id = random.choice(player_ids)
        
        # Randomly select message type
        msg_type = random.choice(['position', 'status', 'event'])
        
        if msg_type == 'position':
            data = protocol.build_position_update(
                player_id,
                random.uniform(-100.0, 100.0),
                random.uniform(0.0, 50.0),
                random.uniform(-100.0, 100.0)
            )
        elif msg_type == 'status':
            data = protocol.build_status_update(
                player_id,
                random.randint(0, 100),
                random.randint(0, 10000)
            )
        else:
            # Game event
            event_id = random.choice([1, 2, 3])  # 1=kill, 2=death, 3=item_pickup
            event_data = struct.pack('<H', random.randint(0, 255))
            data = protocol.build_event_message(event_id, event_data)
        
        # UDP packet
        src_ip = f"10.0.0.{player_id + 100}"
        dst_ip = "10.0.0.1"
        src_mac = f"00:11:22:33:44:{player_id:02x}"
        dst_mac = "aa:bb:cc:dd:ee:00"
        
        pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / \
              UDP(sport=30000 + player_id, dport=8888) / Raw(load=data)
        packets.append(pkt)
    
    wrpcap(output_file, packets)
    print(f"✅ Generation complete: {len(packets)} packets")
    
    print(f"\nHex data of first 3 packets:")
    for i, pkt in enumerate(packets[:3]):
        if Raw in pkt:
            print(f"  {i+1}. {pkt[Raw].load.hex()}")
    
    return packets


def generate_ground_truth_gsync(output_file: str, packets: list = None):
    """Generate GameSync Ground Truth"""
    print(f"\nGenerating Ground Truth: {output_file}")
    
    if packets is None:
        print("❌ packets parameter required")
        return
    
    messages = []
    for i, pkt in enumerate(packets):
        if Raw not in pkt:
            continue
        
        raw_data = bytes(pkt[Raw].load)
        
        # Parse protocol structure
        # SyncWord(2) | Version(1) | PacketID(2) | TLVCount(1) | TLVs... | CRC32(4)
        boundaries = [0, 2, 3, 5, 6]
        
        if len(raw_data) >= 6:
            tlv_count = raw_data[5]
            offset = 6
            
            # Parse each TLV block
            for _ in range(tlv_count):
                if offset + 3 > len(raw_data):
                    break
                boundaries.append(offset)  # TLV start
                tlv_length = struct.unpack('<H', raw_data[offset+1:offset+3])[0]
                offset += 3 + tlv_length
            
            boundaries.append(len(raw_data) - 4)  # CRC32 start
        
        messages.append({
            "message_id": i,
            "packet_hex": raw_data.hex(),
            "boundaries": boundaries,
            "packet_length": len(raw_data)
        })
    
    ground_truth = {
        "protocol": "GameSync (GSYNC)",
        "description": "Virtual game state sync protocol (TLV encoding, little-endian)",
        "boundary_type": "dynamic",
        "total_messages": len(messages),
        "messages": messages
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(ground_truth, f, indent=2, ensure_ascii=False)
    
    print(f"✅ Ground Truth generation complete: {len(messages)} messages")


# ==================== Protocol 3: SecureChat (SCHAT) ====================

class SecureChatProtocol:
    """Encrypted Chat Protocol (SCHAT) - multi-TLV blocks + timestamp + session ID"""
    
    MAGIC = 0xBEEF
    VERSION = 0x03
    
    # Message types
    MSG_TEXT = 0x01
    MSG_FILE = 0x02
    MSG_IMAGE = 0x03
    MSG_STATUS = 0x04
    
    # TLV types
    TLV_SESSION_ID = 0x10
    TLV_SENDER_ID = 0x11
    TLV_RECEIVER_ID = 0x12
    TLV_TIMESTAMP = 0x13
    TLV_CONTENT = 0x14
    TLV_METADATA = 0x15
    
    def __init__(self):
        self.msg_seq = 0
    
    def calculate_checksum(self, data: bytes) -> int:
        """Simple additive checksum"""
        return sum(data) & 0xFF
    
    def build_tlv(self, tlv_type: int, value: bytes) -> bytes:
        """Build TLV: Type(1) | Length(1) | Value(N)"""
        return struct.pack('BB', tlv_type, len(value)) + value
    
    def build_packet(self, msg_type: int, session_id: int, sender_id: int, 
                    receiver_id: int, content: bytes, metadata: bytes = b'') -> bytes:
        """Build packet"""
        # Header: Magic(2) | Version(1) | MsgType(1) | Seq(4) | TLVCount(1)
        tlvs = [
            self.build_tlv(self.TLV_SESSION_ID, struct.pack('>I', session_id)),
            self.build_tlv(self.TLV_SENDER_ID, struct.pack('>H', sender_id)),
            self.build_tlv(self.TLV_RECEIVER_ID, struct.pack('>H', receiver_id)),
            self.build_tlv(self.TLV_TIMESTAMP, struct.pack('>Q', int(time.time() * 1000))),
            self.build_tlv(self.TLV_CONTENT, content),
        ]
        if metadata:
            tlvs.append(self.build_tlv(self.TLV_METADATA, metadata))
        
        tlv_count = len(tlvs)
        header = struct.pack('>HBBIB', self.MAGIC, self.VERSION, msg_type, 
                           self.msg_seq, tlv_count)
        self.msg_seq += 1
        
        tlv_data = b''.join(tlvs)
        packet_without_checksum = header + tlv_data
        
        checksum = self.calculate_checksum(packet_without_checksum)
        return packet_without_checksum + struct.pack('B', checksum)
    
    def build_text_message(self, session_id: int, sender_id: int, 
                          receiver_id: int, text: str) -> bytes:
        """Build text message"""
        content = text.encode('utf-8')
        return self.build_packet(self.MSG_TEXT, session_id, sender_id, 
                                receiver_id, content)
    
    def build_status_message(self, session_id: int, sender_id: int, 
                            receiver_id: int, status: int) -> bytes:
        """Build status message"""
        content = struct.pack('B', status)  # 0=offline, 1=online, 2=away
        metadata = struct.pack('>H', random.randint(0, 1000))  # Random metadata
        return self.build_packet(self.MSG_STATUS, session_id, sender_id, 
                                receiver_id, content, metadata)


def generate_schat_pcap(output_file: str, num_packets: int = 100):
    """Generate SecureChat protocol PCAP file"""
    print(f"\nGenerating SecureChat protocol PCAP file: {output_file}")
    
    if not SCAPY_AVAILABLE:
        print("❌ Scapy required")
        return None
    
    protocol = SecureChatProtocol()
    packets = []
    
    # Simulate users and sessions
    users = [1001, 1002, 1003, 1004, 1005]
    sessions = [10001, 10002, 10003]
    
    messages = [
        "Hello", "How are you?", "Good morning", "See you later",
        "Meeting at 3pm", "Check the report", "Thanks!", "OK"
    ]
    
    for i in range(num_packets):
        session_id = random.choice(sessions)
        sender_id = random.choice(users)
        receiver_id = random.choice([u for u in users if u != sender_id])
        
        # 70% text messages, 30% status messages
        if random.random() < 0.7:
            text = random.choice(messages)
            data = protocol.build_text_message(session_id, sender_id, 
                                              receiver_id, text)
        else:
            status = random.choice([0, 1, 2])
            data = protocol.build_status_message(session_id, sender_id, 
                                                receiver_id, status)
        
        # TCP packet
        src_ip = f"172.16.1.{sender_id % 256}"
        dst_ip = "172.16.1.254"
        src_mac = f"02:00:00:00:{(sender_id >> 8) & 0xff:02x}:{sender_id & 0xff:02x}"
        dst_mac = "02:00:00:00:fe:fe"
        
        from scapy.all import TCP
        pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / \
              TCP(sport=40000 + (sender_id % 1000), dport=9999, flags='PA') / Raw(load=data)
        packets.append(pkt)
    
    wrpcap(output_file, packets)
    print(f"✅ Generation complete: {len(packets)} packets")
    
    print(f"\nHex data of first 3 packets:")
    for i, pkt in enumerate(packets[:3]):
        if Raw in pkt:
            print(f"  {i+1}. {pkt[Raw].load.hex()}")
    
    return packets


def generate_ground_truth_schat(output_file: str, packets: list = None):
    """Generate SecureChat Ground Truth"""
    print(f"\nGenerating Ground Truth: {output_file}")
    
    if packets is None:
        print("❌ packets parameter required")
        return
    
    messages = []
    for i, pkt in enumerate(packets):
        if Raw not in pkt:
            continue
        
        raw_data = bytes(pkt[Raw].load)
        
        # Parse protocol structure
        # Magic(2) | Version(1) | MsgType(1) | Seq(4) | TLVCount(1) | TLVs... | Checksum(1)
        boundaries = [0, 2, 3, 4, 8, 9]
        
        if len(raw_data) >= 9:
            tlv_count = raw_data[8]
            offset = 9
            
            # Parse each TLV block
            for _ in range(tlv_count):
                if offset + 2 > len(raw_data):
                    break
                boundaries.append(offset)  # TLV start
                tlv_length = raw_data[offset + 1]
                offset += 2 + tlv_length
            
            boundaries.append(len(raw_data) - 1)  # Checksum start
        
        messages.append({
            "message_id": i,
            "packet_hex": raw_data.hex(),
            "boundaries": boundaries,
            "packet_length": len(raw_data)
        })
    
    ground_truth = {
        "protocol": "SecureChat (SCHAT)",
        "description": "Virtual encrypted chat protocol (multi-TLV blocks, big-endian)",
        "boundary_type": "dynamic",
        "total_messages": len(messages),
        "messages": messages
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(ground_truth, f, indent=2, ensure_ascii=False)
    
    print(f"✅ Ground Truth generation complete: {len(messages)} messages")


# ==================== Protocol 4: TimeSync (TSYNC) - Fixed Length ====================

class TimeSyncProtocol:
    """Time Sync Protocol (TSYNC) - fixed 32 bytes
    
    Structure (big-endian):
    - Magic(2): 0xABCD
    - Version(1): 0x01
    - MsgType(1): Request/response type
    - ClientID(4): Client identifier
    - Timestamp_Sec(8): Seconds timestamp
    - Timestamp_Nsec(4): Nanoseconds part
    - Stratum(1): Time stratum
    - Precision(1): Precision exponent
    - Reserved(8): Reserved field
    - Checksum(2): CRC16 checksum
    
    Total length: 2+1+1+4+8+4+1+1+8+2 = 32 bytes
    """
    
    MAGIC = 0xABCD
    VERSION = 0x01
    TOTAL_LENGTH = 32
    
    # Message types
    MSG_SYNC_REQUEST = 0x01
    MSG_SYNC_RESPONSE = 0x02
    MSG_DELAY_REQUEST = 0x03
    MSG_DELAY_RESPONSE = 0x04
    
    def __init__(self):
        self.client_id = random.randint(0x10000000, 0xFFFFFFFF)
    
    def calculate_crc16(self, data: bytes) -> int:
        """Calculate CRC16 checksum (simplified)"""
        crc = 0xFFFF
        for byte in data:
            crc ^= byte << 8
            for _ in range(8):
                if crc & 0x8000:
                    crc = (crc << 1) ^ 0x1021
                else:
                    crc <<= 1
                crc &= 0xFFFF
        return crc
    
    def build_packet(self, msg_type: int, timestamp_sec: int, timestamp_nsec: int,
                    stratum: int = 1, precision: int = -20) -> bytes:
        """Build fixed 32-byte packet"""
        # Build packet without checksum
        packet = struct.pack(
            '>HBBI QI BB 8s',
            self.MAGIC,
            self.VERSION,
            msg_type,
            self.client_id,
            timestamp_sec,
            timestamp_nsec,
            stratum,
            precision & 0xFF,
            b'\x00' * 8  # Reserved
        )
        
        # Calculate and add checksum
        crc = self.calculate_crc16(packet)
        packet += struct.pack('>H', crc)
        
        assert len(packet) == self.TOTAL_LENGTH, f"Packet length mismatch: {len(packet)}"
        return packet
    
    def build_sync_request(self) -> bytes:
        """Build sync request"""
        now = time.time()
        sec = int(now)
        nsec = int((now - sec) * 1e9)
        return self.build_packet(self.MSG_SYNC_REQUEST, sec, nsec, stratum=0, precision=-18)
    
    def build_sync_response(self) -> bytes:
        """Build sync response"""
        now = time.time()
        sec = int(now)
        nsec = int((now - sec) * 1e9)
        return self.build_packet(self.MSG_SYNC_RESPONSE, sec, nsec, stratum=1, precision=-20)
    
    def build_delay_request(self) -> bytes:
        """Build delay request"""
        now = time.time()
        sec = int(now)
        nsec = int((now - sec) * 1e9)
        return self.build_packet(self.MSG_DELAY_REQUEST, sec, nsec, stratum=0, precision=-18)
    
    def build_delay_response(self) -> bytes:
        """Build delay response"""
        now = time.time()
        sec = int(now)
        nsec = int((now - sec) * 1e9)
        return self.build_packet(self.MSG_DELAY_RESPONSE, sec, nsec, stratum=1, precision=-20)


def generate_tsync_pcap(output_file: str, num_packets: int = 100):
    """Generate TimeSync protocol PCAP file"""
    print(f"\nGenerating TimeSync protocol PCAP file: {output_file}")
    
    if not SCAPY_AVAILABLE:
        print("❌ Scapy required")
        return None
    
    packets = []
    
    # Simulate multiple clients
    client_ips = ["192.168.10.101", "192.168.10.102", "192.168.10.103"]
    server_ip = "192.168.10.1"
    
    for i in range(num_packets):
        protocol = TimeSyncProtocol()
        client_ip = random.choice(client_ips)
        
        # Randomly select message type (request-response pair)
        msg_pair = random.choice(['sync', 'delay'])
        
        if msg_pair == 'sync':
            req_data = protocol.build_sync_request()
            resp_data = protocol.build_sync_response()
        else:
            req_data = protocol.build_delay_request()
            resp_data = protocol.build_delay_response()
        
        src_mac = f"00:aa:bb:cc:dd:{i % 256:02x}"
        dst_mac = "00:11:22:33:44:55"
        
        # Request packet
        req_pkt = Ether(src=src_mac, dst=dst_mac) / \
                  IP(src=client_ip, dst=server_ip) / \
                  UDP(sport=50123 + i, dport=319) / Raw(load=req_data)
        packets.append(req_pkt)
        
        # Response packet
        resp_pkt = Ether(src=dst_mac, dst=src_mac) / \
                   IP(src=server_ip, dst=client_ip) / \
                   UDP(sport=319, dport=50123 + i) / Raw(load=resp_data)
        packets.append(resp_pkt)
    
    wrpcap(output_file, packets)
    print(f"✅ Generation complete: {len(packets)} packets (each fixed at {TimeSyncProtocol.TOTAL_LENGTH} bytes)")
    
    print(f"\nHex data of first 3 packets:")
    for i, pkt in enumerate(packets[:3]):
        if Raw in pkt:
            raw = pkt[Raw].load
            print(f"  {i+1}. {raw.hex()} (len={len(raw)})")
    
    return packets


def generate_ground_truth_tsync(output_file: str, packets: list = None):
    """Generate TimeSync Ground Truth"""
    print(f"\nGenerating Ground Truth: {output_file}")
    
    if packets is None:
        print("❌ packets parameter required")
        return
    
    messages = []
    for i, pkt in enumerate(packets):
        if Raw not in pkt:
            continue
        
        raw_data = bytes(pkt[Raw].load)
        
        # Fixed structure boundaries
        # Magic(2) | Version(1) | MsgType(1) | ClientID(4) | Timestamp_Sec(8) | 
        # Timestamp_Nsec(4) | Stratum(1) | Precision(1) | Reserved(8) | Checksum(2)
        boundaries = [0, 2, 3, 4, 8, 16, 20, 21, 22, 30, 32]
        
        messages.append({
            "message_id": i,
            "packet_hex": raw_data.hex(),
            "boundaries": boundaries,
            "packet_length": len(raw_data)
        })
    
    ground_truth = {
        "protocol": "TimeSync (TSYNC)",
        "description": "Virtual time sync protocol (fixed 32 bytes, big-endian)",
        "boundary_type": "fixed",
        "total_length": TimeSyncProtocol.TOTAL_LENGTH,
        "total_messages": len(messages),
        "messages": messages
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(ground_truth, f, indent=2, ensure_ascii=False)
    
    print(f"✅ Ground Truth generation complete: {len(messages)} messages")


# ==================== Protocol 5: HeartBeat (HBEAT) - Fixed Length ====================

class HeartBeatProtocol:
    """Heartbeat Monitoring Protocol (HBEAT) - fixed 24 bytes
    
    Structure (little-endian):
    - SyncWord(2): 0xFACE
    - Version(1): 0x02
    - NodeType(1): Node type
    - NodeID(4): Node identifier
    - Sequence(4): Sequence number
    - Uptime(4): Uptime in seconds
    - CpuLoad(1): CPU load percentage
    - MemLoad(1): Memory load percentage
    - Status(1): Status code
    - Flags(1): Flags
    - CRC32(4): CRC32 checksum
    
    Total length: 2+1+1+4+4+4+1+1+1+1+4 = 24 bytes
    """
    
    SYNC_WORD = 0xFACE
    VERSION = 0x02
    TOTAL_LENGTH = 24
    
    # Node types
    NODE_MASTER = 0x01
    NODE_SLAVE = 0x02
    NODE_MONITOR = 0x03
    NODE_GATEWAY = 0x04
    
    # Status codes
    STATUS_OK = 0x00
    STATUS_WARN = 0x01
    STATUS_ERROR = 0x02
    STATUS_CRITICAL = 0x03
    
    def __init__(self, node_id: int, node_type: int = NODE_SLAVE):
        self.node_id = node_id
        self.node_type = node_type
        self.sequence = 0
        self.start_time = time.time()
    
    def build_packet(self, cpu_load: int, mem_load: int, status: int, flags: int = 0) -> bytes:
        """Build fixed 24-byte packet"""
        uptime = int(time.time() - self.start_time)
        
        # Build packet without CRC
        packet = struct.pack(
            '<HBBI II BBBB',
            self.SYNC_WORD,
            self.VERSION,
            self.node_type,
            self.node_id,
            self.sequence,
            uptime,
            cpu_load,
            mem_load,
            status,
            flags
        )
        self.sequence += 1
        
        # Calculate and add CRC32
        crc = crc32(packet) & 0xFFFFFFFF
        packet += struct.pack('<I', crc)
        
        assert len(packet) == self.TOTAL_LENGTH, f"Packet length mismatch: {len(packet)}"
        return packet
    
    def build_heartbeat(self) -> bytes:
        """Build heartbeat packet"""
        cpu_load = random.randint(5, 95)
        mem_load = random.randint(20, 85)
        
        # Determine status based on load
        if cpu_load > 90 or mem_load > 90:
            status = self.STATUS_CRITICAL
        elif cpu_load > 80 or mem_load > 80:
            status = self.STATUS_ERROR
        elif cpu_load > 70 or mem_load > 70:
            status = self.STATUS_WARN
        else:
            status = self.STATUS_OK
        
        flags = 0x01 if random.random() < 0.1 else 0x00  # 10% chance to set flag
        
        return self.build_packet(cpu_load, mem_load, status, flags)


def generate_hbeat_pcap(output_file: str, num_packets: int = 100):
    """Generate HeartBeat protocol PCAP file"""
    print(f"\nGenerating HeartBeat protocol PCAP file: {output_file}")
    
    if not SCAPY_AVAILABLE:
        print("❌ Scapy required")
        return None
    
    packets = []
    
    # Simulate multiple nodes
    nodes = [
        HeartBeatProtocol(0x00010001, HeartBeatProtocol.NODE_MASTER),
        HeartBeatProtocol(0x00020001, HeartBeatProtocol.NODE_SLAVE),
        HeartBeatProtocol(0x00020002, HeartBeatProtocol.NODE_SLAVE),
        HeartBeatProtocol(0x00030001, HeartBeatProtocol.NODE_MONITOR),
        HeartBeatProtocol(0x00040001, HeartBeatProtocol.NODE_GATEWAY),
    ]
    
    monitor_ip = "10.10.10.1"
    
    for i in range(num_packets):
        node = random.choice(nodes)
        node_ip = f"10.10.10.{(node.node_id & 0xFF) + 10}"
        
        data = node.build_heartbeat()
        
        src_mac = f"02:00:00:{(node.node_id >> 16) & 0xff:02x}:{(node.node_id >> 8) & 0xff:02x}:{node.node_id & 0xff:02x}"
        dst_mac = "02:00:00:00:00:01"
        
        # Heartbeat packet (node -> monitor center)
        pkt = Ether(src=src_mac, dst=dst_mac) / \
              IP(src=node_ip, dst=monitor_ip) / \
              UDP(sport=60000 + (node.node_id & 0xFFFF), dport=5678) / Raw(load=data)
        packets.append(pkt)
    
    wrpcap(output_file, packets)
    print(f"✅ Generation complete: {len(packets)} packets (each fixed at {HeartBeatProtocol.TOTAL_LENGTH} bytes)")
    
    print(f"\nHex data of first 3 packets:")
    for i, pkt in enumerate(packets[:3]):
        if Raw in pkt:
            raw = pkt[Raw].load
            print(f"  {i+1}. {raw.hex()} (len={len(raw)})")
    
    return packets


def generate_ground_truth_hbeat(output_file: str, packets: list = None):
    """Generate HeartBeat Ground Truth"""
    print(f"\nGenerating Ground Truth: {output_file}")
    
    if packets is None:
        print("❌ packets parameter required")
        return
    
    messages = []
    for i, pkt in enumerate(packets):
        if Raw not in pkt:
            continue
        
        raw_data = bytes(pkt[Raw].load)
        
        # Fixed structure boundaries
        # SyncWord(2) | Version(1) | NodeType(1) | NodeID(4) | Sequence(4) | 
        # Uptime(4) | CpuLoad(1) | MemLoad(1) | Status(1) | Flags(1) | CRC32(4)
        boundaries = [0, 2, 3, 4, 8, 12, 16, 17, 18, 19, 20, 24]
        
        messages.append({
            "message_id": i,
            "packet_hex": raw_data.hex(),
            "boundaries": boundaries,
            "packet_length": len(raw_data)
        })
    
    ground_truth = {
        "protocol": "HeartBeat (HBEAT)",
        "description": "Virtual heartbeat monitoring protocol (fixed 24 bytes, little-endian)",
        "boundary_type": "fixed",
        "total_length": HeartBeatProtocol.TOTAL_LENGTH,
        "total_messages": len(messages),
        "messages": messages
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(ground_truth, f, indent=2, ensure_ascii=False)
    
    print(f"✅ Ground Truth generation complete: {len(messages)} messages")


def main():
    """Main function"""
    print("="*80)
    print("Custom Protocol Generator")
    print("="*80)
    
    # Check Scapy
    if not SCAPY_AVAILABLE:
        print("\n❌ Error: Scapy required")
        print("Install: pip install scapy")
        print("Or: conda install -c conda-forge scapy")
        return 1
    
    # Ensure output directories exist
    os.makedirs("data", exist_ok=True)
    os.makedirs("ground_truth/boundaries", exist_ok=True)
    os.makedirs("ground_truth/templates", exist_ok=True)
    
    # Generate Protocol 1: CustomIoT
    print("\n" + "="*80)
    print("Protocol 1: CustomIoT (CIOT) - IoT Sensor Protocol")
    print("="*80)
    pcap_file_1 = "data/custom_iot_100.pcap"
    gt_file_1 = "ground_truth/templates/custom_iot_.json"
    
    packets_1 = generate_ciot_pcap(pcap_file_1, num_packets=100)
    if packets_1:
        generate_ground_truth_ciot(gt_file_1, packets=packets_1)
    
    # Generate Protocol 2: GameSync
    print("\n" + "="*80)
    print("Protocol 2: GameSync (GSYNC) - Game State Sync Protocol")
    print("="*80)
    pcap_file_2 = "data/game_sync_100.pcap"
    gt_file_2 = "ground_truth/templates/game_sync_.json"
    
    packets_2 = generate_gsync_pcap(pcap_file_2, num_packets=100)
    if packets_2:
        generate_ground_truth_gsync(gt_file_2, packets=packets_2)
    
    # Generate Protocol 3: SecureChat
    print("\n" + "="*80)
    print("Protocol 3: SecureChat (SCHAT) - Encrypted Chat Protocol")
    print("="*80)
    pcap_file_3 = "data/secure_chat_100.pcap"
    gt_file_3 = "ground_truth/templates/secure_chat_.json"
    
    packets_3 = generate_schat_pcap(pcap_file_3, num_packets=100)
    if packets_3:
        generate_ground_truth_schat(gt_file_3, packets=packets_3)
    
    # Generate Protocol 4: TimeSync (fixed length)
    print("\n" + "="*80)
    print("Protocol 4: TimeSync (TSYNC) - Time Sync Protocol [Fixed 32 bytes]")
    print("="*80)
    pcap_file_4 = "data/time_sync_100.pcap"
    gt_file_4 = "ground_truth/templates/time_sync_.json"
    
    packets_4 = generate_tsync_pcap(pcap_file_4, num_packets=100)
    if packets_4:
        generate_ground_truth_tsync(gt_file_4, packets=packets_4)
    
    # Generate Protocol 5: HeartBeat (fixed length)
    print("\n" + "="*80)
    print("Protocol 5: HeartBeat (HBEAT) - Heartbeat Monitor Protocol [Fixed 24 bytes]")
    print("="*80)
    pcap_file_5 = "data/heart_beat_100.pcap"
    gt_file_5 = "ground_truth/templates/heart_beat_.json"
    
    packets_5 = generate_hbeat_pcap(pcap_file_5, num_packets=100)
    if packets_5:
        generate_ground_truth_hbeat(gt_file_5, packets=packets_5)
    
    # Summary
    print(f"\n{'='*80}")
    print(f"Complete! Generated files:")
    print(f"\nProtocol 1 (CustomIoT) - Dynamic length:")
    print(f"  PCAP: {pcap_file_1}")
    print(f"  Ground Truth: {gt_file_1}")
    print(f"\nProtocol 2 (GameSync) - Dynamic length:")
    print(f"  PCAP: {pcap_file_2}")
    print(f"  Ground Truth: {gt_file_2}")
    print(f"\nProtocol 3 (SecureChat) - Dynamic length:")
    print(f"  PCAP: {pcap_file_3}")
    print(f"  Ground Truth: {gt_file_3}")
    print(f"\nProtocol 4 (TimeSync) - Fixed 32 bytes:")
    print(f"  PCAP: {pcap_file_4}")
    print(f"  Ground Truth: {gt_file_4}")
    print(f"\nProtocol 5 (HeartBeat) - Fixed 24 bytes:")
    print(f"  PCAP: {pcap_file_5}")
    print(f"  Ground Truth: {gt_file_5}")
    print(f"{'='*80}")
    
    return 0


if __name__ == "__main__":
    exit(main())
