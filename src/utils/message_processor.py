#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Message Processing Common Module

Provides unified PCAP message processing and log generation functions,
shared by single_agent and multi_view_moe.
"""

import logging
from collections import defaultdict
from typing import Dict, List, Tuple, Any, Optional

# Import unified PCAP extraction module
try:
    from utils.pcap_extractor import (
        PCAPExtractor,
        infer_protocol_from_filename,
        NETZOB_AVAILABLE,
        remove_protocol_signature,
        has_signature_config
    )
    PCAP_EXTRACTOR_AVAILABLE = True
except ImportError:
    try:
        from .pcap_extractor import (
            PCAPExtractor,
            infer_protocol_from_filename,
            NETZOB_AVAILABLE,
            remove_protocol_signature,
            has_signature_config
        )
        PCAP_EXTRACTOR_AVAILABLE = True
    except ImportError:
        PCAP_EXTRACTOR_AVAILABLE = False
        NETZOB_AVAILABLE = False
        
        def infer_protocol_from_filename(filepath: str) -> str:
            return 'generic'
        
        def remove_protocol_signature(data: bytes, protocol_name: str) -> bytes:
            return data
        
        def has_signature_config(protocol_name: str) -> bool:
            return False

# Try import Netzob (for session processing)
try:
    from netzob.Model.Vocabulary.Session import Session
    SESSION_AVAILABLE = True
except ImportError:
    SESSION_AVAILABLE = False


class SimpleMessage:
    """Simple message object for storing message data"""
    
    def __init__(self, data: bytes):
        self.data = data


class PCAPProcessor:
    """
    PCAP File Processor - Unified message extraction and session processing
    
    Shared by single_agent and multi_view_moe.
    """
    
    MAX_LEN = 500
    
    def __init__(self, filepath: str, protocol_type: str = 'generic', layer: int = 5,
                 remove_signatures: bool = True):
        """
        Initialize PCAP processor
        
        Args:
            filepath: PCAP file path
            protocol_type: Protocol type (for signature removal)
            layer: OSI layer (default 5)
            remove_signatures: Whether to remove protocol signatures
        """
        if not PCAP_EXTRACTOR_AVAILABLE and not NETZOB_AVAILABLE:
            raise ImportError("Either pcap_extractor or Netzob is required")
        
        self.filepath = filepath
        self.protocol_type = (protocol_type or 'generic').lower()
        self.layer = layer
        self.remove_signatures = remove_signatures
        self.messages: List[SimpleMessage] = []
        self.sessions: Dict[str, List[Tuple[SimpleMessage, int]]] = defaultdict(list)
        self._raw_messages = []  # Store original Netzob message objects (for session processing)
        
        logging.info(f"Processing PCAP file: {self.filepath}")
        logging.info(f"Protocol: {self.protocol_type}, Layer: {self.layer}")
        if remove_signatures and has_signature_config(self.protocol_type):
            logging.info(f"Signature removal: ENABLED for {self.protocol_type}")
        
        self._import_and_filter_messages()
        if self.messages:
            self._process_sessions()
    
    def _import_and_filter_messages(self):
        """Import and filter messages - using unified pcap_extractor"""
        logging.info("Importing messages from PCAP...")
        
        if self.protocol_type == 'icmp':
            self.layer = 3
        
        try:
            if PCAP_EXTRACTOR_AVAILABLE:
                # Use unified pcap_extractor module
                extractor = PCAPExtractor(use_netzob=True, layer=self.layer, max_length=self.MAX_LEN)
                extracted = extractor.extract_messages(
                    self.filepath,
                    self.protocol_type
                )
                
                messages = []
                for msg in extracted:
                    data = msg.data
                    # Apply signature removal
                    if self.remove_signatures:
                        data = remove_protocol_signature(data, self.protocol_type)
                    messages.append(SimpleMessage(data))
                
                self.messages = messages
                self._raw_messages = self.messages  # Simplified mode cannot use Netzob sessions
                
            else:
                # Fallback to original Netzob processing
                from netzob.Import.PCAPImporter.PCAPImporter import PCAPImporter
                messages_iterable = PCAPImporter.readFile(
                    filePath=self.filepath,
                    importLayer=self.layer
                ).values()
                
                filtered_messages = []
                for m in messages_iterable:
                    if not m.data or len(m.data) < 4:
                        continue
                    if len(m.data) > self.MAX_LEN:
                        m.data = m.data[:self.MAX_LEN]
                    # Apply signature removal
                    if self.remove_signatures:
                        m.data = remove_protocol_signature(bytes(m.data), self.protocol_type)
                    filtered_messages.append(m)
                
                self.messages = filtered_messages
                self._raw_messages = filtered_messages
            
            logging.info(f"Imported {len(self.messages)} messages")
            
        except Exception as e:
            logging.error(f"Failed to import PCAP file: {e}")
            return
    
    def _process_sessions(self):
        """Process sessions"""
        logging.info("Processing sessions...")
        
        try:
            if SESSION_AVAILABLE and self._raw_messages and hasattr(self._raw_messages[0], 'source'):
                # Use Netzob for session clustering (requires original Netzob message objects)
                session = Session(self._raw_messages)
                session_groups = session.cluster()
                
                for idx, (session_key, messages) in enumerate(session_groups.items()):
                    session_messages = []
                    for message in messages:
                        direction = 0 if idx % 2 == 0 else 1
                        session_messages.append((message, direction))
                    self.sessions[session_key] = session_messages
            else:
                # Simplified session processing: put all messages in one session
                for idx, message in enumerate(self.messages):
                    session_key = f"session_{idx // 10}"
                    direction = idx % 2  # Alternating direction
                    self.sessions[session_key].append((message, direction))
        
        except Exception as e:
            logging.error(f"Session clustering failed: {e}")
            # Fallback to simple grouping
            for idx, message in enumerate(self.messages):
                session_key = f"session_{idx // 10}"  # 10 messages per group
                direction = idx % 2  # Alternating direction
                self.sessions[session_key].append((message, direction))
        
        logging.info(f"Created {len(self.sessions)} sessions")
    
    def get_message_log(self) -> str:
        """
        Generate message log
        
        Unified format:
        - Contains session grouping
        - Shows direction (S = Send, R = Receive)
        - Shows hex data
        
        Returns:
            Formatted message log string
        """
        if not self.sessions:
            return ""
        
        log_lines = [
            "--- Message Direction Analysis (Grouped by Session) ---",
            "Direction: S = Send (from initiator), R = Receive (to initiator)",
            ""
        ]
        
        for s_idx, (s_key, messages) in enumerate(self.sessions.items()):
            log_lines.append(f"{'='*80}")
            log_lines.append(f"Session #{s_idx + 1}:")
            log_lines.append(f"{'-'*80}")
            log_lines.append(f"{'#':<6} {'Dir':<5} {'Data'}")
            log_lines.append(f"{'-'*80}")
            
            for m_idx, (message, direction) in enumerate(messages):
                dir_label = "S" if direction == 0 else "R"
                log_lines.append(
                    f"{m_idx + 1:<6} {dir_label:<5} {message.data.hex()}"
                )
            log_lines.append("")
        
        return "\n".join(log_lines)


# Export public functions
__all__ = [
    'PCAPProcessor',
    'SimpleMessage',
    'infer_protocol_from_filename',
    'remove_protocol_signature',
    'has_signature_config',
    'PCAP_EXTRACTOR_AVAILABLE',
    'NETZOB_AVAILABLE',
    'SESSION_AVAILABLE',
]
