#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Utility Module

Contains PCAP extraction, message processing, protocol format, LLM client, Header detection, etc.
"""

__all__ = [
    'pcap_extractor',
    'message_processor',
    'protocol_format',
    'llm_client',
]

# Export pcap_extractor main interfaces
from .pcap_extractor import (
    PCAPExtractor,
    ExtractedMessage,
    ProtocolExtractor,
    infer_protocol_from_filename,
    extract_protocol_messages,
    get_extractor,
    NETZOB_AVAILABLE,
    SCAPY_AVAILABLE,
)

# Export message_processor main interfaces
from .message_processor import (
    PCAPProcessor,
    SimpleMessage,
)
