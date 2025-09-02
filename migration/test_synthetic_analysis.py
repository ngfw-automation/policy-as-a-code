#!/usr/bin/env python3
"""
Simple test script to validate synthetic testing implementation.
"""
import sys
import os

# Add the parent directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from migration.lib import policy_analyzer as analyzer

def test_helper_functions():
    """Test the helper functions for extracting port and protocol."""
    print("Testing helper functions...")
    
    # Test port extraction
    assert analyzer._extract_port_number_from_defaults("tcp/443,80") == 443
    assert analyzer._extract_port_number_from_defaults(["tcp/80,443"]) == 80
    assert analyzer._extract_port_number_from_defaults("tcp/dynamic") == 443
    assert analyzer._extract_port_number_from_defaults(None) == 443
    
    # Test protocol extraction
    assert analyzer._extract_protocol_from_defaults("tcp/443") == "tcp"
    assert analyzer._extract_protocol_from_defaults("udp/53") == "udp"
    assert analyzer._extract_protocol_from_defaults(["tcp/80"]) == "tcp"
    assert analyzer._extract_protocol_from_defaults(None) == "tcp"
    
    print("✓ Helper functions work correctly")

def test_source_ip_extraction():
    """Test source IP extraction from traffic data."""
    print("Testing source IP extraction...")
    
    # Test data with source IP
    traffic_with_ip = [
        {"Source IP": "10.1.1.100", "Application": "web-browsing"},
        {"Source": "10.1.1.101", "Application": "ssl"}
    ]
    
    ip = analyzer._extract_source_ip_from_traffic(traffic_with_ip)
    assert ip == "10.1.1.100"
    
    # Test data without source IP
    traffic_without_ip = [
        {"Source User": "user1", "Application": "web-browsing"}
    ]
    
    ip = analyzer._extract_source_ip_from_traffic(traffic_without_ip)
    assert ip is None
    
    print("✓ Source IP extraction works correctly")

if __name__ == "__main__":
    try:
        test_helper_functions()
        test_source_ip_extraction()
        print("\n✅ All tests passed!")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)