import pytest
from fastapi.testclient import TestClient
import dpkt
import tempfile
import os
import json
from datetime import datetime
import time
from app import app, process_pcap, get_summary_data, get_protocol_distribution, track_tcp_conversations

client = TestClient(app)

@pytest.fixture
def sample_tcp_pcap():
    """Generate a sample PCAP file with TCP packets"""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as f:
        writer = dpkt.pcap.Writer(f)
        
        # Create TCP packet
        eth = dpkt.ethernet.Ethernet()
        eth.src = b'\x00\x11\x22\x33\x44\x55'
        eth.dst = b'\x66\x77\x88\x99\xaa\xbb'
        ip = dpkt.ip.IP(src=b'\x7f\x00\x00\x01', dst=b'\x7f\x00\x00\x02')
        tcp = dpkt.tcp.TCP(sport=1234, dport=80, seq=1, ack=1)
        ip.data = tcp
        eth.data = ip
        writer.writepkt(eth, ts=time.time())
        
        # Second TCP packet with ack
        tcp_ack = dpkt.tcp.TCP(sport=80, dport=1234, seq=1, ack=2)
        ip_ack = dpkt.ip.IP(src=b'\x7f\x00\x00\x02', dst=b'\x7f\x00\x00\x01')
        ip_ack.data = tcp_ack
        eth_ack = dpkt.ethernet.Ethernet()
        eth_ack.data = ip_ack
        writer.writepkt(eth_ack, ts=time.time()+0.1)
        
        f.close()
        yield f.name
        os.unlink(f.name)

@pytest.fixture
def sample_mqtt_pcap():
    """Generate a sample PCAP with MQTT packets"""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as f:
        writer = dpkt.pcap.Writer(f)
        
        # MQTT CONNECT packet
        eth = dpkt.ethernet.Ethernet()
        ip = dpkt.ip.IP(src=b'\x7f\x00\x00\x01', dst=b'\x7f\x00\x00\x02')
        tcp = dpkt.tcp.TCP(sport=5432, dport=1883, seq=1)
        tcp.data = b'\x10\x16\x00\x04MQTT\x04\x02\x00\x3c\x00\x07client'  # MQTT Connect
        ip.data = tcp
        eth.data = ip
        writer.writepkt(eth, ts=time.time())
        
        f.close()
        yield f.name
        os.unlink(f.name)

def test_process_pcap_tcp(sample_tcp_pcap):
    packets = process_pcap(sample_tcp_pcap)
    assert len(packets) == 2
    assert packets[0]['protocol'] == 'TCP'
    assert packets[0]['src_port'] == 1234
    assert packets[1]['dst_port'] == 1234

def test_process_pcap_mqtt(sample_mqtt_pcap):
    packets = process_pcap(sample_mqtt_pcap)
    assert len(packets) >= 1
    assert packets[0]['protocol'] == 'MQTT'
    assert packets[0]['mqtt_type'] == 1  # CONNECT packet type

def test_summary_data():
    test_packets = [
        {'protocol': 'TCP', 'timestamp': 1.0, 'size': 100},
        {'protocol': 'TCP', 'timestamp': 1.1, 'size': 100},
    ]
    summary = get_summary_data(test_packets)
    assert 'avgLatency' in summary
    assert isinstance(summary['packetLoss'], float)

def test_protocol_distribution():
    test_packets = [
        {'protocol': 'TCP'}, {'protocol': 'TCP'}, {'protocol': 'UDP'}
    ]
    distribution = get_protocol_distribution(test_packets)
    assert len(distribution) == 2
    tcp_perc = next(d for d in distribution if d['name'] == 'TCP')['value']
    assert tcp_perc == 67  # 2/3 ≈ 67%

def test_track_tcp_conversations():
    packets = [
        {'id': 1, 'protocol': 'TCP', 'src_ip': '1.1.1.1', 'dst_ip': '2.2.2.2',
         'src_port': 1234, 'dst_port': 80, 'tcp_seq': 1, 'tcp_ack': 0},
        {'id': 2, 'protocol': 'TCP', 'src_ip': '2.2.2.2', 'dst_ip': '1.1.1.1',
         'src_port': 80, 'dst_port': 1234, 'tcp_seq': 1, 'tcp_ack': 2}
    ]
    pairs = track_tcp_conversations(packets)
    assert pairs == {1: 2}

def test_api_analyze(sample_tcp_pcap):
    with open(sample_tcp_pcap, 'rb') as f:
        response = client.post(
            "/analyze",
            files={"pcap_file": ("test.pcap", f, "application/vnd.tcpdump.pcap")}
        )
    assert response.status_code == 200
    data = response.json()
    assert 'summaryData' in data
    assert 'protocolDistribution' in data

def test_api_invalid_file():
    response = client.post(
        "/analyze",
        files={"pcap_file": ("test.txt", b"invalid data", "text/plain")}
    )
    assert response.status_code == 500
    assert "Error analyzing PCAP file" in response.text

def test_api_save_analysis(sample_tcp_pcap):
    with open(sample_tcp_pcap, 'rb') as f:
        response = client.post(
            "/save-analysis",
            data={"output_filename": "test_output.json"},
            files={"pcap_file": ("test.pcap", f, "application/vnd.tcpdump.pcap")}
        )
    assert response.status_code == 200
    assert os.path.exists("test_output.json")
    os.remove("test_output.json")

def test_insights_data_zero_division():
    # Test case that might cause division by zero
    test_packets = [
        {'protocol': 'TCP', 'timestamp': 1.0, 'size': 100},
        {'protocol': 'TCP', 'timestamp': 1.1, 'size': 100},
    ]
    insights = get_insights_data(test_packets)
    assert 'insights' in insights
    assert 'correlations' in insights

def test_empty_pcap():
    # Create empty pcap
    with tempfile.NamedTemporaryFile(suffix=".pcap") as f:
        writer = dpkt.pcap.Writer(f)
        f.close()
        packets = process_pcap(f.name)
        assert len(packets) == 0
        summary = get_summary_data(packets)
        assert summary['avgLatency'] == 0