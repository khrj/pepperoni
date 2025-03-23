import unittest
import os
from datetime import datetime
from core.pcap_analyze import (
    process_pcap,
    get_summary_data,
    get_protocol_distribution,
    categorize_delays,
    get_latency_trends,
    get_delay_timeline,
    get_packet_data,
    analyze_pcap,
)
from collections import defaultdict

class TestPcapAnalyze(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Load test PCAP files before running tests."""
        cls.test_pcap_path = os.path.join(
            os.path.dirname(__file__), "test_files", "20_11_24_bro_rpi_10ms_2min.pcapng"
        )
        cls.baseline_pcap_path = os.path.join(
            os.path.dirname(__file__), "test_files", "28-1-25-bro-rpi-60ms.pcapng"
        )
        cls.packets = process_pcap(cls.test_pcap_path)
        cls.baseline_packets = process_pcap(cls.baseline_pcap_path)

    def test_process_pcap(self):
        """Test that process_pcap returns a list of packets with expected fields."""
        self.assertIsInstance(self.packets, list)
        self.assertGreater(len(self.packets), 0)

        # Check that each packet has the required fields
        for packet in self.packets:
            self.assertIn("id", packet)
            self.assertIn("timestamp", packet)
            self.assertIn("size", packet)
            self.assertIn("protocol", packet)
            self.assertIn("src_ip", packet)
            self.assertIn("dst_ip", packet)
            self.assertIn("src_port", packet)
            self.assertIn("dst_port", packet)

    def test_get_summary_data(self):
        """Test that get_summary_data returns expected metrics."""
        summary_data = get_summary_data(self.packets, self.baseline_packets)
        self.assertIsInstance(summary_data, dict)

        # Check required fields
        self.assertIn("avgLatency", summary_data)
        self.assertIn("packetLoss", summary_data)
        self.assertIn("jitter", summary_data)
        self.assertIn("numPackets", summary_data)

        # Check baseline data if provided
        if self.baseline_packets:
            self.assertIn("baseline", summary_data)
            self.assertIsInstance(summary_data["baseline"], dict)

    def test_get_protocol_distribution(self):
        """Test that get_protocol_distribution returns a list of protocols with percentages."""
        protocol_distribution = get_protocol_distribution(self.packets)
        self.assertIsInstance(protocol_distribution, list)

        # Check that percentages sum to 100 (approximately)
        total_percentage = sum(item["value"] for item in protocol_distribution)
        self.assertAlmostEqual(total_percentage, 100, delta=1)

    def test_categorize_delays(self):
        """Test that categorize_delays returns a list of delay categories with percentages."""
        delay_categories = categorize_delays(self.packets)
        self.assertIsInstance(delay_categories, list)

        # Check that percentages sum to 100 (approximately)
        total_percentage = sum(item["value"] for item in delay_categories)
        self.assertAlmostEqual(total_percentage, 100, delta=1)

    def test_get_latency_trends(self):
        """Test that get_latency_trends returns a list of latency data over time."""
        latency_trends = get_latency_trends(self.packets)
        self.assertIsInstance(latency_trends, list)

        # Check that each interval has a time and protocol latencies
        for interval in latency_trends:
            self.assertIn("time", interval)
            self.assertIn("mqtt", interval)
            self.assertIn("tcp", interval)

    def test_get_delay_timeline(self):
        """Test that get_delay_timeline returns a list of delay data over time."""
        delay_timeline = get_delay_timeline(self.packets)
        self.assertIsInstance(delay_timeline, list)

        # Check that each interval has a time and protocol delays
        for interval in delay_timeline:
            self.assertIn("time", interval)
            self.assertIn("mqtt", interval)
            self.assertIn("tcp", interval)
            self.assertNotIn("udp", interval)

    def test_get_packet_data(self):
        """Test that get_packet_data returns formatted packet data."""
        packet_data = get_packet_data(self.packets, limit=10)
        self.assertIsInstance(packet_data, list)
        self.assertLessEqual(len(packet_data), 10)

        # Check that each packet has the required fields
        for packet in packet_data:
            self.assertIn("id", packet)
            self.assertIn("timestamp", packet)
            self.assertIn("source", packet)
            self.assertIn("destination", packet)
            self.assertIn("protocol", packet)
            self.assertIn("size", packet)
            self.assertIn("delay", packet)
            self.assertIn("delayCategory", packet)
            self.assertIn("hexPayload", packet)
            self.assertIn("formattedPayload", packet)

    def test_analyze_pcap(self):
        """Test that analyze_pcap returns a complete analysis dictionary."""
        analysis_data = analyze_pcap(self.test_pcap_path, self.baseline_pcap_path)
        self.assertIsInstance(analysis_data, dict)

        # Check that all required keys are present
        self.assertIn("summaryData", analysis_data)
        self.assertIn("protocolDistribution", analysis_data)
        self.assertIn("delayCategories", analysis_data)
        self.assertIn("latencyTrends", analysis_data)
        self.assertIn("delayTimeline", analysis_data)
        self.assertIn("insightsData", analysis_data)
        self.assertIn("packetData", analysis_data)


if __name__ == "__main__":
    unittest.main()
