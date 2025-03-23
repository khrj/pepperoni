import time
from .packet_processing import process_pcap
from .utils import (
    get_summary_data,
    get_protocol_distribution,
    categorize_delays,
    get_latency_trends,
    get_delay_timeline,
    get_insights_data,
    get_packet_data
)

def analyze_pcap(file_path, baseline_file=None):
    start_time = time.time()
    print(f"Starting analysis of {file_path}...")

    packets = process_pcap(file_path)
    print(f"Processed {len(packets)} packets in {time.time() - start_time:.2f} seconds")

    baseline_packets = None
    if baseline_file:
        baseline_packets = process_pcap(baseline_file)

    summary_data = get_summary_data(packets, baseline_packets)
    protocol_distribution = get_protocol_distribution(packets)
    delay_categories = categorize_delays(packets)
    latency_trends = get_latency_trends(packets)
    delay_timeline = get_delay_timeline(packets)
    insights_data = get_insights_data(packets)
    packet_display_data = get_packet_data(packets)

    print(f"Analysis completed in {time.time() - start_time:.2f} seconds")

    return {
        "summaryData": summary_data,
        "protocolDistribution": protocol_distribution,
        "delayCategories": delay_categories,
        "latencyTrends": latency_trends,
        "delayTimeline": delay_timeline,
        "insightsData": insights_data,
        "packetData": packet_display_data,
    }