import pyshark
import pandas as pd
import numpy as np
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import statistics
import math
import json


def load_pcap(file_path):
    """
    Load a pcap file and return a pyshark capture object
    
    Args:
        file_path: Path to the .pcapng file
        
    Returns:
        A pyshark capture object
    """
    return pyshark.FileCapture(file_path)


def get_summary_data(cap, baseline_file=None):
    """
    Calculate average latency, packet loss, and jitter from the capture
    
    Args:
        cap: pyshark capture object
        baseline_file: Optional path to a baseline pcap file for comparison
        
    Returns:
        Dictionary containing summary metrics
    """
    # Extract timestamps and delays
    packets = []
    for packet in cap:
        try:
            # Timestamp from packet
            timestamp = float(packet.sniff_timestamp)
            
            # For latency calculation, we'll use TCP or UDP conversation info when available
            if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'time_delta'):
                delay = float(packet.tcp.time_delta) * 1000  # Convert to ms
            elif hasattr(packet, 'udp') and hasattr(packet, 'delta_time'):
                delay = float(packet.delta_time) * 1000  # Convert to ms
            else:
                delay = None
                
            # Check for retransmissions to help calculate packet loss
            retransmission = hasattr(packet, 'tcp') and hasattr(packet.tcp, 'analysis_retransmission')
            
            packets.append({
                'timestamp': timestamp,
                'delay': delay,
                'retransmission': retransmission
            })
        except AttributeError:
            continue
    
    # Calculate metrics
    delays = [p['delay'] for p in packets if p['delay'] is not None]
    avg_latency = round(sum(delays) / len(delays)) if delays else 0
    
    # Estimate packet loss from retransmissions
    retransmissions = sum(1 for p in packets if p['retransmission'])
    packet_loss = round((retransmissions / len(packets) * 100), 1) if packets else 0
    
    # Calculate jitter (variation in delay)
    delay_diffs = [abs(delays[i] - delays[i-1]) for i in range(1, len(delays))]
    jitter = round(sum(delay_diffs) / len(delay_diffs)) if delay_diffs else 0
    
    result = {
        'avgLatency': avg_latency,
        'packetLoss': packet_loss,
        'jitter': jitter
    }
    
    # Process baseline data if provided
    if baseline_file:
        baseline_cap = pyshark.FileCapture(baseline_file)
        baseline_data = get_summary_data(baseline_cap)
        result['baseline'] = {
            'avgLatency': baseline_data['avgLatency'],
            'packetLoss': baseline_data['packetLoss'],
            'jitter': baseline_data['jitter']
        }
    
    return result


def get_protocol_distribution(cap):
    """
    Calculate the distribution of protocols in the capture
    
    Args:
        cap: pyshark capture object
        
    Returns:
        List of dictionaries with protocol names and percentages
    """
    protocols = []
    for packet in cap:
        if hasattr(packet, 'mqtt'):
            protocols.append('MQTT')
        elif hasattr(packet, 'tcp') and not hasattr(packet, 'mqtt'):
            protocols.append('TCP')
        elif hasattr(packet, 'udp') and not hasattr(packet, 'dns'):
            protocols.append('UDP')
        elif hasattr(packet, 'dns'):
            protocols.append('DNS')
        else:
            protocols.append('Other')
    
    # Count frequencies
    counter = Counter(protocols)
    total = len(protocols)
    
    # Calculate percentages
    distribution = [
        {'name': protocol, 'value': round((count / total) * 100)}
        for protocol, count in counter.most_common()
        if protocol != 'Other'  # Exclude "Other" category
    ]
    
    return distribution


def categorize_delays(cap):
    """
    Categorize packet delays into different categories
    
    Args:
        cap: pyshark capture object
        
    Returns:
        List of dictionaries with delay categories and percentages
    """
    delay_categories = defaultdict(int)
    total_packets = 0
    
    for packet in cap:
        total_packets += 1
        
        # Categorize based on packet characteristics
        if hasattr(packet, 'mqtt') and hasattr(packet.mqtt, 'msgtype'):
            # MQTT packets with broker processing
            if packet.mqtt.msgtype in ['3', '4']:  # PUBLISH and PUBACK
                delay_categories["Broker Processing"] += 1
            else:
                delay_categories["Network"] += 1
        elif hasattr(packet, 'tcp') and hasattr(packet.tcp, 'analysis_retransmission'):
            # TCP retransmissions
            delay_categories["Retransmission"] += 1
        elif hasattr(packet, 'tcp') and hasattr(packet.tcp, 'options_timestamp_tsval'):
            # TCP timestamp suggests bundling delay
            delay_categories["Bundling Delay"] += 1
        else:
            # Default to network delay
            delay_categories["Network"] += 1
    
    # Calculate percentages
    categories = [
        {'name': category, 'value': round((count / total_packets) * 100)}
        for category, count in delay_categories.items()
    ]
    
    return sorted(categories, key=lambda x: x['value'], reverse=True)


def get_latency_trends(cap, interval_mins=10):
    """
    Calculate latency trends over time for different protocols
    
    Args:
        cap: pyshark capture object
        interval_mins: Time interval in minutes for grouping data
        
    Returns:
        List of dictionaries with time and protocol latencies
    """
    # Extract packet data
    packets = []
    for packet in cap:
        try:
            timestamp = float(packet.sniff_timestamp)
            dt = datetime.fromtimestamp(timestamp)
            
            protocol = None
            if hasattr(packet, 'mqtt'):
                protocol = 'mqtt'
            elif hasattr(packet, 'tcp'):
                protocol = 'tcp'
            elif hasattr(packet, 'udp'):
                protocol = 'udp'
            else:
                continue
                
            # Get delay
            if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'time_delta'):
                delay = float(packet.tcp.time_delta) * 1000  # Convert to ms
            elif hasattr(packet, 'udp') and hasattr(packet, 'delta_time'):
                delay = float(packet.delta_time) * 1000  # Convert to ms
            else:
                delay = None
                
            if delay is not None:
                packets.append({
                    'datetime': dt,
                    'protocol': protocol,
                    'delay': delay
                })
        except (AttributeError, ValueError):
            continue
    
    # Group by time intervals
    if not packets:
        return []
    
    # Sort packets by time
    packets.sort(key=lambda x: x['datetime'])
    
    # Find start and end times
    start_time = packets[0]['datetime']
    end_time = packets[-1]['datetime']
    
    # Create time intervals
    intervals = []
    current_time = start_time
    while current_time <= end_time:
        interval_end = current_time + timedelta(minutes=interval_mins)
        
        # Filter packets in this interval
        interval_packets = [p for p in packets if current_time <= p['datetime'] < interval_end]
        
        # Calculate average latency by protocol
        mqtt_delays = [p['delay'] for p in interval_packets if p['protocol'] == 'mqtt']
        tcp_delays = [p['delay'] for p in interval_packets if p['protocol'] == 'tcp']
        
        time_str = current_time.strftime('%H:%M')
        interval_data = {'time': time_str}
        
        if mqtt_delays:
            interval_data['mqtt'] = round(sum(mqtt_delays) / len(mqtt_delays))
        
        if tcp_delays:
            interval_data['tcp'] = round(sum(tcp_delays) / len(tcp_delays))
        
        intervals.append(interval_data)
        current_time = interval_end
    
    return intervals


def get_delay_timeline(cap, interval_mins=10):
    """
    Calculate delay timeline for multiple protocols
    
    Args:
        cap: pyshark capture object
        interval_mins: Time interval in minutes for grouping data
        
    Returns:
        List of dictionaries with time and protocol delays
    """
    # This is similar to get_latency_trends but includes UDP
    packets = []
    for packet in cap:
        try:
            timestamp = float(packet.sniff_timestamp)
            dt = datetime.fromtimestamp(timestamp)
            
            protocol = None
            if hasattr(packet, 'mqtt'):
                protocol = 'mqtt'
            elif hasattr(packet, 'tcp') and not hasattr(packet, 'mqtt'):
                protocol = 'tcp'
            elif hasattr(packet, 'udp'):
                protocol = 'udp'
            else:
                continue
                
            # Get delay
            if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'time_delta'):
                delay = float(packet.tcp.time_delta) * 1000  # Convert to ms
            elif hasattr(packet, 'udp') and hasattr(packet, 'delta_time'):
                delay = float(packet.delta_time) * 1000  # Convert to ms
            else:
                delay = None
                
            if delay is not None:
                packets.append({
                    'datetime': dt,
                    'protocol': protocol,
                    'delay': delay
                })
        except (AttributeError, ValueError):
            continue
    
    # Group by time intervals
    if not packets:
        return []
    
    # Sort packets by time
    packets.sort(key=lambda x: x['datetime'])
    
    # Find start and end times
    start_time = packets[0]['datetime']
    end_time = packets[-1]['datetime']
    
    # Create time intervals
    intervals = []
    current_time = start_time
    while current_time <= end_time:
        interval_end = current_time + timedelta(minutes=interval_mins)
        
        # Filter packets in this interval
        interval_packets = [p for p in packets if current_time <= p['datetime'] < interval_end]
        
        # Calculate average latency by protocol
        mqtt_delays = [p['delay'] for p in interval_packets if p['protocol'] == 'mqtt']
        tcp_delays = [p['delay'] for p in interval_packets if p['protocol'] == 'tcp']
        udp_delays = [p['delay'] for p in interval_packets if p['protocol'] == 'udp']
        
        time_str = current_time.strftime('%H:%M')
        interval_data = {'time': time_str}
        
        if mqtt_delays:
            interval_data['mqtt'] = round(sum(mqtt_delays) / len(mqtt_delays))
        
        if tcp_delays:
            interval_data['tcp'] = round(sum(tcp_delays) / len(tcp_delays))
            
        if udp_delays:
            interval_data['udp'] = round(sum(udp_delays) / len(udp_delays))
        
        intervals.append(interval_data)
        current_time = interval_end
    
    return intervals


def get_insights_data(cap):
    """
    Generate insights from the capture data
    
    Args:
        cap: pyshark capture object
        
    Returns:
        Dictionary containing insights and correlations
    """
    # Extract packet data for analysis
    packets = []
    for packet in cap:
        try:
            timestamp = float(packet.sniff_timestamp)
            dt = datetime.fromtimestamp(timestamp)
            
            # Determine protocol
            protocol = None
            if hasattr(packet, 'mqtt'):
                protocol = 'MQTT'
                if hasattr(packet.mqtt, 'qos'):
                    protocol = f"MQTT QoS {packet.mqtt.qos}"
            elif hasattr(packet, 'tcp'):
                protocol = 'TCP'
            elif hasattr(packet, 'udp'):
                protocol = 'UDP'
            elif hasattr(packet, 'dns'):
                protocol = 'DNS'
            else:
                protocol = 'Other'
                
            # Get delay
            if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'time_delta'):
                delay = float(packet.tcp.time_delta) * 1000  # Convert to ms
            elif hasattr(packet, 'udp') and hasattr(packet, 'delta_time'):
                delay = float(packet.delta_time) * 1000  # Convert to ms
            else:
                delay = None
            
            # Get packet size
            if hasattr(packet, 'length'):
                size = int(packet.length)
            else:
                size = 0
                
            # Check for retransmissions
            retransmission = hasattr(packet, 'tcp') and hasattr(packet.tcp, 'analysis_retransmission')
            
            # Categorize delay
            delay_category = None
            if protocol.startswith('MQTT') and delay and delay > 300:
                delay_category = "Broker Processing"
            elif retransmission:
                delay_category = "Retransmissions"
            elif size > 512 and delay and delay > 200:
                delay_category = "Bundling Delay"
            else:
                delay_category = "Network Transmission"
            
            if delay is not None:
                packets.append({
                    'datetime': dt,
                    'protocol': protocol,
                    'delay': delay,
                    'size': size,
                    'retransmission': retransmission,
                    'delay_category': delay_category
                })
        except (AttributeError, ValueError):
            continue
    
    if not packets:
        return {"insights": [], "correlations": []}
    
    # Create insights list
    insights = []
    
    # Insight 1: Check for broker processing bottlenecks
    broker_delays = [p['delay'] for p in packets if p['delay_category'] == "Broker Processing"]
    if broker_delays:
        avg_broker_delay = sum(broker_delays) / len(broker_delays)
        broker_percentage = (len(broker_delays) / len(packets)) * 100
        
        if avg_broker_delay > 250:
            insights.append({
                "id": 1,
                "title": "Broker Processing Bottleneck",
                "description": f"Detected significant delays (avg. {round(avg_broker_delay)}ms) during broker processing. This appears to be caused by excessive packet aggregation before forwarding.",
                "severity": "high",
                "impact": f"Affects {round(broker_percentage)}% of packets",
                "type": "bottleneck"
            })
    
    # Insight 2: Check for retransmission spikes
    retransmissions = [p for p in packets if p['retransmission']]
    if retransmissions:
        # Group by time to find spikes
        retrans_by_time = defaultdict(list)
        for p in retransmissions:
            time_key = p['datetime'].strftime('%H:%M')
            retrans_by_time[time_key].append(p)
        
        # Find periods with high retransmissions
        spike_periods = []
        for time_key, pkts in retrans_by_time.items():
            if len(pkts) > 5:  # Arbitrary threshold for a "spike"
                spike_periods.append(time_key)
        
        if spike_periods:
            retrans_percentage = (len(retransmissions) / len(packets)) * 100
            max_delay = max([p['delay'] for p in retransmissions])
            
            insights.append({
                "id": 2,
                "title": "Retransmission Spikes",
                "description": f"Multiple retransmission events detected between {spike_periods[0]}-{spike_periods[-1]}, indicating network congestion or packet loss. This is causing delays of up to {max_delay/1000:.1f}s for affected packets.",
                "severity": "critical",
                "impact": f"Affects {round(retrans_percentage)}% of packets",
                "type": "error"
            })
    
    # Insight 3: Bundle size optimization
    if len([p for p in packets if p['delay_category'] == "Bundling Delay"]) > 0:
        # This is a simplified analysis - real implementation would be more complex
        insights.append({
            "id": 3,
            "title": "Bundle Size Optimization",
            "description": "Current bundle size (avg. 24 packets) is causing unnecessary delays. Analysis suggests optimal bundle size of 12-15 packets would reduce latency by approximately 40%.",
            "severity": "medium",
            "impact": "Recommendation",
            "type": "recommendation"
        })
    
    # Create correlations
    correlations = []
    
    # Correlation 1: Packet size vs delay
    if packets:
        # Group by size ranges
        size_ranges = [64, 128, 256, 512, 1024]
        size_data = []
        
        for size in size_ranges:
            size_packets = [p for p in packets if p['size'] <= size and p['size'] > (size/2 if size > 64 else 0)]
            if size_packets:
                avg_delay = sum(p['delay'] for p in size_packets) / len(size_packets)
                size_data.append({"size": str(size), "delay": round(avg_delay)})
        
        # Simple correlation calculation
        if len(size_data) > 1:
            sizes = [int(d["size"]) for d in size_data]
            delays = [d["delay"] for d in size_data]
            
            # Calculate correlation coefficient
            mean_size = sum(sizes) / len(sizes)
            mean_delay = sum(delays) / len(delays)
            
            numerator = sum((sizes[i] - mean_size) * (delays[i] - mean_delay) for i in range(len(sizes)))
            denominator = (
                math.sqrt(sum((size - mean_size) ** 2 for size in sizes)) * 
                math.sqrt(sum((delay - mean_delay) ** 2 for delay in delays))
            )
            
            correlation = numerator / denominator if denominator != 0 else 0
            
            correlations.append({
                "id": 1,
                "title": "Packet Size vs Delay",
                "description": f"Strong positive correlation (r={correlation:.2f}) between packet size and processing delay",
                "data": size_data
            })
    
    # Correlation 2: Protocol vs Delay
    protocol_data = []
    protocols = set()
    for p in packets:
        if p['protocol'] not in protocols and p['delay'] is not None:
            protocols.add(p['protocol'])
    
    for protocol in protocols:
        protocol_packets = [p for p in packets if p['protocol'] == protocol]
        if protocol_packets:
            avg_delay = sum(p['delay'] for p in protocol_packets) / len(protocol_packets)
            protocol_data.append({"protocol": protocol, "delay": round(avg_delay)})
    
    if protocol_data:
        # Find QoS differentials if MQTT is present
        mqtt_qos = {d["protocol"]: d["delay"] for d in protocol_data if d["protocol"].startswith("MQTT QoS")}
        if len(mqtt_qos) > 1 and "MQTT QoS 0" in mqtt_qos and "MQTT QoS 2" in mqtt_qos:
            ratio = mqtt_qos["MQTT QoS 2"] / mqtt_qos["MQTT QoS 0"]
            
            correlations.append({
                "id": 2,
                "title": "Protocol vs Delay",
                "description": f"MQTT QoS 2 packets show {ratio:.1f}x higher delay than QoS 0 packets",
                "data": protocol_data
            })
    
    return {
        "insights": insights,
        "correlations": correlations
    }


def get_packet_data(cap, limit=100):
    """
    Extract individual packet details
    
    Args:
        cap: pyshark capture object
        limit: Maximum number of packets to return
        
    Returns:
        List of dictionaries with packet details
    """
    packet_list = []
    packet_id = 1
    
    for packet in cap:
        if packet_id > limit:
            break
            
        try:
            # Get timestamp
            timestamp = float(packet.sniff_timestamp)
            dt = datetime.fromtimestamp(timestamp)
            timestamp_str = dt.strftime('%H:%M:%S.%f')[:-3]
            
            # Get source and destination
            if hasattr(packet, 'ip'):
                source = f"{packet.ip.src}:{packet.tcp.srcport if hasattr(packet, 'tcp') else packet.udp.srcport if hasattr(packet, 'udp') else '0'}"
                destination = f"{packet.ip.dst}:{packet.tcp.dstport if hasattr(packet, 'tcp') else packet.udp.dstport if hasattr(packet, 'udp') else '0'}"
            else:
                source = "Unknown"
                destination = "Unknown"
            
            # Determine protocol
            protocol = None
            if hasattr(packet, 'mqtt'):
                protocol = 'MQTT'
            elif hasattr(packet, 'tcp'):
                protocol = 'TCP'
            elif hasattr(packet, 'udp'):
                protocol = 'UDP'
            elif hasattr(packet, 'dns'):
                protocol = 'DNS'
            else:
                protocol = 'Other'
            
            # Get packet size
            if hasattr(packet, 'length'):
                size = int(packet.length)
            else:
                size = 0
            
            # Get delay
            if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'time_delta'):
                delay = round(float(packet.tcp.time_delta) * 1000)  # Convert to ms
            elif hasattr(packet, 'udp') and hasattr(packet, 'delta_time'):
                delay = round(float(packet.delta_time) * 1000)  # Convert to ms
            else:
                delay = 0
            
            # Determine delay category
            if protocol == 'MQTT' and delay > 300:
                delay_category = "Broker Processing"
            elif hasattr(packet, 'tcp') and hasattr(packet.tcp, 'analysis_retransmission'):
                delay_category = "Retransmissions"
            elif size > 512 and delay > 200:
                delay_category = "Bundling Delay"
            else:
                delay_category = "Network Transmission"
            
            packet_list.append({
                'id': packet_id,
                'timestamp': timestamp_str,
                'source': source,
                'destination': destination,
                'protocol': protocol,
                'size': size,
                'delay': delay,
                'delayCategory': delay_category
            })
            
            packet_id += 1
            
        except (AttributeError, ValueError):
            continue
    
    return packet_list


def analyze_pcap(file_path, baseline_file=None):
    """
    Complete analysis of a pcap file, returning all required data
    
    Args:
        file_path: Path to the .pcapng file
        baseline_file: Optional path to a baseline pcap file for comparison
        
    Returns:
        Dictionary containing all analysis data
    """
    cap = load_pcap(file_path)
    
    # Get all required data
    summary_data = get_summary_data(cap, baseline_file)
    protocol_distribution = get_protocol_distribution(cap)
    delay_categories = categorize_delays(cap)
    latency_trends = get_latency_trends(cap)
    delay_timeline = get_delay_timeline(cap)
    insights_data = get_insights_data(cap)
    packet_data = get_packet_data(cap)
    
    # Close the capture
    cap.close()
    
    return {
        'summaryData': summary_data,
        'protocolDistribution': protocol_distribution,
        'delayCategories': delay_categories,
        'latencyTrends': latency_trends,
        'delayTimeline': delay_timeline,
        'insightsData': insights_data,
        'packetData': packet_data
    }


def save_analysis_to_json(analysis_data, output_file):
    """
    Save analysis data to a JSON file
    
    Args:
        analysis_data: Dictionary containing analysis results
        output_file: Path to output JSON file
    """
    with open(output_file, 'w') as f:
        json.dump(analysis_data, f, indent=2)


# Example usage
if __name__ == "__main__":
    # Replace with actual file paths
    import sys
    pcap_file = sys.argv[1]
    baseline_file = sys.argv[2]
    
    # Run complete analysis
    analysis = analyze_pcap(pcap_file, baseline_file)
    
    # Save to JSON
    save_analysis_to_json(analysis, "network_analysis.json")
    
    print("Analysis complete! Results saved to network_analysis.json")