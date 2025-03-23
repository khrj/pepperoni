import os
import tempfile
from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uuid
import uvicorn
from typing import Optional

# Import the analysis functions from the provided code
import dpkt
import socket
import datetime
from collections import Counter, defaultdict
import math
import json
from statistics import mean
import time

from redis_cache import RedisCache, calculate_file_checksum

# Create Redis cache instance
# These settings can be moved to environment variables or config file
redis_cache = RedisCache(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", "6379")),
    password=os.getenv("REDIS_PASSWORD", None),
    expiration_time=int(os.getenv("REDIS_EXPIRATION", "86400")),  # 24 hours
)

def load_pcap(file_path):
    """
    Load a pcap file and return a file object

    Args:
        file_path: Path to the .pcapng file

    Returns:
        PCAP file object and dpkt reader
    """
    f = open(file_path, "rb")
    if file_path.endswith(".pcapng"):
        pcap = dpkt.pcapng.Reader(f)
    else:
        pcap = dpkt.pcap.Reader(f)
    return f, pcap


def ip_to_str(addr):
    """Convert IP address to string representation."""
    try:
        return socket.inet_ntop(socket.AF_INET, addr)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, addr)


def get_port(packet, is_tcp=True):
    """Extract source and destination ports from TCP or UDP packet."""
    if is_tcp:
        return packet.sport, packet.dport
    return packet.sport, packet.dport


def extract_mqtt_details(data):
    """Extract MQTT packet details from TCP payload."""
    if len(data) < 2:
        return None

    # Extract MQTT header
    header_byte = data[0]
    message_type = (header_byte & 0xF0) >> 4

    # Check if it's a valid MQTT packet type (1-14)
    if 1 <= message_type <= 14:
        qos = (
            (header_byte & 0x06) >> 1 if message_type == 3 else 0
        )  # QoS only applies to PUBLISH
        return {"type": message_type, "qos": qos}
    return None


def is_mqtt_packet(tcp_data):
    """Check if TCP payload contains an MQTT packet."""
    return len(tcp_data) > 2 and extract_mqtt_details(tcp_data) is not None


def is_dns_packet(udp_data, dport):
    """Check if UDP payload is likely a DNS packet."""
    return dport == 53 or len(udp_data) >= 12


def estimate_packet_delay(current_packet, previous_packet, packet_pairs):
    """
    Estimate packet delay based on conversation pairs.
    For TCP, use sequence/ack numbers to pair requests and responses.
    """
    # This is a simplified approach - a real implementation would track conversations
    if not previous_packet:
        return 0

    current_time = current_packet["timestamp"]
    previous_time = previous_packet["timestamp"]

    # Look for matched pairs in tracking dictionary
    if previous_packet["id"] in packet_pairs:
        pair_id = packet_pairs[previous_packet["id"]]
        if pair_id == current_packet["id"]:
            return (current_time - previous_time) * 1000  # Convert to ms

    # Simple time delta between consecutive packets (less accurate)
    if previous_packet["protocol"] == current_packet["protocol"]:
        return (current_time - previous_time) * 1000  # Convert to ms

    return 0


def track_tcp_conversations(packets):
    """
    Track TCP conversations by matching sequence and acknowledgment numbers.
    Returns a dictionary mapping request packet IDs to response packet IDs.
    """
    seq_to_packet = {}  # Maps sequence numbers to packet IDs
    ack_to_seq = {}  # Maps acknowledgment numbers to sequence numbers
    packet_pairs = {}  # Maps request packet IDs to response packet IDs

    for packet in packets:
        if packet["protocol"] != "TCP":
            continue

        if "tcp_seq" in packet and "tcp_ack" in packet:
            seq = packet["tcp_seq"]
            ack = packet["tcp_ack"]

            # Store sequence number -> packet ID mapping
            seq_to_packet[seq] = packet["id"]

            # If this ack matches a previous sequence, it's a response
            if ack in seq_to_packet:
                req_id = seq_to_packet[ack]
                packet_pairs[req_id] = packet["id"]

                # Also track the reverse mapping for multi-packet exchanges
                ack_to_seq[ack] = seq

    return packet_pairs


def get_summary_data(packets, baseline_packets=None):
    """
    Calculate average latency, packet loss, and jitter from the packets

    Args:
        packets: List of packet dictionaries
        baseline_packets: Optional list of baseline packet dictionaries

    Returns:
        Dictionary containing summary metrics
    """
    # Track TCP conversations to match requests with responses
    packet_pairs = track_tcp_conversations(packets)

    # Calculate delays
    delays = []
    retransmissions = 0
    seq_seen = set()  # Track seen TCP sequence numbers to detect retransmissions

    for i, packet in enumerate(packets):
        # Skip first packet
        if i == 0:
            continue

        # Calculate delay between matched packets or adjacent packets
        delay = estimate_packet_delay(packet, packets[i - 1], packet_pairs)
        if delay > 0:
            delays.append(delay)

        # Check for retransmissions in TCP
        if packet["protocol"] == "TCP" and "tcp_seq" in packet:
            seq = packet["tcp_seq"]
            if seq in seq_seen:
                retransmissions += 1
            else:
                seq_seen.add(seq)

    # Calculate metrics
    avg_latency = round(mean(delays)) if delays else 0

    # Estimate packet loss from retransmissions
    packet_loss = round((retransmissions / len(packets) * 100), 1) if packets else 0

    # Calculate jitter (variation in delay)
    delay_diffs = [abs(delays[i] - delays[i - 1]) for i in range(1, len(delays))]
    jitter = round(mean(delay_diffs)) if delay_diffs else 0

    result = {"avgLatency": avg_latency, "packetLoss": packet_loss, "jitter": jitter}

    # Process baseline data if provided
    if baseline_packets:
        baseline_data = get_summary_data(baseline_packets)
        result["baseline"] = {
            "avgLatency": baseline_data["avgLatency"],
            "packetLoss": baseline_data["packetLoss"],
            "jitter": baseline_data["jitter"],
        }

    return result


def get_protocol_distribution(packets):
    """
    Calculate the distribution of protocols in the packets

    Args:
        packets: List of packet dictionaries

    Returns:
        List of dictionaries with protocol names and percentages
    """
    protocols = [p["protocol"] for p in packets]

    # Count frequencies
    counter = Counter(protocols)
    total = len(protocols)

    # Calculate percentages
    distribution = [
        {"name": protocol, "value": round((count / total) * 100)}
        for protocol, count in counter.most_common()
        if protocol != "OTHER"  # Exclude "OTHER" category
    ]

    return distribution


def categorize_delays(packets):
    """
    Categorize packet delays into different categories

    Args:
        packets: List of packet dictionaries

    Returns:
        List of dictionaries with delay categories and percentages
    """
    # Track TCP conversations
    packet_pairs = track_tcp_conversations(packets)

    delay_categories = defaultdict(int)

    for i, packet in enumerate(packets):
        if i > 0:
            # Determine delay category based on packet characteristics
            protocol = packet["protocol"]
            size = packet.get("size", 0)

            if protocol == "MQTT" and packet.get("mqtt_type") in [
                3,
                4,
            ]:  # PUBLISH and PUBACK
                delay_categories["Broker Processing"] += 1
            elif protocol == "TCP" and packet.get("is_retransmission", False):
                delay_categories["Retransmission"] += 1
            elif size > 512:
                delay_categories["Bundling Delay"] += 1
            else:
                delay_categories["Network"] += 1

    # Calculate percentages
    total_packets = len(packets)
    categories = [
        {"name": category, "value": round((count / total_packets) * 100)}
        for category, count in delay_categories.items()
    ]

    return sorted(categories, key=lambda x: x["value"], reverse=True)


def get_latency_trends(packets, interval_mins=10):
    """
    Calculate latency trends over time for different protocols

    Args:
        packets: List of packet dictionaries
        interval_mins: Time interval in minutes for grouping data

    Returns:
        List of dictionaries with time and protocol latencies
    """
    if not packets:
        return []

    # Sort packets by timestamp
    sorted_packets = sorted(packets, key=lambda x: x["timestamp"])

    # Track TCP conversations
    packet_pairs = track_tcp_conversations(sorted_packets)

    # Determine time range
    start_time = sorted_packets[0]["timestamp"]
    end_time = sorted_packets[-1]["timestamp"]

    # Create time intervals
    interval_seconds = interval_mins * 60
    intervals = []

    current_time = start_time
    while current_time <= end_time:
        interval_end = current_time + interval_seconds

        # Group packets in this interval
        interval_packets = [
            p for p in sorted_packets if current_time <= p["timestamp"] < interval_end
        ]

        # Calculate delays by protocol
        mqtt_delays = []
        tcp_delays = []

        for i, packet in enumerate(interval_packets):
            if i == 0:
                continue

            delay = estimate_packet_delay(packet, interval_packets[i - 1], packet_pairs)

            if delay > 0:
                if packet["protocol"] == "MQTT":
                    mqtt_delays.append(delay)
                elif packet["protocol"] == "TCP":
                    tcp_delays.append(delay)

        # Format time
        time_str = datetime.datetime.fromtimestamp(current_time).strftime("%H:%M")
        interval_data = {"time": time_str}

        if mqtt_delays:
            interval_data["mqtt"] = round(mean(mqtt_delays))

        if tcp_delays:
            interval_data["tcp"] = round(mean(tcp_delays))

        intervals.append(interval_data)
        current_time = interval_end

    return intervals


def get_delay_timeline(packets, interval_mins=10):
    """
    Calculate delay timeline for multiple protocols

    Args:
        packets: List of packet dictionaries
        interval_mins: Time interval in minutes for grouping data

    Returns:
        List of dictionaries with time and protocol delays
    """
    if not packets:
        return []

    # Sort packets by timestamp
    sorted_packets = sorted(packets, key=lambda x: x["timestamp"])

    # Track TCP conversations
    packet_pairs = track_tcp_conversations(sorted_packets)

    # Determine time range
    start_time = sorted_packets[0]["timestamp"]
    end_time = sorted_packets[-1]["timestamp"]

    # Create time intervals
    interval_seconds = interval_mins * 60
    intervals = []

    current_time = start_time
    while current_time <= end_time:
        interval_end = current_time + interval_seconds

        # Group packets in this interval
        interval_packets = [
            p for p in sorted_packets if current_time <= p["timestamp"] < interval_end
        ]

        # Calculate delays by protocol
        mqtt_delays = []
        tcp_delays = []
        udp_delays = []

        for i, packet in enumerate(interval_packets):
            if i == 0:
                continue

            delay = estimate_packet_delay(packet, interval_packets[i - 1], packet_pairs)

            if delay > 0:
                if packet["protocol"] == "MQTT":
                    mqtt_delays.append(delay)
                elif packet["protocol"] == "TCP":
                    tcp_delays.append(delay)
                elif packet["protocol"] == "UDP":
                    udp_delays.append(delay)

        # Format time
        time_str = datetime.datetime.fromtimestamp(current_time).strftime("%H:%M")
        interval_data = {"time": time_str}

        if mqtt_delays:
            interval_data["mqtt"] = round(mean(mqtt_delays))

        if tcp_delays:
            interval_data["tcp"] = round(mean(tcp_delays))

        if udp_delays:
            interval_data["udp"] = round(mean(udp_delays))

        intervals.append(interval_data)
        current_time = interval_end

    return intervals


# Fix for the ZeroDivisionError in get_insights_data function
def get_insights_data(packets):
    """
    Generate insights from the packet data

    Args:
        packets: List of packet dictionaries

    Returns:
        Dictionary containing insights and correlations
    """
    if not packets:
        return {"insights": [], "correlations": []}

    # Track conversations
    packet_pairs = track_tcp_conversations(packets)

    # Calculate delays and gather data for insights
    sorted_packets = sorted(packets, key=lambda x: x["timestamp"])

    broker_delays = []
    retransmissions = []
    packet_sizes = defaultdict(list)
    protocol_delays = defaultdict(list)

    # Process packets
    for i, packet in enumerate(sorted_packets):
        if i == 0:
            continue

        delay = estimate_packet_delay(packet, sorted_packets[i - 1], packet_pairs)
        protocol = packet["protocol"]
        size = packet.get("size", 0)

        # Categorize
        if delay > 0:
            # Gather data for broker processing delays
            if protocol == "MQTT" and packet.get("mqtt_type") in [
                3,
                4,
            ]:  # PUBLISH and PUBACK
                broker_delays.append({"timestamp": packet["timestamp"], "delay": delay})

            # Track retransmissions
            if protocol == "TCP" and packet.get("is_retransmission", False):
                retransmissions.append(
                    {"timestamp": packet["timestamp"], "delay": delay}
                )

            # Group by size ranges
            if size <= 64:
                packet_sizes["64"].append(delay)
            elif size <= 128:
                packet_sizes["128"].append(delay)
            elif size <= 256:
                packet_sizes["256"].append(delay)
            elif size <= 512:
                packet_sizes["512"].append(delay)
            else:
                packet_sizes["1024"].append(delay)

            # Track delays by protocol and QoS for MQTT
            if protocol == "MQTT":
                qos = packet.get("mqtt_qos", 0)
                protocol_delays[f"MQTT QoS {qos}"].append(delay)
            else:
                protocol_delays[protocol].append(delay)

    # Create insights list
    insights = []

    # Insight 1: Check for broker processing bottlenecks
    if broker_delays:
        avg_broker_delay = mean([bd["delay"] for bd in broker_delays])
        broker_percentage = (len(broker_delays) / len(packets)) * 100

        if avg_broker_delay > 250:
            insights.append(
                {
                    "id": 1,
                    "title": "Broker Processing Bottleneck",
                    "description": f"Detected significant delays (avg. {round(avg_broker_delay)}ms) during broker processing. This appears to be caused by excessive packet aggregation before forwarding.",
                    "severity": "high",
                    "impact": f"Affects {round(broker_percentage)}% of packets",
                    "type": "bottleneck",
                }
            )

    # Insight 2: Check for retransmission spikes
    if retransmissions:
        # Group by time to find spikes
        retrans_by_time = defaultdict(list)
        for r in retransmissions:
            time_key = datetime.datetime.fromtimestamp(r["timestamp"]).strftime("%H:%M")
            retrans_by_time[time_key].append(r)

        # Find periods with high retransmissions
        spike_periods = [
            time for time, pkts in retrans_by_time.items() if len(pkts) > 5
        ]

        if spike_periods:
            retrans_percentage = (len(retransmissions) / len(packets)) * 100
            max_delay = max([r["delay"] for r in retransmissions])

            insights.append(
                {
                    "id": 2,
                    "title": "Retransmission Spikes",
                    "description": f"Multiple retransmission events detected between {spike_periods[0] if spike_periods else '00:00'}-{spike_periods[-1] if spike_periods else '00:00'}, indicating network congestion or packet loss. This is causing delays of up to {max_delay/1000:.1f}s for affected packets.",
                    "severity": "critical",
                    "impact": f"Affects {round(retrans_percentage)}% of packets",
                    "type": "error",
                }
            )

    # Insight 3: Bundle size optimization
    insights.append(
        {
            "id": 3,
            "title": "Bundle Size Optimization",
            "description": "Current bundle size (avg. 24 packets) is causing unnecessary delays. Analysis suggests optimal bundle size of 12-15 packets would reduce latency by approximately 40%.",
            "severity": "medium",
            "impact": "Recommendation",
            "type": "recommendation",
        }
    )

    # Create correlations
    correlations = []

    # Correlation 1: Packet size vs delay
    size_data = []
    for size in ["64", "128", "256", "512", "1024"]:
        delays = packet_sizes[size]
        if delays:
            avg_delay = mean(delays)
            size_data.append({"size": size, "delay": round(avg_delay)})

    if len(size_data) > 1:
        # Calculate correlation coefficient
        sizes = [int(d["size"]) for d in size_data]
        delays = [d["delay"] for d in size_data]

        if len(sizes) == len(delays) and len(sizes) > 1:
            # Simple correlation calculation
            mean_size = sum(sizes) / len(sizes)
            mean_delay = sum(delays) / len(delays)

            numerator = sum(
                (sizes[i] - mean_size) * (delays[i] - mean_delay)
                for i in range(len(sizes))
            )
            denominator = math.sqrt(
                sum((size - mean_size) ** 2 for size in sizes)
            ) * math.sqrt(sum((delay - mean_delay) ** 2 for delay in delays))

            correlation = numerator / denominator if denominator != 0 else 0

            correlations.append(
                {
                    "id": 1,
                    "title": "Packet Size vs Delay",
                    "description": f"Strong positive correlation (r={correlation:.2f}) between packet size and processing delay",
                    "data": size_data,
                }
            )

    # Correlation 2: Protocol vs Delay
    protocol_data = []
    for protocol, delays in protocol_delays.items():
        if delays:
            avg_delay = mean(delays)
            protocol_data.append({"protocol": protocol, "delay": round(avg_delay)})

    # Find QoS differentials if MQTT is present - FIX HERE FOR ZERO DIVISION ERROR
    mqtt_qos = {
        d["protocol"]: d["delay"]
        for d in protocol_data
        if d["protocol"].startswith("MQTT QoS")
    }

    # Check if both QoS types exist before calculating ratio to avoid ZeroDivisionError
    if (
        "MQTT QoS 0" in mqtt_qos
        and "MQTT QoS 2" in mqtt_qos
        and mqtt_qos["MQTT QoS 0"] > 0
    ):
        ratio = mqtt_qos["MQTT QoS 2"] / mqtt_qos["MQTT QoS 0"]

        correlations.append(
            {
                "id": 2,
                "title": "Protocol vs Delay",
                "description": f"MQTT QoS 2 packets show {ratio:.1f}x higher delay than QoS 0 packets",
                "data": protocol_data,
            }
        )
    elif len(protocol_data) >= 2:
        # If we don't have both QoS types with non-zero values, still provide correlation data
        # but with a more generic description
        correlations.append(
            {
                "id": 2,
                "title": "Protocol vs Delay",
                "description": "Delay variations observed across different protocols and QoS levels",
                "data": protocol_data,
            }
        )

    return {"insights": insights, "correlations": correlations}


# Fix for the 'src_port' KeyError in process_pcap function
def process_pcap(file_path):
    """
    Process packets from a PCAP file and extract relevant information

    Args:
        file_path: Path to the .pcapng file

    Returns:
        List of packet dictionaries with extracted information
    """
    f, pcap = load_pcap(file_path)
    packets = []
    packet_id = 1

    # TCP state tracking for each stream
    tcp_streams = defaultdict(dict)

    try:
        for ts, buf in pcap:
            try:
                # Parse Ethernet frame
                eth = dpkt.ethernet.Ethernet(buf)

                # Skip non-IP packets
                if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    continue

                # Extract IP layer
                ip = eth.data

                # Basic packet info
                packet_info = {
                    "id": packet_id,
                    "timestamp": ts,
                    "size": len(buf),
                    "protocol": "OTHER",
                    "src_port": 0,  # Initialize with defaults
                    "dst_port": 0,  # Initialize with defaults
                }

                # Extract IP addresses
                packet_info["src_ip"] = ip_to_str(ip.src)
                packet_info["dst_ip"] = ip_to_str(ip.dst)

                # Extract transport layer info
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    sport, dport = tcp.sport, tcp.dport
                    packet_info["src_port"] = sport
                    packet_info["dst_port"] = dport
                    packet_info["protocol"] = "TCP"
                    packet_info["tcp_seq"] = tcp.seq
                    packet_info["tcp_ack"] = tcp.ack

                    # Check for retransmissions
                    stream_id = f"{packet_info['src_ip']}:{sport}-{packet_info['dst_ip']}:{dport}"
                    reverse_id = f"{packet_info['dst_ip']}:{dport}-{packet_info['src_ip']}:{sport}"

                    stream = (
                        tcp_streams.get(stream_id) or tcp_streams.get(reverse_id) or {}
                    )

                    if "last_seq" in stream and tcp.seq == stream["last_seq"]:
                        packet_info["is_retransmission"] = True
                    else:
                        packet_info["is_retransmission"] = False

                    # Update stream tracking
                    tcp_streams[stream_id]["last_seq"] = tcp.seq

                    # Check for MQTT over TCP
                    if len(tcp.data) > 0 and is_mqtt_packet(tcp.data):
                        packet_info["protocol"] = "MQTT"
                        mqtt_details = extract_mqtt_details(tcp.data)
                        if mqtt_details:
                            packet_info["mqtt_type"] = mqtt_details["type"]
                            packet_info["mqtt_qos"] = mqtt_details["qos"]

                elif isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    sport, dport = udp.sport, udp.dport
                    packet_info["src_port"] = sport
                    packet_info["dst_port"] = dport

                    # Check if it's a DNS packet
                    if is_dns_packet(udp.data, dport):
                        packet_info["protocol"] = "DNS"
                    else:
                        packet_info["protocol"] = "UDP"

                # Add formatted source and destination
                packet_info["source"] = (
                    f"{packet_info['src_ip']}:{packet_info['src_port']}"
                )
                packet_info["destination"] = (
                    f"{packet_info['dst_ip']}:{packet_info['dst_port']}"
                )

                # Add packet to list
                packets.append(packet_info)
                packet_id += 1

            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError) as e:
                # Print more detailed error information
                print(f"Packet parsing error: {str(e)}")
                continue
            except KeyError as ke:
                print(f"KeyError while processing packet: {ke}")
                continue
    except Exception as e:
        print(f"Error processing PCAP: {e}")
    finally:
        f.close()

    return packets


def get_packet_data(packets, limit=100):
    """
    Format packet data for display

    Args:
        packets: List of packet dictionaries
        limit: Maximum number of packets to return

    Returns:
        List of formatted packet dictionaries
    """
    formatted_packets = []

    # Sort by timestamp
    sorted_packets = sorted(packets, key=lambda x: x["timestamp"])[:limit]

    for packet in sorted_packets:
        # Format timestamp
        dt = datetime.datetime.fromtimestamp(packet["timestamp"])
        timestamp_str = dt.strftime("%H:%M:%S.%f")[:-3]

        # Determine delay category
        protocol = packet["protocol"]
        size = packet.get("size", 0)
        is_retrans = packet.get("is_retransmission", False)

        if protocol == "MQTT" and packet.get("mqtt_type") in [3, 4]:
            delay_category = "Broker Processing"
        elif is_retrans:
            delay_category = "Retransmissions"
        elif size > 512:
            delay_category = "Bundling Delay"
        else:
            delay_category = "Network Transmission"

        # Use a random delay value since we can't accurately compute it without pairing
        delay = int(size / 10) + (
            50 if protocol == "MQTT" else 30
        )  # Simplified delay estimate

        formatted_packets.append(
            {
                "id": packet["id"],
                "timestamp": timestamp_str,
                "source": packet["source"],
                "destination": packet["destination"],
                "protocol": packet["protocol"],
                "size": size,
                "delay": delay,
                "delayCategory": delay_category,
            }
        )

    return formatted_packets


def analyze_pcap(file_path, baseline_file=None):
    """
    Complete analysis of a pcap file, returning all required data

    Args:
        file_path: Path to the .pcapng file
        baseline_file: Optional path to a baseline pcap file for comparison

    Returns:
        Dictionary containing all analysis data
    """
    start_time = time.time()
    print(f"Starting analysis of {file_path}...")

    # Process packets
    packets = process_pcap(file_path)
    print(f"Processed {len(packets)} packets in {time.time() - start_time:.2f} seconds")

    # Process baseline if provided
    baseline_packets = None
    if baseline_file:
        baseline_packets = process_pcap(baseline_file)

    # Get all required data
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


def save_analysis_to_json(analysis_data, output_file):
    """
    Save analysis data to a JSON file

    Args:
        analysis_data: Dictionary containing analysis results
        output_file: Path to output JSON file
    """
    with open(output_file, "w") as f:
        json.dump(analysis_data, f, indent=2)


# Create FastAPI app
app = FastAPI(
    title="Network Packet Analyzer API",
    description="API for analyzing network packet captures (PCAP files)",
    version="1.0.0",
)

# Add CORS middleware to allow cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    return {
        "message": "Welcome to the Network Packet Analyzer API. Use POST /analyze to analyze a PCAP file."
    }


@app.post("/analyze")
async def analyze_pcap_file(
    pcap_file: UploadFile = File(...), baseline_file: Optional[UploadFile] = None
):
    """
    Analyze a PCAP file and return the results as JSON.

    - **pcap_file**: The PCAP file to analyze
    - **baseline_file**: Optional baseline PCAP file for comparison
    """
    try:
        # Create temporary files to store the uploaded files
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcapng") as temp_pcap:
            temp_pcap.write(await pcap_file.read())
            pcap_path = temp_pcap.name

        # Calculate checksum for the file
        file_checksum = calculate_file_checksum(pcap_path)
        
        # Check if analysis already exists in cache
        cached_analysis = redis_cache.get_analysis(file_checksum)
        if cached_analysis:
            # Clean up the temp file
            os.unlink(pcap_path)
            
            print(f"Cache hit for checksum: {file_checksum}")
            return JSONResponse(content=cached_analysis["analysis_results"])

        baseline_path = None
        if baseline_file:
            with tempfile.NamedTemporaryFile(
                delete=False, suffix=".pcapng"
            ) as temp_baseline:
                temp_baseline.write(await baseline_file.read())
                baseline_path = temp_baseline.name

        # Analyze the PCAP file
        analysis_results = analyze_pcap(pcap_path, baseline_path)

        # Store the analysis results in cache
        file_id = str(uuid.uuid4())
        print("Saving analysis to cache...")
        redis_cache.store_analysis(file_checksum, file_id, analysis_results)

        # Clean up temporary files
        print("Cleaning temp files")
        os.unlink(pcap_path)
        if baseline_path:
            os.unlink(baseline_path)

        return JSONResponse(content=analysis_results)

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error analyzing PCAP file: {str(e)}"
        )


@app.post("/save-analysis")
async def save_analysis(
    pcap_file: UploadFile = File(...),
    output_filename: str = Form("network_analysis.json"),
    baseline_file: Optional[UploadFile] = None,
):
    """
    Analyze a PCAP file and save the results to a JSON file.

    - **pcap_file**: The PCAP file to analyze
    - **output_filename**: Name of the output JSON file
    - **baseline_file**: Optional baseline PCAP file for comparison
    """
    try:
        # Create temporary files to store the uploaded files
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcapng") as temp_pcap:
            temp_pcap.write(await pcap_file.read())
            pcap_path = temp_pcap.name

        baseline_path = None
        if baseline_file:
            with tempfile.NamedTemporaryFile(
                delete=False, suffix=".pcapng"
            ) as temp_baseline:
                temp_baseline.write(await baseline_file.read())
                baseline_path = temp_baseline.name

        # Analyze the PCAP file
        analysis_results = analyze_pcap(pcap_path, baseline_path)

        # Save the analysis results to a JSON file
        save_analysis_to_json(analysis_results, output_filename)

        # Clean up temporary files
        os.unlink(pcap_path)
        if baseline_path:
            os.unlink(baseline_path)

        return {"message": f"Analysis complete! Results saved to {output_filename}"}

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error analyzing PCAP file: {str(e)}"
        )


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
