import os
import tempfile
from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uuid
from pydantic import BaseModel, Field
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

# Configure Gemini
from openai import OpenAI

client = OpenAI(
    api_key="AIzaSyBH1e_YkXGL-sngYqpHSpvV1PQw-YJltOk",
    base_url="https://generativelanguage.googleapis.com/v1beta/openai/"
)

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

    result = {
        "avgLatency": avg_latency,
        "packetLoss": packet_loss,
        "jitter": jitter,
        "numPackets": len(packets),
    }

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


def get_latency_trends(packets, interval_secs=10):
    """
    Calculate latency trends over time for different protocols

    Args:
        packets: List of packet dictionaries
        interval_secs: Time interval in seconds for grouping data

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
    intervals = []

    current_time = start_time
    while current_time <= end_time:
        interval_end = current_time + interval_secs

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
        time_str = datetime.datetime.fromtimestamp(current_time).strftime("%H:%M:%S")
        interval_data = {"time": time_str}

        if mqtt_delays:
            interval_data["mqtt"] = round(mean(mqtt_delays))

        if tcp_delays:
            interval_data["tcp"] = round(mean(tcp_delays))

        intervals.append(interval_data)
        current_time = interval_end

    return intervals


def get_delay_timeline(packets, interval_secs=10):
    """
    Calculate delay timeline for multiple protocols

    Args:
        packets: List of packet dictionaries
        interval_secs: Time interval in seconds for grouping data

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
    intervals = []

    current_time = start_time
    while current_time <= end_time:
        interval_end = current_time + interval_secs

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
        time_str = datetime.datetime.fromtimestamp(current_time).strftime("%H:%M:%S")
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


def get_insights_data(packets):
    """
    Generate LLM-powered insights from raw packet data using Gemini
    
    Args:
        packets: List of packet dictionaries
        
    Returns:
        Dictionary containing insights and correlations
    """
    if not packets:
        return {"insights": [], "correlations": []}

    from datetime import datetime
    import dpkt
    
    def simplify_packets_for_llm(packets, max_packets=1500):
        """
        Create a condensed version of packet data suitable for LLM analysis
        
        Args:
            packets: List of packets from process_pcap
            max_packets: Maximum number of packets to include (for context limits)
            
        Returns:
            List of simplified packet dictionaries
        """
        simplified = []

        for pkt in packets[:max_packets]:
            # Base information
            simplified_pkt = {
                "timestamp": datetime.fromtimestamp(pkt["timestamp"]).strftime('%Y-%m-%d %H:%M:%S'),
                "protocol": pkt["protocol"],
                "size": pkt["size"],
                "source": f"{pkt['src_ip']}:{pkt.get('src_port', 0)}",
                "destination": f"{pkt['dst_ip']}:{pkt.get('dst_port', 0)}"
            }

            # Protocol-specific additions
            if pkt["protocol"] == "TCP":
                simplified_pkt.update({
                    "flags": {
                        "retransmission": pkt.get("is_retransmission", False),
                    }
                })

            if pkt["protocol"] == "MQTT":
                simplified_pkt.update({
                    "mqtt": {
                        "type": pkt.get("mqtt_type", 0),
                        "qos": pkt.get("mqtt_qos", 0)
                    }
                })

            # Remove unnecessary fields
            simplified_pkt.pop("raw_payload", None)

            simplified.append(simplified_pkt)

        return simplified
        
    packets = simplify_packets_for_llm(packets)
        
    FRONTEND = """<div>
				<h2 className="text-xl font-bold mb-4">Root Cause Analysis</h2>
				<div className="grid gap-4 md:grid-cols-2">
					{insightsData.correlations.map(correlation => (
						<Card key={correlation.id}>
							<CardHeader>
								<CardTitle>{correlation.title}</CardTitle>
								<CardDescription>{correlation.description}</CardDescription>
							</CardHeader>
							<CardContent>
								<ResponsiveContainer width="100%" height={300}>
									<BarChart
										data={correlation.data}
										margin={{
											top: 5,
											right: 30,
											left: 20,
											bottom: 5,
										}}
									>
										<CartesianGrid strokeDasharray="3 3" />
										<XAxis dataKey={correlation.id === 1 ? "size" : "protocol"} />
										<YAxis
											label={{
												value: "Delay (ms)",
												angle: -90,
												position: "insideLeft",
											}}
										/>
										<Tooltip />
										<Bar dataKey="count" fill="#f4735b" />
									</BarChart>
								</ResponsiveContainer>
							</CardContent>
						</Card>
					))}
				</div>
			</div>"""

    # Construct the LLM prompt
    # print(packets)
    prompt = f"""Analyze these network packets and generate network insights in exactly this JSON format:
{json.dumps(packets, indent=2)}

Output Requirements:
1. insights (max 3 items) with:
- id: sequential number
- title: short problem title
- description: concise explanation with specific metrics
- severity: low/medium/high/critical
- impact: percentage or qualitative
- type: bottleneck/error/recommendation

2. correlations (max 2 items) with:
- id: sequential number
- title: correlation title  
- description: statistical relationship
- data: supporting metrics

Look for:
- Major issues and bottlenecks in the network
- Broker delays (MQTT PUBLISH/PUBACK timing)
- Retransmission patterns
- Packet size vs timing correlations
- Protocol/QoS performance differences
- Network congestion patterns
- The data provided by the correlations should be compatible with the frontend as shown below:
    {FRONTEND}

Example insight: {{
  "id": 1,
  "title": "Broker Processing Bottleneck",
  "description": "Average 250ms delay observed between MQTT PUBLISH (type 3) and PUBACK (type 4) packets",
  "severity": "high",
  "impact": "Affects 15% of packets",
  "type": "bottleneck"
}}

Example correlation: {{
    "id": 1,
    "title": "Packet Size and Retransmission",
    "description": "The retransmission primarily affects packets with size 74, highlighting an issue with smaller packets being dropped.",
    "data": [
        {{
            "size": "74",
            "count": 104
        }},
        {{
            "size": "96",
            "count": 6
        }},
        {{
            "size": "102",
            "count": 8
        }}
    ]
}}

Return ONLY valid JSON with double quotes. No markdown formatting:"""
    # print("Length of prompt: ", len(prompt))

    try:
        # Get Gemini response
        response = client.chat.completions.create(
            model="gemini-2.0-flash",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )

        response = response.choices[0].message.content
        cleaned = response.strip().replace('```json', '').replace('```', '')

        # Parse and validate
        result = json.loads(cleaned)

        # Convert data values to numeric if needed
        for corr in result.get('correlations', []):
            if isinstance(corr['data'], dict):
                for k, v in corr['data'].items():
                    if isinstance(v, str) and 'ms' in v:
                        corr['data'][k] = float(v.replace('ms', '').strip())

        return {
            "insights": result.get("insights", [])[:3],
            "correlations": result.get("correlations", [])[:2]
        }

    except Exception as e:
        print(f"LLM analysis failed: {str(e)}")
        return {"insights": [], "correlations": []}

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
                    "raw_payload": buf.hex(),  # Store the raw payload as hex
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

        raw_payload = packet.get("raw_payload", "")

        formatted_payload = ""
        if raw_payload:
            for i in range(0, len(raw_payload), 32):
                chunk = raw_payload[i : i + 32]
                offset = f"0x{i//2:08x}"  # Display offset in bytes
                formatted_payload += f"{offset}  {' '.join(chunk[j:j+2] for j in range(0, len(chunk), 2))}\n"

        formatted_packets.append(
            {
                "id": packet["id"],
                "timestamp": timestamp_str,
                "source": packet["source"],
                "destination": packet["destination"],
                "protocol": packet["protocol"],
                "size": size,
                "delay": round(delay),
                "delayCategory": delay_category,
                "hexPayload": raw_payload,  # Include the raw hex payload
                "formattedPayload": formatted_payload,  # Include formatted payload for display
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
        "all_packets": packets
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
        analysis_results["file_id"] = file_id
        print("Saving analysis to cache...")
        redis_cache.store_analysis(file_checksum, file_id, analysis_results)


        # Remove the 'all_packets' key from the response
        analysis_results.pop("all_packets")

        # Clean up temporary files
        print("Cleaning temp files")
        os.unlink(pcap_path)
        if baseline_path:
            os.unlink(baseline_path)

        save_analysis_to_json(analysis_results, "analysis_results.json")
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


class PacketItem(BaseModel):
    file_id: str
    num_packets: int
    start_index: int


@app.post("/get_packets")
async def get_packets(
    file_id: Optional[str] = None, num_packets: int = 100, start_index: int = 0
):
    # Check if analysis already exists in cache
    print("File id", file_id)
    if file_id is None:
        return {"message": "file_id required"}
    cached_analysis = redis_cache.get_analysis_file_id(file_id)
    if cached_analysis:
        packets = cached_analysis["analysis_results"]["all_packets"]
        return packets[start_index : start_index + num_packets]
    else:
        return {"message": "Analysis not found in cache"}


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
    
    # Testing LLM
    # packets = process_pcap("sample2.pcapng")
    # insights_data = get_insights_data(packets)
    
    # print(insights_data)
