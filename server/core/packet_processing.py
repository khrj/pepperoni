import dpkt
import socket
import datetime
from collections import defaultdict
from .utils import (
    ip_to_str,
    get_port,
    extract_mqtt_details,
    is_mqtt_packet,
    is_dns_packet,
    track_tcp_conversations
)

def process_pcap(file_path):
    f, pcap = load_pcap(file_path)
    packets = []
    packet_id = 1
    tcp_streams = defaultdict(dict)

    try:
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    continue

                ip = eth.data
                packet_info = {
                    "id": packet_id,
                    "timestamp": ts,
                    "size": len(buf),
                    "protocol": "OTHER",
                    "src_port": 0,
                    "dst_port": 0,
                }

                packet_info["src_ip"] = ip_to_str(ip.src)
                packet_info["dst_ip"] = ip_to_str(ip.dst)

                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    sport, dport = get_port(tcp)
                    packet_info.update({
                        "src_port": sport,
                        "dst_port": dport,
                        "protocol": "TCP",
                        "tcp_seq": tcp.seq,
                        "tcp_ack": tcp.ack
                    })

                    stream_id = f"{packet_info['src_ip']}:{sport}-{packet_info['dst_ip']}:{dport}"
                    reverse_id = f"{packet_info['dst_ip']}:{dport}-{packet_info['src_ip']}:{sport}"

                    stream = tcp_streams.get(stream_id) or tcp_streams.get(reverse_id) or {}
                    packet_info["is_retransmission"] = "last_seq" in stream and tcp.seq == stream["last_seq"]
                    tcp_streams[stream_id]["last_seq"] = tcp.seq

                    if len(tcp.data) > 0 and is_mqtt_packet(tcp.data):
                        packet_info["protocol"] = "MQTT"
                        mqtt_details = extract_mqtt_details(tcp.data)
                        if mqtt_details:
                            packet_info["mqtt_type"] = mqtt_details["type"]
                            packet_info["mqtt_qos"] = mqtt_details["qos"]

                elif isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    sport, dport = get_port(udp, is_tcp=False)
                    packet_info.update({
                        "src_port": sport,
                        "dst_port": dport,
                        "protocol": "DNS" if is_dns_packet(udp.data, dport) else "UDP"
                    })

                packet_info["source"] = f"{packet_info['src_ip']}:{packet_info['src_port']}"
                packet_info["destination"] = f"{packet_info['dst_ip']}:{packet_info['dst_port']}"
                packets.append(packet_info)
                packet_id += 1

            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, KeyError) as e:
                print(f"Error processing packet: {e}")
                continue
    except Exception as e:
        print(f"Error processing PCAP: {e}")
    finally:
        f.close()

    return packets

def load_pcap(file_path):
    f = open(file_path, "rb")
    if file_path.endswith(".pcapng"):
        pcap = dpkt.pcapng.Reader(f)
    else:
        pcap = dpkt.pcap.Reader(f)
    return f, pcap