import bisect
from collections import defaultdict

def analyze_packets(packets):
    # Identify Broker and Cloud IPs
    def identify_broker_and_cloud(packets):
        dest_counts = defaultdict(int)
        for p in packets:
            dest_counts[p['destination']] += 1
        broker_ip = max(dest_counts, key=dest_counts.get, default=None)
        
        cloud_dests = defaultdict(int)
        for p in packets:
            if p['source'] == broker_ip:
                cloud_dests[p['destination']] += 1
        cloud_ip = max(cloud_dests, key=cloud_dests.get, default=None) if cloud_dests else None
        return broker_ip, cloud_ip

    broker_ip, cloud_ip = identify_broker_and_cloud(packets)
    
    # Compute RTT for TCP packets (Device to Broker)
    sent_packets = defaultdict(list)
    ack_packets = []
    for p in packets:
        if p['protocol'] == 'TCP' and p['destination'] == broker_ip and p['size'] > 0:
            flow_key = (p['source'], p['src_port'], p['destination'], p['dst_port'])
            sent_packets[flow_key].append({'id': p['id'], 'seq': p['tcp_seq'], 'timestamp': p['timestamp'], 'length': p['size']})
        elif p['protocol'] == 'TCP' and p['source'] == broker_ip and p['size'] == 0:
            ack_packets.append(p)
    
    rtt_dict = {}
    for ack_p in ack_packets:
        flow_key = (ack_p['destination'], ack_p['dst_port'], ack_p['source'], ack_p['src_port'])
        if flow_key not in sent_packets:
            continue
        ack_num = ack_p['tcp_ack']
        for sent in sent_packets[flow_key]:
            if sent['seq'] + sent['length'] <= ack_num:
                rtt = ack_p['timestamp'] - sent['timestamp']
                if sent['id'] not in rtt_dict or rtt < rtt_dict[sent['id']]:
                    rtt_dict[sent['id']] = rtt

    # Compute Inter-Packet Times for Device-to-Broker
    device_intervals = defaultdict(list)
    device_timestamps = defaultdict(list)
    for p in packets:
        if p['destination'] == broker_ip:
            device = p['source']
            device_timestamps[device].append(p['timestamp'])
    
    inter_thresholds = {}
    for device, timestamps in device_timestamps.items():
        sorted_ts = sorted(timestamps)
        intervals = [sorted_ts[i] - sorted_ts[i-1] for i in range(1, len(sorted_ts))]
        if intervals:
            mean = sum(intervals) / len(intervals)
            std = (sum((x - mean)**2 for x in intervals) / len(intervals))**0.5
            inter_thresholds[device] = mean + 2 * std

    # Compute Broker Processing Time
    broker_received = sorted([p['timestamp'] for p in packets if p['destination'] == broker_ip])
    broker_sent_to_cloud = [p for p in packets if p['source'] == broker_ip and cloud_ip and p['destination'] == cloud_ip]
    processing_times = []
    for sent_p in broker_sent_to_cloud:
        idx = bisect.bisect_left(broker_received, sent_p['timestamp']) - 1
        if idx >= 0:
            processing_time = sent_p['timestamp'] - broker_received[idx]
            processing_times.append(processing_time)
    proc_threshold = (sum(processing_times)/len(processing_times) + 2 * (sum((t - sum(processing_times)/len(processing_times))**2 for t in processing_times)/len(processing_times))**0.5) if processing_times else 0

    # Compute Cloud Upload RTT
    cloud_rtt = {}
    cloud_sent = [p for p in packets if p['source'] == broker_ip and p['destination'] == cloud_ip and p['protocol'] == 'TCP' and p['size'] > 0]
    cloud_acks = [p for p in packets if p['destination'] == broker_ip and p['source'] == cloud_ip and p['protocol'] == 'TCP' and p['size'] == 0]
    for ack_p in cloud_acks:
        for sent_p in cloud_sent:
            if sent_p['tcp_seq'] + sent_p['size'] <= ack_p['tcp_ack']:
                rtt = ack_p['timestamp'] - sent_p['timestamp']
                cloud_rtt[sent_p['id']] = rtt
                break
    cloud_rtt_values = list(cloud_rtt.values())
    cloud_threshold = (sum(cloud_rtt_values)/len(cloud_rtt_values) + 2 * (sum((t - sum(cloud_rtt_values)/len(cloud_rtt_values))**2 for t in cloud_rtt_values)/len(cloud_rtt_values))**0.5) if cloud_rtt_values else 0

    results = []
    for p in packets:
        delay = 0
        delay_category = None
        is_delay = False
        
        if p['is_retransmission']:
            delay_category = 'Retransmissions'
            is_delay = True
            delay = rtt_dict.get(p['id'], 0)
        else:
            if p['id'] in rtt_dict:
                delay = rtt_dict[p['id']]
                protocol_rtt = [rtt for pid, rtt in rtt_dict.items() if packets[pid-1]['protocol'] == p['protocol']]
                if protocol_rtt:
                    mean = sum(protocol_rtt) / len(protocol_rtt)
                    std = (sum((x - mean)**2 for x in protocol_rtt) / len(protocol_rtt))**0.5
                    if delay > mean + 2 * std:
                        is_delay = True
            
            if is_delay:
                if p['destination'] == broker_ip:
                    device = p['source']
                    timestamps = device_timestamps.get(device, [])
                    if timestamps:
                        idx = bisect.bisect_left(sorted(timestamps), p['timestamp'])
                        if idx > 0:
                            inter_time = p['timestamp'] - sorted(timestamps)[idx-1]
                            if inter_time > inter_thresholds.get(device, 0):
                                delay_category = 'Device-to-Broker'
                if not delay_category and p['source'] == broker_ip and p['destination'] == cloud_ip:
                    if cloud_rtt.get(p['id'], 0) > cloud_threshold:
                        delay_category = 'Cloud Upload'
                if not delay_category and p['source'] == broker_ip and p['destination'] == cloud_ip:
                    idx = bisect.bisect_left(broker_received, p['timestamp']) - 1
                    if idx >= 0:
                        proc_time = p['timestamp'] - broker_received[idx]
                        if proc_time > proc_threshold:
                            delay_category = 'Broker Processing'
        
        results.append({
            "id": p["id"],
            "timestamp": str(p["timestamp"]),
            "source": p["source"],
            "destination": p["destination"],
            "protocol": p["protocol"],
            "size": p["size"],
            "delay": round(delay),
            "delayCategory": delay_category,
            "isDelay": is_delay
        })
    
    return results
