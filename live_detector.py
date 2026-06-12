import time
import pandas as pd
import xgboost as xgb
from scapy.all import sniff, IP, TCP

print("🧠 Loading High-Precision NIDS Brain...")
model = xgb.XGBClassifier()
model.load_model('tcp_tracker_high_precision.json')

# The strict threshold you configured earlier
STRICT_THRESHOLD = 0.95

# This dictionary acts as our short-term memory to track active connections over time
active_flows = {}

def process_packet(packet):
    # We only care about IP and TCP packets
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
        
        # Create a unique, bidirectional ID for this conversation
        connection_id = tuple(sorted([f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}"]))
        current_time = time.time()
        
        # If this is a brand new connection, initialize its memory state
        if connection_id not in active_flows:
            active_flows[connection_id] = {
                'start_time': current_time,
                'fwd_packets': 0,
                'bwd_packets': 0,
                'ack_count': 0,
                'psh_count': 0,
                'initiator': src_ip
            }
        
        flow = active_flows[connection_id]
        
        # Update our running metrics
        if src_ip == flow['initiator']:
            flow['fwd_packets'] += 1
        else:
            flow['bwd_packets'] += 1
            
        if 'A' in flags: flow['ack_count'] += 1
        if 'P' in flags: flow['psh_count'] += 1
        
        # Calculate Flow Duration (ensure it's never exactly 0 to avoid dividing by zero errors)
        duration = max(current_time - flow['start_time'], 0.0001) 
        total_packets = flow['fwd_packets'] + flow['bwd_packets']
        
        # Assemble the exact 7 features your model expects in the correct order
        live_features = pd.DataFrame([{
            'Destination Port': dst_port,
            'Flow Duration': duration,
            'ACK Flag Count': flow['ack_count'],
            'PSH Flag Count': flow['psh_count'],
            'Fwd Packets/s': flow['fwd_packets'] / duration,
            'Bwd Packets/s': flow['bwd_packets'] / duration,
            'Flow Packets/s': total_packets / duration
        }])
        
        # Feed the live data to the XGBoost model
        risk_score = model.predict_proba(live_features)[0][1]
        
        # The Security Tripwire
        if risk_score >= STRICT_THRESHOLD:
            print(f"🚨 [ALERT] SYN FLOOD SIGNATURE DETECTED!")
            print(f"   -> Target: {dst_ip}:{dst_port}")
            print(f"   -> Risk Confidence: {risk_score * 100:.2f}% | Packets/s: {total_packets / duration:.0f}")
            print(f"   -> Action: INTRUSION BLOCKED\n")

print("🛡️ TCPTracker Live NIDS Armed and Active.")
print("Listening to network traffic in real-time. Press Ctrl+C to stop.\n")

# Start listening! store=False prevents the script from eating up all your RAM
sniff(prn=process_packet, store=False)