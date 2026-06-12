import dpkt
import socket
import csv

def process_pcap(pcap_file, output_csv, label):
    print(f"Processing {pcap_file}...")
    
    # State tracking dictionary for O(1) lookups
    ip_last_seen = {} 

    with open(pcap_file, 'rb') as f, open(output_csv, mode='w', newline='') as out:
        pcap = dpkt.pcap.Reader(f)
        writer = csv.writer(out)
        
        # Notice the new columns: Time_Since_Last_Packet and Label
        writer.writerow(["Src_IP", "Dst_IP", "Src_Port", "Dst_Port", "Payload_Size", "SYN_Flag", "ACK_Flag", "Time_Since_Last_Packet", "Label"])
        
        count = 0
        for ts, buf in pcap: # ts is the actual Unix timestamp of the packet
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP): continue
                ip = eth.data
                if not isinstance(ip.data, dpkt.tcp.TCP): continue
                tcp = ip.data
                
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
                
                # --- FEATURE ENGINEERING: Time Delta ---
                if src_ip in ip_last_seen:
                    time_delta = ts - ip_last_seen[src_ip]
                else:
                    time_delta = 0.0 # First time seeing this IP
                
                # Update the state tracker with the new timestamp
                ip_last_seen[src_ip] = ts
                
                syn_flag = 1 if (tcp.flags & dpkt.tcp.TH_SYN) != 0 else 0
                ack_flag = 1 if (tcp.flags & dpkt.tcp.TH_ACK) != 0 else 0
                payload_size = len(tcp.data)
                
                writer.writerow([src_ip, dst_ip, tcp.sport, tcp.dport, payload_size, syn_flag, ack_flag, time_delta, label])
                count += 1
                
                if count % 500000 == 0:
                    print(f"Processed {count} packets...")
                    
            except Exception:
                continue
                
    print(f"Extraction complete! {count} packets saved to {output_csv}\n")

# Run the function on BOTH of your files. 
# 0 = Benign (Normal Traffic), 1 = Malicious (Attack Traffic)
process_pcap("benign_capture.pcap", "benign_features.csv", label=0)
process_pcap("syn_flood_capture.pcap", "attack_features.csv", label=1)