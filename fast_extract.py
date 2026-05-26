import dpkt
import socket
import csv

def extract_fast(pcap_path, output_csv):
    print(f"Loading {pcap_path} for high-speed extraction...")
    
    # Open the pcap file in binary read mode
    with open(pcap_path, 'rb') as f, open(output_csv, mode='w', newline='') as out:
        pcap = dpkt.pcap.Reader(f)
        writer = csv.writer(out)
        
        # Write the headers
        writer.writerow(["Src_IP", "Dst_IP", "Src_Port", "Dst_Port", "Payload_Size", "SYN_Flag", "ACK_Flag"])
        
        count = 0
        # Loop through the raw buffer
        for timestamp, buf in pcap:
            try:
                # Unpack the Ethernet frame
                eth = dpkt.ethernet.Ethernet(buf)
                
                # Ensure it's an IP packet
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                
                # Ensure it's a TCP packet
                if not isinstance(ip.data, dpkt.tcp.TCP):
                    continue
                tcp = ip.data
                
                # Convert IPs from raw bytes to standard string format (e.g., 192.168.1.1)
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
                
                # Use bitwise operators to check for SYN and ACK flags
                syn_flag = 1 if (tcp.flags & dpkt.tcp.TH_SYN) != 0 else 0
                ack_flag = 1 if (tcp.flags & dpkt.tcp.TH_ACK) != 0 else 0
                payload_size = len(tcp.data)
                
                writer.writerow([src_ip, dst_ip, tcp.sport, tcp.dport, payload_size, syn_flag, ack_flag])
                count += 1
                
                # Print progress every 500,000 packets so you know it isn't frozen
                if count % 500000 == 0:
                    print(f"Processed {count} packets...")
                    
            except Exception:
                # Skip corrupted packets silently
                continue

    print(f"Extraction complete! {count} TCP packets successfully saved to {output_csv}")

# Run the high-speed function
extract_fast("syn_flood_capture.pcap", "network_features.csv")