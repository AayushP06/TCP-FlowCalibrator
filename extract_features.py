from scapy.all import rdpcap, TCP, IP
import csv

def extract_to_csv(pcap_path, output_csv):
    print(f"Loading {pcap_path}... (This might take a few seconds)")
    packets = rdpcap(pcap_path)
    
    with open(output_csv, mode='w', newline='') as file:
        writer = csv.writer(file)
        # 1. Define the Columns (These are your ML Features)
        writer.writerow(["Src_IP", "Dst_IP", "Src_Port", "Dst_Port", "Payload_Size", "SYN_Flag", "ACK_Flag"])

        count = 0
        # 2. Loop through every packet
        for pkt in packets:
            # We only care about TCP/IP packets for this specific model
            if IP in pkt and TCP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                payload_size = len(pkt[TCP].payload)

                # Extract the TCP Flags (This is how we spot the attack)
                flags = pkt[TCP].flags
                syn_flag = 1 if 'S' in flags else 0
                ack_flag = 1 if 'A' in flags else 0

                # Write the row to our dataset
                writer.writerow([src_ip, dst_ip, src_port, dst_port, payload_size, syn_flag, ack_flag])
                count += 1

    print(f"Extraction complete! {count} packets saved to {output_csv}")

# Run the function on your capture file
extract_to_csv("syn_flood_capture.pcap", "network_features.csv")