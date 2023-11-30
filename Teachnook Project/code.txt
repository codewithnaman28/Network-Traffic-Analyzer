#SOURCE CODE
import logging
from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime
import traceback

logging.basicConfig(filename='network_traffic.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

connection_bytes = {} # Dictionary to store the total bytes transferred for each TCP connection
source_ip_counts = {} # Dictionary to store source IP counts
connection_id=None #declaring connection_id variable
def packet_callback(packet):
    global connection_id
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Update source IP counts
        if src_ip in source_ip_counts:
            source_ip_counts[src_ip] += 1
        else:
            source_ip_counts[src_ip] = 1

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            # Create a unique connection identifier
            connection_id = (src_ip, dst_ip, src_port, dst_port)

            # Calculate the packet length (bytes)
            packet_length = len(packet)

            # Update the total bytes transferred for this connection
            if connection_id in connection_bytes:
                connection_bytes[connection_id] += packet_length
            else:
                connection_bytes[connection_id] = packet_length

            # Check for unusually large data transfers
            threshold = 1000000  #in bytes..adjust/lower this for more false positives
            if connection_bytes[connection_id] > threshold:
                logging.info(f"Suspiciously large data transfer detected on {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({connection_bytes[connection_id]} bytes)")

            # Check for HTTP traffic by examining payload
            if dst_port == 80 or dst_port == 8080 or src_port == 80 or src_port == 8080:
                payload = packet[TCP].payload
                if "HTTP" in str(payload):
                    logging.info(f"HTTP Traffic Detected: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

            # Check for specific UDP traffic
            if dst_port == 53: #customize as per requirement
                logging.info(f"DNS Traffic Detected: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        elif packet.haslayer("ICMP"):
            protocol = "ICMP"
            src_port = "N/A"
            dst_port = "N/A"

        else:
            protocol = "Unknown"
            src_port = "N/A"
            dst_port = "N/A"

        logging.info(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}, Source Port: {src_port}, Destination Port: {dst_port}, Bytes transferred: {connection_bytes[connection_id]}")

if __name__ == "__main__":
    print("Capturing packets, Press Ctrl+C to stop.")
    try:
        print("Filters: 1.TCP 2.UDP 3.IP 4.Port")
        choice=int(input("Enter your choice: "))
        if choice==1:
            fltr="tcp"
        elif choice==2:
            fltr="udp"
        elif choice==3:
            fltr="ip"
        else:
            prt=int(input("Enter the port number: "))
            fltr=f"port {prt}"
        
        num=int(input("Enter the number of packets to capture: "))
        sniff(filter=fltr, prn=packet_callback, count=num)

    except KeyboardInterrupt:
        # Detect and print abnormal source IP addresses
        logging.info("\nAbnormal Source IP Addresses:")
        for ip, count in source_ip_counts.items():
            if count > 100:  # Customize the threshold as needed
                logging.info(f"Source IP: {ip}, Count: {count}")
        
        
    except Exception as e:
        logging.info(f"An error occurred: {str(e)}")
