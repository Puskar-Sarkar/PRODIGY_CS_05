from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, Raw

import logging

logging.basicConfig(filename='packet_sniffer.log', 
                    level=logging.INFO, format='%(asctime)s - %(message)s')

def packet_callback(packet):

    try:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        payload = bytes(packet.payload)

        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}") 
        print(f"Protocol: {protocol}, Payload: {payload}")

        logging.info(f"Source IP: {src_ip}, Destination IP: {dst_ip}")
        logging.info(f"Protocol: {protocol}, Payload: {payload}")       

    except Exception as e:
        print(f"Error processing packet: {e}")
def main():

    print("Starting packet sniffer... Press Ctrl+C to stop.")
    try:
        packets = sniff(prn=packet_callback, count=0) 
    except KeyboardInterrupt:
        print("Packet sniffing stopped.")
    except Exception as e:
        print(f"An error occurred: {e}")

    wrpcap('captured_packets.pcap', packets)
    print("Captured packets saved to 'captured_packets.pcap'.")

if __name__ == "__main__":
    main()