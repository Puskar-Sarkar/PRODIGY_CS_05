from scapy.all import sniff

def packet_callback(packet):
    
    print(f"Packet: {packet.summary()}")

    if packet.haslayer('IP'):
        ip_layer = packet['IP']
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

        if packet.haslayer('Raw'):
            payload = packet['Raw'].load
            print(f"Payload: {payload}")

    print("\n")

if __name__ == "__main__":
    print("Starting packet sniffer...")
    sniff(prn=packet_callback, store=0)