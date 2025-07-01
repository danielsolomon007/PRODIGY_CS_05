from scapy.all import sniff, IP, TCP, UDP, Raw

def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src

        dst_ip = packet[IP].dst

        protocol = packet[IP].proto

        print(f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {protocol}")

        # Check if TCP or UDP and    # to Print the payload
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            if Raw in packet:
               payload_data = packet[Raw].load
               try:
                    
                    decoded = payload_data.decode(errors='ignore')
                    print( f"Payload:\n{decoded}" )

               except Exception as e:
                 print("Could not decode payload:", e )

def main():

  # Start sniffing not store packets :)
    sniff( prn = process_packet , store=False )

    
if __name__ == "__main__":
   
   main( )
   