from scapy.all import rdpcap, IP, DNS, DNSRR
import collections

def extract_iocs_from_pcap(pcap_path):
    # ... (the rest of this function is perfect and does not need to be changed)
    found_ips = set()
    found_domains = set()
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"Error: Could not read or parse the PCAP file at {pcap_path}. Reason: {e}")
        return [], []
    for packet in packets:
        try:
            if packet.haslayer(IP):
                found_ips.add(packet[IP].src)
                found_ips.add(packet[IP].dst)
            if packet.haslayer(DNS):
                if packet[DNS].qd:
                    domain = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
                    found_domains.add(domain)
                if packet[DNS].an:
                    for i in range(packet[DNS].ancount):
                        dns_record = packet[DNS].an[i]
                        if isinstance(dns_record, DNSRR) and dns_record.type == 1:
                            found_ips.add(dns_record.rdata)
        except Exception as e:
            pass
    return list(found_ips), list(found_domains)


if __name__ == '__main__':
    # --- THIS IS THE LINE TO CHANGE ---
    # Replace this placeholder with the full path you copied in step 2.
    # It will look something like "C:\\Users\\Nitesh\\Downloads\\small_set_malicous.pcap"
    pcap_file = r"C:\Users\mudra\Desktop\threat-intel-pipeline\data\malicious_logs\small_set_malicous.pcap" 
    
    ips, domains = extract_iocs_from_pcap(pcap_file)
    
    print("--- Robust Extraction Results ---")
    print(f"Found {len(ips)} unique IPv4 addresses.")
    print(f"Found {len(domains)} unique domain names.")
    
    print("\n--- Sample of IPs Found ---")
    print(ips[:10]) 

    print("\n--- Domains Found ---")
    print(domains)

    input("\nPress Enter to exit...")