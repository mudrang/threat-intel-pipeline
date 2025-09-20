from scapy.all import rdpcap, IP, DNS, DNSRR

def parse_pcap_data(pcap_path):
    """
    Robustly parses a PCAP file to extract all unique IPv4 addresses and domain names.
    Handles mixed traffic and malformed packets.
    """
    found_ips = set()
    found_domains = set()
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"Error reading PCAP file: {e}")
        return [], []

    for packet in packets:
        try:
            if packet.haslayer(IP):
                found_ips.add(packet[IP].src)
                found_ips.add(packet[IP].dst)
            if packet.haslayer(DNS):
                if packet[DNS].qd and isinstance(packet[DNS].qd.qname, bytes):
                    domain = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
                    found_domains.add(domain)
                if packet[DNS].an:
                    for i in range(packet[DNS].ancount):
                        dns_record = packet[DNS].an[i]
                        if isinstance(dns_record, DNSRR) and dns_record.type == 1:
                            found_ips.add(dns_record.rdata)
        except Exception:
            pass # Ignore packets that can't be parsed
    return list(found_ips), list(found_domains)