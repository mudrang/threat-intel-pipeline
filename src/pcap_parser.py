import dpkt
import socket
import csv
import sys
import os

def is_valid_ip(address):
    """
    Checks if a string is a valid IPv4 or IPv6 address.
    """
    try:
        socket.inet_pton(socket.AF_INET, address)
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, address)
        except socket.error:
            return False
    return True

def parse_pcap(filename, output_filename):
    """
    Parses a PCAP file to extract unique IPs and domain names.
    Writes the results to a CSV file.
    """
    ips = set()
    domains = set()

    try:
        with open(filename, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)

            for timestamp, buf in pcap:
                # Unpack the Ethernet frame
                eth = dpkt.ethernet.Ethernet(buf)

                # Check for IP packet
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue

                ip = eth.data

                # Add source and destination IPs to the set
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
                
                if is_valid_ip(src_ip):
                    ips.add(src_ip)
                if is_valid_ip(dst_ip):
                    ips.add(dst_ip)
                
                # Check for TCP or UDP protocols
                if isinstance(ip.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                    # Check for DNS traffic (port 53)
                    if ip.data.sport == 53 or ip.data.dport == 53:
                        try:
                            dns = dpkt.dns.DNS(ip.data.data)
                            if dns.qr == dpkt.dns.DNS_R:  # DNS Response
                                if dns.an:
                                    for answer in dns.an:
                                        if answer.type == dpkt.dns.DNS_A or answer.type == dpkt.dns.DNS_CNAME:
                                            # Check if the name needs decoding, as some dpkt versions handle it differently
                                            domain_name = answer.name
                                            if isinstance(domain_name, bytes):
                                                domain_name = domain_name.decode('utf-8')
                                            domains.add(domain_name)
                        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError) as e:
                            # Handle potential unpacking errors for malformed packets
                            continue
            
    except (IOError, dpkt.dpkt.NeedData) as e:
        print(f"Error reading the PCAP file: {e}")
        return

    # Write the results to a CSV file
    with open(output_filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Type', 'Value'])
        for ip in sorted(list(ips)):
            writer.writerow(['IP', ip])
        for domain in sorted(list(domains)):
            writer.writerow(['Domain', domain])

    print(f"Extraction complete. Results saved to {output_filename}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python pcap_parser.py <path_to_pcap_file>")
        sys.exit(1)

    pcap_file_path = sys.argv[1]
    if not os.path.exists(pcap_file_path):
        print(f"Error: The file '{pcap_file_path}' was not found.")
        sys.exit(1)
        
    # The output will be saved as 'pcap_analysis.csv' in the same directory as the script.
    parse_pcap(pcap_file_path, 'pcap_analysis.csv')