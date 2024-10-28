import sys
import ipaddress
import re
import argparse
from collections import defaultdict

def is_private(ip):
    return ip.is_private

def calculate_usable_ips(network, include_net, include_broadcast, include_gateway):
    hosts = list(network.hosts())
    total_hosts = len(hosts)

    # Adjust counts based on inclusion/exclusion of net, broadcast, gateway
    if include_net:
        total_hosts += 1  # Count the network IP
    if include_broadcast:
        total_hosts += 1  # Count the broadcast IP
    if include_gateway and len(hosts) > 1:
        total_hosts += 1  # Add a "gateway" IP if there are multiple hosts

    return total_hosts

def parse_line(line, include_net, include_broadcast, include_gateway):
    line = line.strip()
    match = re.match(r"(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?", line)
    snm_match = re.search(r"(255\.\d+\.\d+\.\d+)", line)

    if match:
        ip_str, cidr = match.groups()
        try:
            if cidr:
                network = ipaddress.ip_network(f"{ip_str}/{cidr}", strict=False)
            elif snm_match:
                snm = snm_match.group()
                network = ipaddress.IPv4Network(f"{ip_str}/{ipaddress.IPv4Address(snm).max_prefixlen}", strict=False)
            else:
                return None

            usable_count = calculate_usable_ips(network, include_net, include_broadcast, include_gateway)
            is_private_ip = is_private(network.network_address)

            return {
                "network": str(network),
                "usable_ips": usable_count,
                "private": is_private_ip,
                "total_ips": network.num_addresses,
            }
        except ValueError as e:
            print(f"Invalid IP/CIDR: {line} - {e}")
            return None
    return None

def parse_file(file_path, include_net, include_broadcast, include_gateway):
    results = {"public": 0, "private": 0}
    total_records = 0
    summaries = defaultdict(int)

    with open(file_path, 'r') as file:
        for line in file:
            result = parse_line(line, include_net, include_broadcast, include_gateway)
            if result:
                total_records += 1
                if result["private"]:
                    summaries["private_count"] += result["usable_ips"]
                    results["private"] += result["usable_ips"]
                else:
                    summaries["public_count"] += result["usable_ips"]
                    results["public"] += result["usable_ips"]

    return results, summaries, total_records

def main():
    parser = argparse.ArgumentParser(description="Count usable IPs from a file with IP/CIDR or SNM notation.")
    parser.add_argument("-i", "--input", required=True, help="Input file path.")
    parser.add_argument(
        "-inc", "--include",
        help="Choose inclusion option for network, broadcast, and gateway IPs. 1=All, 2=None, 3=Custom",
        type=int,
        choices=[1, 2, 3],
        default=1,
    )
    args = parser.parse_args()

    # Interpret inclusion settings
    if args.include == 1:  # All included
        include_net, include_broadcast, include_gateway = True, True, True
    elif args.include == 2:  # None included
        include_net, include_broadcast, include_gateway = False, False, False
    else:  # Custom, prompting user
        include_net = input("Include Network IP? (y/n): ").strip().lower() == 'y'
        include_broadcast = input("Include Broadcast IP? (y/n): ").strip().lower() == 'y'
        include_gateway = input("Include Gateway IP? (y/n): ").strip().lower() == 'y'

    # Parse file and get results
    results, summaries, total_records = parse_file(args.input, include_net, include_broadcast, include_gateway)

    # Display summary results
    print(f"\nSummary for {total_records} records:")
    print("Public IPs:", summaries["public_count"])
    print("Private IPs:", summaries["private_count"])
    print("Total Usable IPs:", results["public"] + results["private"])
    print(f"\nPublic IPs Total: {results['public']}, Private IPs Total: {results['private']}")

if __name__ == "__main__":
    main()
