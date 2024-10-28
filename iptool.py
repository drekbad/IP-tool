import sys
import ipaddress
import re
import argparse
from collections import defaultdict

def is_private(ip):
    return ip.is_private

def calculate_usable_ips(network, disclude_net, disclude_broadcast, disclude_gateway):
    hosts = list(network.hosts())
    total_hosts = len(hosts)

    # Adjust counts based on disclusion
    if disclude_net:
        total_hosts -= 1
    if disclude_broadcast:
        total_hosts -= 1
    if disclude_gateway and len(hosts) > 1:
        total_hosts -= 1  # Consider the "gateway" IP if discluded

    return total_hosts

def parse_line(line, disclude_net, disclude_broadcast, disclude_gateway):
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

            usable_count = calculate_usable_ips(network, disclude_net, disclude_broadcast, disclude_gateway)
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

def parse_file(file_path, disclude_net, disclude_broadcast, disclude_gateway):
    results = {"public": 0, "private": 0}
    total_records = 0
    summaries = defaultdict(int)

    with open(file_path, 'r') as file:
        for line in file:
            result = parse_line(line, disclude_net, disclude_broadcast, disclude_gateway)
            if result:
                total_records += 1
                if result["private"]:
                    summaries["private_count"] += result["usable_ips"]
                    results["private"] += result["usable_ips"]
                else:
                    summaries["public_count"] += result["usable_ips"]
                    results["public"] += result["usable_ips"]

    return results, summaries, total_records

def display_range_info(network):
    # Display range details for a single CIDR/SNM input
    hosts = list(network.hosts())
    usable_count = len(hosts)
    first_usable = hosts[0] if hosts else None
    last_usable = hosts[-1] if hosts else None

    print(f"Network: {network.network_address}")
    print(f"Netmask: {network.netmask}")
    print(f"Broadcast: {network.broadcast_address}")
    print(f"First Usable IP: {first_usable}")
    print(f"Last Usable IP: {last_usable}")
    print(f"Total IPs: {network.num_addresses}")
    print(f"Usable IPs: {usable_count}")

def main():
    parser = argparse.ArgumentParser(description="Count usable IPs from a file with IP/CIDR or SNM notation.")
    parser.add_argument("-i", "--input", help="Input file path.")
    parser.add_argument(
        "-disclude", "--disclude",
        help="Choose which IPs to disclude from count: NW (Network), GW (Gateway), BC (Broadcast). Separate by comma.",
        type=str,
        default=""
    )
    parser.add_argument("-calc", "--calculate", help="Calculate IP range details for a given IP/CIDR or SNM")
    parser.add_argument("-all", "--all_counts", action="store_true", help="Display all IP counts with different inclusion configurations.")
    args = parser.parse_args()

    # Interpret disclude settings
    disclude_net = 'NW' in args.disclude.upper()
    disclude_broadcast = 'BC' in args.disclude.upper()
    disclude_gateway = 'GW' in args.disclude.upper()

    if args.calculate:
        # Handle single range calculation
        calc_input = args.calculate.strip()
        calc_match = re.match(r"(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2})|\s*(255(?:\.\d+){3}|255\.\d+))?", calc_input)

        if calc_match:
            ip_str, cidr, snm = calc_match.groups()
            try:
                if cidr:
                    network = ipaddress.ip_network(f"{ip_str}/{cidr}", strict=False)
                elif snm:
                    network = ipaddress.IPv4Network(f"{ip_str}/{ipaddress.IPv4Address(snm).max_prefixlen}", strict=False)
                else:
                    print("Error: Provide a valid CIDR or SNM format.")
                    return

                # Display range information
                display_range_info(network)

            except ValueError as e:
                print(f"Invalid range provided for calculation: {e}")
                return
        else:
            print("Error: Provide a valid IP/CIDR or SNM format for calculation.")
            return

    elif args.input:
        # Parse file and get results
        results, summaries, total_records = parse_file(args.input, disclude_net, disclude_broadcast, disclude_gateway)

        # Display summary results
        print(f"\nSummary for {total_records} records:")
        print("Public IPs:", summaries["public_count"])
        print("Private IPs:", summaries["private_count"])
        print("Total Usable IPs:", results["public"] + results["private"])

        if args.all_counts:
            # Calculate and display all counts based on different disclude settings
            all_configs = [
                ("All Included", False, False, False),
                ("Network Excluded", True, False, False),
                ("Broadcast Excluded", False, True, False),
                ("Gateway Excluded", False, False, True),
                ("Network & Broadcast Excluded", True, True, False),
                ("Network & Gateway Excluded", True, False, True),
                ("Broadcast & Gateway Excluded", False, True, True),
                ("All Excluded", True, True, True)
            ]

            print("\nDetailed Counts:")
            for config_name, net, bc, gw in all_configs:
                results, summaries, _ = parse_file(args.input, net, bc, gw)
                print(f"{config_name}: Public IPs = {summaries['public_count']}, Private IPs = {summaries['private_count']}")

if __name__ == "__main__":
    main()
