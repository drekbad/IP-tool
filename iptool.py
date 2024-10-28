import sys
import ipaddress
import re
import argparse
from collections import defaultdict

def is_private(ip):
    return ip.is_private

def calculate_usable_ips(network, disclude_net=False, disclude_broadcast=False, disclude_gateway=False):
    hosts = list(network.hosts())
    total_hosts = len(hosts)

    # Ensure inclusions by default
    if not disclude_net:
        total_hosts += 1  # Count the network IP
    if not disclude_broadcast:
        total_hosts += 1  # Count the broadcast IP
    if not disclude_gateway and len(hosts) > 1:
        total_hosts += 1  # Add a "gateway" IP if multiple hosts exist

    return total_hosts

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

def parse_snm_or_cidr(value):
    # Determines if input is CIDR, SNM in last-octet, or full SNM format, returns IP network
    try:
        # Try parsing as CIDR
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        # Check if it's in subnet mask format (either full or final octet form)
        snm_match = re.fullmatch(r"255(\.\d+){3}|(\d{1,3})$", value.strip('.'))
        if snm_match:
            # Handle SNM formats
            snm = snm_match.group()
            if len(snm.split('.')) == 1:
                # Last octet form (e.g., 248 or .248)
                snm = f"255.255.255.{snm}"
            return ipaddress.IPv4Network(f"0.0.0.0/{ipaddress.IPv4Address(snm).max_prefixlen}", strict=False)
    raise ValueError("Invalid format for CIDR or SNM")

def main():
    parser = argparse.ArgumentParser(description="Count usable IPs from a file with IP/CIDR or SNM notation.")
    parser.add_argument("-i", "--input", help="Input file path.")
    parser.add_argument(
        "-disclude", "--disclude",
        help="Choose which IPs to disclude from count: NW (Network), GW (Gateway), BC (Broadcast). Separate by comma.",
        type=str,
        default=""
    )
    parser.add_argument("-calc", "--calculate", nargs='?', help="Calculate IP range details for a given IP/CIDR or SNM")
    parser.add_argument("-all", "--all_counts", action="store_true", help="Display all IP counts with different inclusion configurations.")
    args = parser.parse_args()

    # Interpret disclude settings
    disclude_net = 'NW' in args.disclude.upper()
    disclude_broadcast = 'BC' in args.disclude.upper()
    disclude_gateway = 'GW' in args.disclude.upper()

    if args.calculate:
        # If `-calc` is provided without value, assume `-i` file content should be used
        if not args.calculate and args.input:
            with open(args.input, 'r') as file:
                for line in file:
                    line = line.strip()
                    try:
                        network = parse_snm_or_cidr(line)
                        display_range_info(network)
                        print()  # Newline for readability
                    except ValueError as e:
                        print(f"Invalid format in file line '{line}': {e}")
        else:
            # Handle single `-calc` value (CIDR or SNM format)
            try:
                network = parse_snm_or_cidr(args.calculate)
                display_range_info(network)
            except ValueError as e:
                print(f"Invalid format for -calc: {e}")

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
