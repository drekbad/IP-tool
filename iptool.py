import ipaddress
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

def parse_snm_or_cidr(ip, netmask=None):
    try:
        # Check if IP includes a CIDR notation
        if '/' in ip:
            return ipaddress.ip_network(ip, strict=False)
        
        # Handle SNM in various formats
        if netmask:
            if '.' not in netmask:
                netmask = f"255.255.255.{netmask.lstrip('.')}"  # Convert short form (e.g., "240") to full SNM
            prefix_length = ipaddress.IPv4Address(netmask).max_prefixlen
            return ipaddress.ip_network(f"{ip}/{prefix_length}", strict=False)
        
        raise ValueError("Missing CIDR or SNM.")
        
    except ValueError as e:
        raise ValueError(f"Invalid format for -calc with CIDR or SNM: {e}")

def parse_file(file_path, disclude_net, disclude_broadcast, disclude_gateway):
    results = {"public": 0, "private": 0}
    total_records = 0
    summaries = defaultdict(int)

    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            try:
                parts = line.split()
                network = parse_snm_or_cidr(parts[0], parts[1] if len(parts) > 1 else None)
                usable_count = calculate_usable_ips(network, disclude_net, disclude_broadcast, disclude_gateway)
                
                is_private_ip = is_private(network.network_address)
                if is_private_ip:
                    summaries["private_count"] += usable_count
                    results["private"] += usable_count
                else:
                    summaries["public_count"] += usable_count
                    results["public"] += usable_count

                total_records += 1
            except ValueError as e:
                print(f"Invalid format in file line '{line}': {e}")

    return results, summaries, total_records

def main():
    parser = argparse.ArgumentParser(description="Count usable IPs from a file with IP/CIDR or SNM notation.")
    parser.add_argument("-i", "--input", help="Input file path.")
    parser.add_argument(
        "-disclude", "--disclude",
        help="Choose which IPs to disclude from count: NW (Network), GW (Gateway), BC (Broadcast). Separate by comma.",
        type=str,
        default=""
    )
    parser.add_argument("-calc", "--calculate", nargs='*', help="Calculate IP range details for a given IP/CIDR or SNM.")
    parser.add_argument("-all", "--all_counts", action="store_true", help="Display all IP counts with different inclusion configurations.")
    args = parser.parse_args()

    # Interpret disclude settings
    disclude_net = 'NW' in args.disclude.upper()
    disclude_broadcast = 'BC' in args.disclude.upper()
    disclude_gateway = 'GW' in args.disclude.upper()

    # Handle `-calc` with `-i` input file option
    if args.calculate is not None and args.input:
        with open(args.input, 'r') as file:
            for line in file:
                line = line.strip()
                parts = line.split()
                if len(parts) < 2 and '/' not in parts[0]:
                    print("Error in file entry: Please provide both an IP and a CIDR or SNM.")
                    continue
                try:
                    network = parse_snm_or_cidr(parts[0], parts[1] if len(parts) > 1 else None)
                    display_range_info(network)
                    print()  # Newline for readability
                except ValueError as e:
                    print(f"Invalid format in file line '{line}': {e}")
        return  # Exit after processing file with -calc

    # Handle single `-calc` option with provided IP/CIDR or IP SNM
    elif args.calculate:
        if len(args.calculate) == 1 and '/' not in args.calculate[0]:
            print("Error: Please provide both an IP and a CIDR or SNM.")
            return
        elif len(args.calculate) == 1:
            try:
                network = parse_snm_or_cidr(args.calculate[0])
                display_range_info(network)
            except ValueError as e:
                print(f"Invalid format for -calc with CIDR/SNM: {e}")
        elif len(args.calculate) == 2:
            try:
                network = parse_snm_or_cidr(args.calculate[0], args.calculate[1])
                display_range_info(network)
            except ValueError as e:
                print(f"Invalid format for -calc with SNM/CIDR: {e}")
        else:
            print("Error: -calc expects an IP with CIDR or SNM.")
    elif args.input:
        # Parse file and get results
        results, summaries, total_records = parse_file(args.input, disclude_net, disclude_broadcast, disclude_gateway)

        # Display summary results
        print(f"\nSummary for {total_records} records:")
        print("Public IPs:", summaries["public_count"])
        print("Private IPs:", summaries["private_count"])
        print("Total Usable IPs:", results["public"] + results["private"])

        if args.all_counts:
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
