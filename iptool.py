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

def display_range_info(network, provided_addr):
    # Convert IPv4Address and IPv4Network objects to strings for formatting
    network_address = str(network.network_address)
    netmask = str(network.netmask)
    broadcast = str(network.broadcast_address)
    hosts = list(network.hosts())
    usable_count = len(hosts)
    first_usable = str(hosts[0]) if hosts else "N/A"
    last_usable = str(hosts[-1]) if hosts else "N/A"
    
    print(f"Provided Addr:  {provided_addr}")
    print(f"{'Network:':<15}{network_address:>20}")
    print(f"{'Netmask:':<15}{netmask:>20}")
    print(f"{'Broadcast:':<15}{broadcast:>20}")
    print(f"{'First Usable IP:':<15}{first_usable:>20}")
    print(f"{'Last Usable IP:':<15}{last_usable:>20}")
    print(f"{'Total IPs:':<15}{network.num_addresses:>20}")
    print(f"{'Usable IPs:':<15}{usable_count:>20}")

def parse_snm_or_cidr(ip, netmask=None):
    try:
        # Convert SNM to CIDR if provided
        if netmask and '/' not in netmask:
            if '.' not in netmask:
                netmask = f"255.255.255.{netmask}"  # Convert abbreviated SNM (e.g., "240") to full
            # Convert SNM to CIDR notation
            cidr = ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
            return ipaddress.ip_network(f"{ip}/{cidr}", strict=False)
        # Assume CIDR if no netmask provided
        return ipaddress.ip_network(ip, strict=False)
        
    except ValueError:
        raise ValueError("Invalid format: Must provide both IP and valid CIDR or SNM.")

def parse_file(file_path, disclude_net, disclude_broadcast, disclude_gateway):
    results = {"public": 0, "private": 0}
    total_records = 0
    summaries = defaultdict(int)

    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            try:
                parts = line.split()
                provided_addr = f"{parts[0]} {parts[1]}" if len(parts) > 1 else parts[0]
                network = parse_snm_or_cidr(parts[0], parts[1] if len(parts) > 1 else None)
                display_range_info(network, provided_addr)
                print()  # Newline for readability
                
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
        results, summaries, total_records = parse_file(args.input, disclude_net, disclude_broadcast, disclude_gateway)

        # Display separator and summary totals at the end
        print("\n" + "="*50)
        print(f"\nSummary for {total_records} records:")
        print(f"{'Public IPs:':<15}{summaries['public_count']:>20}")
        print(f"{'Private IPs:':<15}{summaries['private_count']:>20}")
        print(f"{'Total Usable IPs:':<15}{results['public'] + results['private']:>20}")
        return  # Exit after processing file with -calc

    # Handle single `-calc` option with provided IP/CIDR or IP SNM
    elif args.calculate:
        if len(args.calculate) == 1:
            print("Error: Please provide both an IP and a CIDR or SNM.")
            return
        elif len(args.calculate) == 2:
            try:
                provided_addr = f"{args.calculate[0]} {args.calculate[1]}"
                network = parse_snm_or_cidr(args.calculate[0], args.calculate[1])
                display_range_info(network, provided_addr)
            except ValueError as e:
                print(f"Invalid format for -calc with SNM/CIDR: {e}")
        else:
            print("Error: -calc expects an IP with CIDR or SNM.")
    elif args.input:
        # Parse file and get results
        results, summaries, total_records = parse_file(args.input, disclude_net, disclude_broadcast, disclude_gateway)

        # Display summary results
        print(f"\nSummary for {total_records} records:")
        print(f"{'Public IPs:':<15}{summaries['public_count']:>20}")
        print(f"{'Private IPs:':<15}{summaries['private_count']:>20}")
        print(f"{'Total Usable IPs:':<15}{results['public'] + results['private']:>20}")

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
