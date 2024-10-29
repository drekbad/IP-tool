import ipaddress
import argparse
from collections import defaultdict

def calculate_usable_ips(network, disclude_net=False, disclude_broadcast=False, disclude_gateway=False):
    hosts = list(network.hosts())
    total_hosts = len(hosts)

    if not disclude_net:
        total_hosts += 1
    if not disclude_broadcast:
        total_hosts += 1
    if not disclude_gateway and len(hosts) > 1:
        total_hosts += 1

    return total_hosts

def underline_text(text):
    # ANSI escape code for underlined text (without the colon)
    return f"\033[4m{text}\033[0m:"

def display_range_info(network, provided_addr, provided_snm=False):
    # Display CIDR or Netmask based on what was provided
    cidr_or_netmask = f"/{network.prefixlen}" if provided_snm else str(network.netmask)
    
    # Output fields with specific alignment adjustments
    print(f"{underline_text('Provided Addr'):<15} {provided_addr:>20}")
    print(f"{'Network:':<15} {str(network.network_address):>20}")
    print(f"{'Netmask/CIDR:':<15} {cidr_or_netmask:>20}")
    print(f"{'Broadcast:':<15} {str(network.broadcast_address):>20}")
    print(f"{'First Usable IP:':<15} {str(list(network.hosts())[0] if list(network.hosts()) else 'N/A'):>20}")  # Corrected spacing for "First Usable IP"
    print(f"{'Last Usable IP:':<15} {str(list(network.hosts())[-1] if list(network.hosts()) else 'N/A'):>20}")
    print(f"{'Total IPs:':<15} {network.num_addresses:>20}")
    print(f"{'Usable IPs:':<15} {len(list(network.hosts())):>20}")

def parse_snm_or_cidr(ip, netmask=None):
    try:
        if '/' in ip:
            return ipaddress.ip_network(ip, strict=False), False
        elif netmask:
            if '.' not in netmask:
                netmask = f"255.255.255.{netmask.lstrip('.')}"
            prefix_length = ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
            return ipaddress.ip_network(f"{ip}/{prefix_length}", strict=False), True
        else:
            raise ValueError("Missing CIDR or SNM.")
    except ValueError as e:
        raise ValueError(f"Invalid format for -calc with CIDR or SNM: {e}")

def parse_file(file_path, disclude_net, disclude_broadcast, disclude_gateway, calc_mode=False):
    results = {"public": 0, "private": 0}
    total_records = 0
    summaries = defaultdict(int)

    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            try:
                parts = line.split()
                provided_addr = f"{parts[0]} {parts[1]}" if len(parts) > 1 else parts[0]
                network, provided_snm = parse_snm_or_cidr(parts[0], parts[1] if len(parts) > 1 else None)
                
                if calc_mode:
                    display_range_info(network, provided_addr, provided_snm)
                    print()  # Ensure only one line break between records
                
                usable_count = calculate_usable_ips(network, disclude_net, disclude_broadcast, disclude_gateway)
                
                is_private_ip = network.is_private
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

    disclude_net = 'NW' in args.disclude.upper()
    disclude_broadcast = 'BC' in args.disclude.upper()
    disclude_gateway = 'GW' in args.disclude.upper()

    if args.calculate is not None and args.input:
        results, summaries, total_records = parse_file(args.input, disclude_net, disclude_broadcast, disclude_gateway, calc_mode=True)

        print("=" * 36)
        print(f"\nSummary for {total_records} records:")
        print(f"{'Public IPs:':<15} {summaries['public_count']:>20}")
        print(f"{'Private IPs:':<15} {summaries['private_count']:>20}")
        print(f"{'Total Usable IPs:':<15} {results['public'] + results['private']:>18}\n")
        return

    elif args.calculate:
        if len(args.calculate) == 1 and '/' not in args.calculate[0]:
            print("Error: Please provide both an IP and a CIDR or SNM.")
            return
        elif len(args.calculate) == 1:
            try:
                network, provided_snm = parse_snm_or_cidr(args.calculate[0])
                display_range_info(network, args.calculate[0])
            except ValueError as e:
                print(f"Invalid format for -calc with CIDR/SNM: {e}")
        elif len(args.calculate) == 2:
            try:
                network, provided_snm = parse_snm_or_cidr(args.calculate[0], args.calculate[1])
                display_range_info(network, f"{args.calculate[0]} {args.calculate[1]}")
            except ValueError as e:
                print(f"Invalid format for -calc with SNM/CIDR: {e}")
        else:
            print("Error: -calc expects an IP with CIDR or SNM.")
    elif args.input:
        results, summaries, total_records = parse_file(args.input, disclude_net, disclude_broadcast, disclude_gateway, calc_mode=False)

        print(f"\nSummary for {total_records} records:")
        print(f"{'Public IPs:':<15} {summaries['public_count']:>20}")
        print(f"{'Private IPs:':<15} {summaries['private_count']:>20}")
        print(f"{'Total Usable IPs:':<15} {results['public'] + results['private']:>18}\n")

if __name__ == "__main__":
    main()
