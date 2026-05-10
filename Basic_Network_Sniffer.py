import sys
import os
import socket
import struct
import time
import threading
import argparse
import json
import signal
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR,
        Ether, Raw, IPv6, wrpcap, rdpcap, conf
    )
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
CYAN    = "\033[96m"
WHITE   = "\033[97m"
DIM     = "\033[2m"
BG_DARK = "\033[40m"


PROTO_COLORS = {
    "TCP":   BLUE,
    "UDP":   GREEN,
    "ICMP":  YELLOW,
    "ARP":   MAGENTA,
    "DNS":   CYAN,
    "HTTP":  RED,
    "HTTPS": RED,
    "OTHER": WHITE,
}

WELL_KNOWN_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 119: "NNTP", 123: "NTP",
    143: "IMAP", 161: "SNMP", 194: "IRC", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "SYSLOG", 587: "SMTP",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "ORACLE", 3306: "MYSQL", 3389: "RDP", 5432: "POSTGRES",
    5900: "VNC", 6379: "REDIS", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
    27017: "MONGODB",
}

ICMP_TYPES = {
    0: "Echo Reply", 3: "Destination Unreachable", 4: "Source Quench",
    5: "Redirect", 8: "Echo Request", 11: "Time Exceeded",
    12: "Parameter Problem", 13: "Timestamp Request", 14: "Timestamp Reply",
}


class PacketStats:
    def __init__(self):
        self.total       = 0
        self.by_proto    = defaultdict(int)
        self.by_src_ip   = defaultdict(int)
        self.by_dst_ip   = defaultdict(int)
        self.by_port     = defaultdict(int)
        self.bytes_total = 0
        self.start_time  = time.time()
        self.lock        = threading.Lock()

    def update(self, proto, src_ip, dst_ip, port, size):
        with self.lock:
            self.total           += 1
            self.bytes_total     += size
            self.by_proto[proto] += 1
            if src_ip:
                self.by_src_ip[src_ip] += 1
            if dst_ip:
                self.by_dst_ip[dst_ip] += 1
            if port:
                self.by_port[port] += 1

    def elapsed(self):
        return time.time() - self.start_time

    def pps(self):
        elapsed = self.elapsed()
        return self.total / elapsed if elapsed > 0 else 0


stats = PacketStats()
packet_log = []
stop_event = threading.Event()


def banner():
    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════════════╗
║           PYTHON NETWORK PACKET ANALYZER v2.0                ║
║          Real-time Traffic Capture & Protocol Analysis        ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")


def separator(char="─", width=66, color=DIM):
    print(f"{color}{char * width}{RESET}")


def get_service(port):
    return WELL_KNOWN_PORTS.get(port, str(port))


def proto_label(name):
    color = PROTO_COLORS.get(name, WHITE)
    return f"{color}{BOLD}[{name:<6}]{RESET}"


def hex_dump(data, max_bytes=64):
    if not data:
        return ""
    data   = bytes(data)[:max_bytes]
    lines  = []
    for i in range(0, len(data), 16):
        chunk   = data[i:i+16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        asc_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {DIM}{i:04x}{RESET}  {hex_str:<48}  {DIM}{asc_str}{RESET}")
    if len(bytes(data)) == max_bytes:
        lines.append(f"  {DIM}... (truncated){RESET}")
    return "\n".join(lines)


def safe_payload(raw):
    try:
        text = raw.decode("utf-8", errors="replace").strip()
        return text[:200] if text else None
    except Exception:
        return None


def analyze_tcp_flags(flags):
    names = {0x01: "FIN", 0x02: "SYN", 0x04: "RST",
             0x08: "PSH", 0x10: "ACK", 0x20: "URG"}
    active = [v for k, v in names.items() if int(flags) & k]
    return "|".join(active) if active else "NONE"


def format_packet_scapy(pkt, verbose=False, show_hex=False):
    ts      = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    size    = len(pkt)
    lines   = []
    payload = None
    proto   = "OTHER"
    src_ip  = dst_ip = sport = dport = None

    if pkt.haslayer(ARP):
        proto  = "ARP"
        arp    = pkt[ARP]
        op     = "REQUEST" if arp.op == 1 else "REPLY"
        lines.append(
            f"{proto_label(proto)} {YELLOW}{ts}{RESET}  "
            f"{BOLD}{arp.psrc}{RESET} → {BOLD}{arp.pdst}{RESET}  "
            f"{DIM}op={op} hwsrc={arp.hwsrc}{RESET}  "
            f"{DIM}size={size}B{RESET}"
        )
        src_ip = arp.psrc
        dst_ip = arp.pdst

    elif pkt.haslayer(IP) or pkt.haslayer(IPv6):
        ip     = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        src_ip = ip.src
        dst_ip = ip.dst
        ttl    = getattr(ip, "ttl", getattr(ip, "hlim", "?"))

        if pkt.haslayer(DNS):
            proto     = "DNS"
            dns       = pkt[DNS]
            qr        = "RESPONSE" if dns.qr else "QUERY"
            qname     = dns[DNSQR].qname.decode() if pkt.haslayer(DNSQR) else "?"
            answers   = []
            if dns.qr and dns.ancount > 0:
                rr = dns.an
                while rr and rr.type != 41:
                    rdata = getattr(rr, "rdata", "?")
                    answers.append(str(rdata))
                    rr = rr.payload if hasattr(rr, "payload") else None
            ans_str = " → " + ", ".join(answers) if answers else ""
            lines.append(
                f"{proto_label(proto)} {YELLOW}{ts}{RESET}  "
                f"{BOLD}{src_ip}{RESET} → {BOLD}{dst_ip}{RESET}  "
                f"{CYAN}{qr}{RESET} {qname}{ans_str}  "
                f"{DIM}size={size}B{RESET}"
            )

        elif pkt.haslayer(ICMP):
            proto    = "ICMP"
            icmp     = pkt[ICMP]
            icmp_str = ICMP_TYPES.get(icmp.type, f"type={icmp.type}")
            lines.append(
                f"{proto_label(proto)} {YELLOW}{ts}{RESET}  "
                f"{BOLD}{src_ip}{RESET} → {BOLD}{dst_ip}{RESET}  "
                f"{YELLOW}{icmp_str}{RESET}  "
                f"{DIM}ttl={ttl} size={size}B{RESET}"
            )

        elif pkt.haslayer(TCP):
            proto  = "TCP"
            tcp    = pkt[TCP]
            sport  = tcp.sport
            dport  = tcp.dport
            flags  = analyze_tcp_flags(tcp.flags)
            svc    = get_service(dport) or get_service(sport)

            if dport == 443 or sport == 443:
                proto = "HTTPS"
            elif dport == 80 or sport == 80:
                proto = "HTTP"

            if pkt.haslayer(HTTPRequest):
                http  = pkt[HTTPRequest]
                meth  = http.Method.decode() if http.Method else "?"
                path  = http.Path.decode()   if http.Path   else "/"
                host  = http.Host.decode()   if http.Host   else dst_ip
                lines.append(
                    f"{proto_label('HTTP')} {YELLOW}{ts}{RESET}  "
                    f"{BOLD}{src_ip}:{sport}{RESET} → {BOLD}{dst_ip}:{dport}{RESET}  "
                    f"{RED}{meth} http://{host}{path}{RESET}  "
                    f"{DIM}flags={flags} size={size}B{RESET}"
                )
            elif pkt.haslayer(HTTPResponse):
                http    = pkt[HTTPResponse]
                status  = http.Status_Code.decode() if http.Status_Code else "?"
                reason  = http.Reason_Phrase.decode() if http.Reason_Phrase else ""
                lines.append(
                    f"{proto_label('HTTP')} {YELLOW}{ts}{RESET}  "
                    f"{BOLD}{src_ip}:{sport}{RESET} → {BOLD}{dst_ip}:{dport}{RESET}  "
                    f"{GREEN}HTTP {status} {reason}{RESET}  "
                    f"{DIM}flags={flags} size={size}B{RESET}"
                )
            else:
                lines.append(
                    f"{proto_label(proto)} {YELLOW}{ts}{RESET}  "
                    f"{BOLD}{src_ip}:{sport}{RESET} → {BOLD}{dst_ip}:{dport}{RESET}  "
                    f"{DIM}flags={flags} ttl={ttl} svc={svc} size={size}B{RESET}"
                )

            if pkt.haslayer(Raw):
                payload = safe_payload(pkt[Raw].load)

        elif pkt.haslayer(UDP):
            proto = "UDP"
            udp   = pkt[UDP]
            sport = udp.sport
            dport = udp.dport
            svc   = get_service(dport) or get_service(sport)
            lines.append(
                f"{proto_label(proto)} {YELLOW}{ts}{RESET}  "
                f"{BOLD}{src_ip}:{sport}{RESET} → {BOLD}{dst_ip}:{dport}{RESET}  "
                f"{DIM}ttl={ttl} svc={svc} size={size}B{RESET}"
            )
            if pkt.haslayer(Raw):
                payload = safe_payload(pkt[Raw].load)

        else:
            proto_id = ip.proto if pkt.haslayer(IP) else "IPv6"
            lines.append(
                f"{proto_label('OTHER')} {YELLOW}{ts}{RESET}  "
                f"{BOLD}{src_ip}{RESET} → {BOLD}{dst_ip}{RESET}  "
                f"{DIM}proto={proto_id} size={size}B{RESET}"
            )

    else:
        lines.append(
            f"{proto_label('OTHER')} {YELLOW}{ts}{RESET}  "
            f"{DIM}Non-IP frame  size={size}B{RESET}"
        )

    if verbose and payload:
        lines.append(f"  {DIM}Payload:{RESET} {CYAN}{payload[:120]}{RESET}")

    if show_hex and pkt.haslayer(Raw):
        raw_bytes = bytes(pkt[Raw].load)
        if raw_bytes:
            lines.append(f"  {DIM}Hex dump:{RESET}")
            lines.append(hex_dump(raw_bytes))

    stats.update(proto, src_ip, dst_ip,
                 dport if dport else sport,
                 size)

    packet_log.append({
        "time":    datetime.now().isoformat(),
        "proto":   proto,
        "src_ip":  src_ip,
        "dst_ip":  dst_ip,
        "sport":   sport,
        "dport":   dport,
        "size":    size,
    })

    return "\n".join(lines)


def print_live_stats():
    elapsed = stats.elapsed()
    rate    = stats.bytes_total / elapsed / 1024 if elapsed > 0 else 0
    print(
        f"\r{DIM}Packets: {BOLD}{WHITE}{stats.total}{RESET}{DIM}  "
        f"Rate: {BOLD}{WHITE}{stats.pps():.1f}{RESET}{DIM} pkt/s  "
        f"Throughput: {BOLD}{WHITE}{rate:.2f}{RESET}{DIM} KB/s  "
        f"Elapsed: {BOLD}{WHITE}{elapsed:.0f}{RESET}{DIM}s{RESET}",
        end="", flush=True
    )


def stats_summary():
    elapsed = stats.elapsed()
    print(f"\n\n{BOLD}{CYAN}{'═'*66}")
    print(f"  CAPTURE SUMMARY")
    print(f"{'═'*66}{RESET}")
    print(f"  {BOLD}Total Packets  :{RESET} {stats.total}")
    print(f"  {BOLD}Total Bytes    :{RESET} {stats.bytes_total:,} B  ({stats.bytes_total/1024:.2f} KB)")
    print(f"  {BOLD}Duration       :{RESET} {elapsed:.2f}s")
    print(f"  {BOLD}Avg Throughput :{RESET} {stats.bytes_total/elapsed/1024:.2f} KB/s")

    print(f"\n  {BOLD}Protocol Breakdown:{RESET}")
    separator("─", 44)
    for proto, count in sorted(stats.by_proto.items(),
                                key=lambda x: x[1], reverse=True):
        pct   = count / stats.total * 100 if stats.total else 0
        bar   = "█" * int(pct / 2)
        color = PROTO_COLORS.get(proto, WHITE)
        print(f"  {color}{proto:<8}{RESET}  {count:>5} pkts  {pct:5.1f}%  {color}{bar}{RESET}")

    print(f"\n  {BOLD}Top Source IPs:{RESET}")
    separator("─", 44)
    for ip, count in sorted(stats.by_src_ip.items(),
                              key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {GREEN}{ip:<18}{RESET}  {count:>5} pkts")

    print(f"\n  {BOLD}Top Destination IPs:{RESET}")
    separator("─", 44)
    for ip, count in sorted(stats.by_dst_ip.items(),
                              key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {RED}{ip:<18}{RESET}  {count:>5} pkts")

    print(f"\n  {BOLD}Top Ports:{RESET}")
    separator("─", 44)
    for port, count in sorted(stats.by_port.items(),
                               key=lambda x: x[1], reverse=True)[:10]:
        if port:
            svc = WELL_KNOWN_PORTS.get(port, "")
            svc_str = f"  ({svc})" if svc else ""
            print(f"  {CYAN}{port:<7}{RESET}{DIM}{svc_str:<12}{RESET}  {count:>5} pkts")

    print(f"{BOLD}{CYAN}{'═'*66}{RESET}\n")


def save_json(path):
    with open(path, "w") as f:
        json.dump(packet_log, f, indent=2, default=str)
    print(f"{GREEN}Packet log saved to {BOLD}{path}{RESET}")


def save_pcap(packets, path):
    try:
        wrpcap(path, packets)
        print(f"{GREEN}PCAP saved to {BOLD}{path}{RESET}")
    except Exception as e:
        print(f"{RED}Failed to save PCAP: {e}{RESET}")


class RawSocketCapture:
    def __init__(self, iface=None, verbose=False, show_hex=False):
        self.verbose  = verbose
        self.show_hex = show_hex

    def parse_ip_header(self, data):
        iph    = struct.unpack("!BBHHHBBH4s4s", data[:20])
        ihl    = (iph[0] & 0xF) * 4
        proto  = iph[6]
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])
        return ihl, proto, src_ip, dst_ip, len(data)

    def parse_tcp(self, data, offset):
        tcp    = struct.unpack("!HHLLBBHHH", data[offset:offset+20])
        sport  = tcp[0]
        dport  = tcp[1]
        flags  = tcp[5]
        flag_s = analyze_tcp_flags(flags)
        return sport, dport, flag_s

    def parse_udp(self, data, offset):
        udp   = struct.unpack("!HHHH", data[offset:offset+8])
        sport = udp[0]
        dport = udp[1]
        return sport, dport

    def parse_icmp(self, data, offset):
        icmp_type = data[offset]
        return ICMP_TYPES.get(icmp_type, f"type={icmp_type}")

    def capture(self, count=0, bpf_filter=None):
        try:
            sock = socket.socket(socket.AF_PACKET,
                                  socket.SOCK_RAW,
                                  socket.htons(0x0003))
        except PermissionError:
            print(f"{RED}Error: Raw socket requires root/admin privileges.{RESET}")
            sys.exit(1)

        captured = 0
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print(f"{DIM}Raw socket capture started at {ts}{RESET}\n")

        while not stop_event.is_set():
            try:
                raw_data, addr = sock.recvfrom(65536)
            except Exception:
                break

            size = len(raw_data)
            eth_proto = struct.unpack("!H", raw_data[12:14])[0]

            if eth_proto == 0x0800:
                try:
                    ihl, proto, src_ip, dst_ip, _ = self.parse_ip_header(raw_data[14:])
                    ts_now = datetime.now().strftime("%H:%M:%S.%f")[:-3]

                    if proto == 6:
                        sport, dport, flags = self.parse_tcp(raw_data[14:], ihl)
                        p = "HTTPS" if dport in (443,) or sport in (443,) else "TCP"
                        svc = get_service(dport)
                        print(
                            f"{proto_label(p)} {YELLOW}{ts_now}{RESET}  "
                            f"{BOLD}{src_ip}:{sport}{RESET} → {BOLD}{dst_ip}:{dport}{RESET}  "
                            f"{DIM}flags={flags} svc={svc} size={size}B{RESET}"
                        )
                        stats.update(p, src_ip, dst_ip, dport, size)

                    elif proto == 17:
                        sport, dport = self.parse_udp(raw_data[14:], ihl)
                        svc = get_service(dport)
                        p   = "DNS" if dport == 53 or sport == 53 else "UDP"
                        print(
                            f"{proto_label(p)} {YELLOW}{ts_now}{RESET}  "
                            f"{BOLD}{src_ip}:{sport}{RESET} → {BOLD}{dst_ip}:{dport}{RESET}  "
                            f"{DIM}svc={svc} size={size}B{RESET}"
                        )
                        stats.update(p, src_ip, dst_ip, dport, size)

                    elif proto == 1:
                        icmp_str = self.parse_icmp(raw_data[14:], ihl)
                        print(
                            f"{proto_label('ICMP')} {YELLOW}{ts_now}{RESET}  "
                            f"{BOLD}{src_ip}{RESET} → {BOLD}{dst_ip}{RESET}  "
                            f"{YELLOW}{icmp_str}{RESET}  {DIM}size={size}B{RESET}"
                        )
                        stats.update("ICMP", src_ip, dst_ip, None, size)

                    else:
                        print(
                            f"{proto_label('OTHER')} {YELLOW}{ts_now}{RESET}  "
                            f"{BOLD}{src_ip}{RESET} → {BOLD}{dst_ip}{RESET}  "
                            f"{DIM}proto={proto} size={size}B{RESET}"
                        )
                        stats.update("OTHER", src_ip, dst_ip, None, size)

                except struct.error:
                    continue

            captured += 1
            if count and captured >= count:
                break

            if captured % 10 == 0:
                print_live_stats()

        sock.close()


def run_scapy_capture(args):
    captured_pkts = []

    def packet_handler(pkt):
        if stop_event.is_set():
            return

        line = format_packet_scapy(pkt,
                                    verbose=args.verbose,
                                    show_hex=args.hex)
        print(line)

        if args.count and args.count % 20 == 0:
            print_live_stats()

        if args.pcap:
            captured_pkts.append(pkt)

    iface  = args.iface if args.iface else conf.iface
    filt   = args.filter if args.filter else None
    count  = args.count  if args.count  else 0

    print(f"{DIM}Scapy capture on iface={BOLD}{iface}{RESET}"
          f"{DIM}  filter={BOLD}{filt or 'none'}{RESET}"
          f"{DIM}  count={BOLD}{count or '∞'}{RESET}\n")

    try:
        sniff(iface=iface,
              filter=filt,
              prn=packet_handler,
              count=count,
              store=False,
              stop_filter=lambda _: stop_event.is_set())
    except PermissionError:
        print(f"{RED}Permission denied. Run as root/sudo.{RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{RED}Capture error: {e}{RESET}")

    return captured_pkts


def read_pcap_file(path, verbose=False, show_hex=False):
    if not os.path.isfile(path):
        print(f"{RED}File not found: {path}{RESET}")
        sys.exit(1)

    print(f"{CYAN}Reading PCAP: {BOLD}{path}{RESET}\n")
    pkts = rdpcap(path)
    print(f"{DIM}Loaded {len(pkts)} packets{RESET}\n")

    for pkt in pkts:
        print(format_packet_scapy(pkt, verbose=verbose, show_hex=show_hex))


def signal_handler(sig, frame):
    print(f"\n\n{YELLOW}Capture interrupted.{RESET}")
    stop_event.set()


def main():
    banner()

    parser = argparse.ArgumentParser(
        description="Network Packet Analyzer",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-i", "--iface",   default=None,
                        help="Network interface (default: auto)")
    parser.add_argument("-c", "--count",   type=int, default=0,
                        help="Number of packets to capture (0=unlimited)")
    parser.add_argument("-f", "--filter",  default=None,
                        help="BPF filter (e.g. 'tcp', 'port 80', 'host 1.2.3.4')")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show payload snippets")
    parser.add_argument("-x", "--hex",     action="store_true",
                        help="Show hex dump of payloads")
    parser.add_argument("--pcap",          default=None,
                        help="Save capture to .pcap file")
    parser.add_argument("--read",          default=None,
                        help="Read and analyze an existing .pcap file")
    parser.add_argument("--json",          default=None,
                        help="Save packet log as JSON")
    parser.add_argument("--raw",           action="store_true",
                        help="Use raw sockets instead of scapy")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler)

    if args.read:
        if not SCAPY_AVAILABLE:
            print(f"{RED}Scapy required for reading PCAP files.{RESET}")
            sys.exit(1)
        read_pcap_file(args.read, args.verbose, args.hex)
        stats_summary()
        if args.json:
            save_json(args.json)
        return

    if args.raw or not SCAPY_AVAILABLE:
        if not SCAPY_AVAILABLE:
            print(f"{YELLOW}Scapy not available — falling back to raw sockets.{RESET}\n")
        cap = RawSocketCapture(args.iface, args.verbose, args.hex)
        cap.capture(count=args.count, bpf_filter=args.filter)
    else:
        captured = run_scapy_capture(args)
        if args.pcap and captured:
            save_pcap(captured, args.pcap)

    stats_summary()

    if args.json:
        save_json(args.json)


if __name__ == "__main__":
    main()