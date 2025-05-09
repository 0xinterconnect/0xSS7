#!/usr/bin/env python3
import argparse
import socket
import selectors
import ipaddress
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TimeElapsedColumn, TextColumn

# ────────── Defaults ──────────
DEFAULT_CONCURRENCY = 1024
DEFAULT_TIMEOUT     = 1.0
PING_CONCURRENCY   = 100
PING_TIMEOUT       = 1  # seconds

# ────────── CLI Arguments ──────────
parser = argparse.ArgumentParser(
    description="🚀 Fast SCTP scanner with host-alive pre-check",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter
)
parser.add_argument("-i","--ips",      required=True, help="IP range (start-end), CIDR, or comma list")
parser.add_argument("-p","--ports",    default="2905-2905",   help="Port range, e.g. 2905-2910")
parser.add_argument("-c","--concurrency", type=int, default=DEFAULT_CONCURRENCY,
                    help="Max simultaneous SCTP connections")
parser.add_argument("-T","--timeout",  type=float, default=DEFAULT_TIMEOUT,
                    help="Per-connect timeout (seconds)")
args = parser.parse_args()

console = Console()

def expand_ips(ipspec):
    ips = set()
    for part in ipspec.split(","):
        part = part.strip()
        if "/" in part:
            net = ipaddress.ip_network(part, strict=False)
            ips.update(str(ip) for ip in net.hosts())
        elif "-" in part:
            a,b = part.split("-",1)
            for i in range(int(ipaddress.IPv4Address(a)), int(ipaddress.IPv4Address(b))+1):
                ips.add(str(ipaddress.IPv4Address(i)))
        else:
            ips.add(part)
    return sorted(ips)

def expand_ports(prange):
    if "-" in prange:
        a,b = prange.split("-",1)
        return list(range(int(a), int(b)+1))
    return [int(prange)]

def ping_host(ip):
    # -c1: send 1 echo, -W: timeout in seconds
    res = subprocess.run(
        ["ping", "-c1", f"-W{PING_TIMEOUT}", ip],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    return ip if res.returncode == 0 else None

def filter_alive(ips):
    console.print(f"[blue]⏱  Pinging {len(ips)} hosts to find alive ones...[/]")
    alive = []
    with ThreadPoolExecutor(max_workers=PING_CONCURRENCY) as pool:
        futures = { pool.submit(ping_host, ip): ip for ip in ips }
        with Progress(
            SpinnerColumn(),
            "[progress.description]{task.description}",
            BarColumn(bar_width=None),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeElapsedColumn(),
            console=console
        ) as prog:
            task = prog.add_task("Pinging", total=len(futures))
            for fut in as_completed(futures):
                if fut.result():
                    alive.append(fut.result())
                prog.update(task, advance=1)
    console.print(f"[green]✔️  {len(alive)} hosts alive, {len(ips)-len(alive)} down[/]")
    return alive

def scan_sctp(ips, ports, concurrency, timeout):
    selector = selectors.DefaultSelector()
    results  = []
    in_flight = {}
    tasks = ((ip,port) for ip in ips for port in ports)
    total = len(ips)*len(ports)

    console.print(f"[blue]🔍 Scanning {len(ips)} hosts × {len(ports)} ports...[/]")
    with Progress(
        SpinnerColumn(),
        "[progress.description]{task.description}",
        BarColumn(bar_width=None),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeElapsedColumn(),
        console=console
    ) as prog:
        task_id = prog.add_task("Scanning", total=total)

        while True:
            # kick off new connections up to concurrency
            try:
                while len(in_flight) < concurrency:
                    ip, port = next(tasks)
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP)
                    sock.setblocking(False)
                    sock.connect_ex((ip, port))
                    selector.register(sock, selectors.EVENT_WRITE)
                    in_flight[sock] = (ip, port, time.time())
            except StopIteration:
                pass

            if not in_flight:
                break

            events = selector.select(timeout=0.1)
            now = time.time()
            # handle ready
            for key, _ in events:
                sock = key.fileobj
                ip, port, start = in_flight.pop(sock)
                selector.unregister(sock)
                err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if err == 0:
                    results.append((ip, port))
                sock.close()
                prog.update(task_id, advance=1)

            # handle timeouts
            for sock, (ip, port, start) in list(in_flight.items()):
                if now - start >= timeout:
                    selector.unregister(sock)
                    sock.close()
                    in_flight.pop(sock)
                    prog.update(task_id, advance=1)

    return results

def main():
    all_ips = expand_ips(args.ips)
    ports   = expand_ports(args.ports)

    alive_ips = filter_alive(all_ips)
    if not alive_ips:
        console.print("[bold yellow]⚠️  No alive hosts found, exiting.[/]")
        return

    open_ports = scan_sctp(alive_ips, ports, args.concurrency, args.timeout)

    if open_ports:
        table = Table(title="🟢 Open SCTP Ports")
        table.add_column("IP",    style="cyan", no_wrap=True)
        table.add_column("Port",  style="magenta")
        for ip, port in sorted(open_ports):
            table.add_row(ip, str(port))
        console.print(table)
    else:
        console.print("[bold yellow]⚠️  No open SCTP ports detected on alive hosts.[/]")

if __name__ == "__main__":
    main()
