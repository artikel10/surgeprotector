#!/usr/bin/env python3

from collections import defaultdict
import os
import os.path
import re
import sys
import time

import click
import psutil


EXIT_POLICY_RE = re.compile(r'ExitPolicy reject \[?([0-9a-z.:]+)\]? # (\d+)')


@click.group()
def main():
    """Block Tor Exit traffic to flooded IP addresses via ExitPolicy."""
    pass


@main.command()
@click.option('--number', '-n',
              help='Number of IP addresses to show.',
              default=10,
              show_default=True)
@click.option('--file', '-f',
              help='torrc fragment to show.',
              type=click.Path(exists=True, dir_okay=False))
def show(number, file):
    """Show IP addresses with the most TCP connections.

    If --file is used, show IP addresses and their timestamps from the torrc
    fragment instead.
    """
    if file is None:
        connections = [(v, k) for k, v in get_connections().items()]
        connections.sort(key=lambda conn: conn[0])
        for conn in connections[-number:]:
            click.echo(f'{conn[0]:6} {conn[1]}')
    else:
        for addr, timestamp in get_addresses(file):
            ts_struct = time.gmtime(timestamp)
            ts_string = time.strftime('%Y-%m-%dT%H:%M:%SZ', ts_struct)
            click.echo(f'{ts_string} {addr}')


@main.command()
@click.argument('output', type=click.Path(dir_okay=False))
@click.argument('limit', type=int)
@click.option('--ttl',
              help='Number of hours after which ExitPolicy lines expire.',
              default=24,
              show_default=True)
@click.option('--command', '-c',
              help='Execute this command if OUTPUT changed.')
def update(limit, output, ttl, command):
    """Update ExitPolicy lines for flooded IP addresses in OUTPUT.

    An IP address is considered flooded over LIMIT TCP connections.
    """
    now = int(time.time())
    ttl = ttl * 3600
    updated = False  # True if OUTPUT needs updating
    addresses = {}  # IP addresses and timestamps for OUTPUT
    if os.path.exists(output):
        for addr, timestamp in get_addresses(output):
            if now > timestamp + ttl:
                updated = True
            else:
                addresses[addr] = timestamp
    for addr, count in get_connections().items():
        if addr in addresses or limit >= count:
            continue
        addresses[addr] = now
        updated = True
    if updated:
        with click.open_file(output, mode='w') as f:
            for addr, timestamp in addresses.items():
                if ':' in addr:
                    line = f'ExitPolicy reject [{addr}] # {timestamp}\n'
                else:
                    line = f'ExitPolicy reject {addr} # {timestamp}\n'
                f.write(line)
        if command:
            os.system(command)


def get_addresses(path):
    """Return IP address/timestamp tuples from the torrc fragment."""
    result = []
    with click.open_file(path) as f:
        for line in f:
            m = EXIT_POLICY_RE.match(line.strip())
            if m is None:
                continue
            addr = m.group(1)
            timestamp = int(m.group(2))
            result.append((addr, timestamp))
    return result


def get_connections():
    """Return a dict of IP address to TCP connection count."""
    connections = defaultdict(int)
    for conn in psutil.net_connections(kind='tcp'):
        if not conn.raddr:
            continue
        connections[conn.raddr.ip] += 1
    return connections


if __name__ == '__main__':
    main()
