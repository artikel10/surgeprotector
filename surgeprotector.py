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
    pass


@main.command()
@click.option('--number', '-n',
              help='Number of IP addresses to show.',
              default=10,
              show_default=True)
def show(number):
    """Show IP addresses with the most TCP connections."""
    connections = get_connections()
    connections = [(v, k) for k, v in connections.items()]
    connections.sort(key=lambda conn: conn[0])
    for conn in connections[-number:]:
        print(f'{conn[0]:6} {conn[1]}')


@main.command()
@click.argument('output', type=click.Path(dir_okay=False))
@click.argument('limit', type=int)
@click.option('--ttl',
              help='Number of seconds after which "ExitPolicy" lines expire.',
              default=3600,
              show_default=True)
@click.option('--command', '-c',
              help='Execute this command to reload Tor configuration.')
def update(limit, output, ttl, command):
    """Update "ExitPolicy" lines for flooded IP addresses in OUTPUT.

    An IP address is considered flooded over LIMIT TCP connections.
    """
    now = int(time.time())
    updated = False  # True if OUTPUT needs updating
    lines = []  # Lines for OUTPUT
    known = set()  # Known IP addresses from OUTPUT
    if os.path.exists(output):
        with click.open_file(output) as f:
            for line in f:
                m = EXIT_POLICY_RE.match(line.strip())
                if m is None:
                    continue
                addr = m.group(1)
                timestamp = int(m.group(2))
                if timestamp + ttl < now:
                    updated = True
                else:
                    lines.append(line)
                    known.add(addr)
    connections = get_connections()
    connections = {k: v for k, v in connections.items() if k not in known}
    connections = {k: v for k, v in connections.items() if v > limit}
    for addr in connections.keys():
        if ':' in addr:
            lines.append(f'ExitPolicy reject [{addr}] # {now}\n')
        else:
            lines.append(f'ExitPolicy reject {addr} # {now}\n')
        updated = True
    if updated:
        with click.open_file(output, mode='w') as f:
            for line in lines:
                f.write(line)
        if command:
            os.system(command)


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
