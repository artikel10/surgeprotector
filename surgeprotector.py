#!/usr/bin/env python3

from collections import defaultdict
import os
import sys
import time

import click
import psutil


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
@click.argument('output', type=click.Path(dir_okay=False, allow_dash=True))
@click.argument('limit', type=int)
@click.option('--command', '-c',
              help='Execute this command to reload Tor configuration.')
def update(limit, output, command):
    """Update "ExitPolicy" lines for flooded IP addresses in OUTPUT.

    An IP address is considered flooded over LIMIT TCP connections.
    """
    timestamp = int(time.time())
    connections = get_connections()
    connections = {k: v for k, v in connections.items() if v > limit}
    if not connections:
        return
    with click.open_file(output, mode='w') as f:
        for addr in connections.keys():
            if ':' in addr:
                line = f'ExitPolicy reject [{addr}] # {timestamp}\n'
            else:
                line = f'ExitPolicy reject {addr} # {timestamp}\n'
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
