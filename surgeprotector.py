#!/usr/bin/env python3

from collections import defaultdict
import os
import sys
import time

import click
import psutil


@click.command()
@click.argument('limit', type=int)
@click.option('--output', '-o',
              help='Write "ExitPolicy reject" lines to this file.',
              type=click.Path(dir_okay=False, allow_dash=True),
              default='-')
@click.option('--command', '-c',
              help='Execute this command to reload Tor configuration.')
def main(limit, output, command):
    """Generate "ExitPolicy reject" lines for flooded remote IP addresses.

    An address is considered flooded over LIMIT TCP connections.
    """
    timestamp = int(time.time())
    connections = defaultdict(int)
    for conn in psutil.net_connections(kind='tcp'):
        if not conn.raddr:
            continue
        connections[conn.raddr.ip] += 1
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


if __name__ == '__main__':
    main()
