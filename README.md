# surgeprotector

Block Tor Exit traffic to flooded IP addresses via `ExitPolicy`.

An IP address is considered flooded above a certain number of TCP connections.

## Usage

Install the dependencies into a Python virtual environment via `Pipfile` or
`requirements.txt`, then run `./surgeprotector.py --help` for more information.

To automatically update your Exit instances, create a *torrc* fragment, i.e.
`touch /etc/tor/surgeprotector`, and include it in your *torrc* file(s):

```
%include /etc/tor/surgeprotector
ExitPolicy accept ...
[...]
ExitPolicy reject *:*
```

Usage example:

```bash
# Install dependencies
pipenv install

# Show "popular" IP addresses and their TCP connection counts
pipenv run ./surgeprotector.py show

# Update a torrc fragment and restart tor on changes
pipenv run ./surgeprotector.py update /etc/tor/surgeprotector 100000 -c "systemctl restart tor"
```

If you don't want to restart all of your relay instances at once, you could run
a shell script similar to this:

```bash
#!/bin/bash

# Update ExitPolicy immediately
systemctl reload tor
# Wait for reload
sleep 5
# Restart instances starting with "exit" sequentially
for i in /etc/tor/instances/exit*; do
	systemctl restart "tor@$(basename "$i")"
done
```
