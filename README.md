# wg-interactive
`wg-interactive` is a command line tool for initializing WireGuard server configuration files as well as adding and deleting peers interactively.

## Requirements
- Python 3, at least version 3.9
- Either: all pip3 packages provided by `requirements.txt`
- Or: a python virtualenv with packages from `Pipfile`

## Usage
Launch `wg-interactive.py` as root. The tool will prompt for all options interactively.

## Configuration options
#### Environment variables
- `WGCONFPATH`: Path to look for WireGuard config files in. If not specified, defaults to `/etc/wireguard`