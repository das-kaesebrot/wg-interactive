# wg-interactive
`wg-interactive` is a command line tool for initializing WireGuard server configuration files as well as adding and deleting peers interactively.

## Requirements
_Relevant only for the .py script file, not for the binary_
- Python 3, at least version 3.7
- Either: all pip3 packages provided by `requirements.txt`
- Or: a python virtualenv with packages from `Pipfile`

## Usage
Launch `wg-interactive.py` (or the binary) as root. The tool will prompt for all options interactively.

## Configuration options
#### Environment variables
- `WGCONFPATH`: Path to look for WireGuard config files in. If not specified, defaults to `/etc/wireguard`

## Build and install
To build the script to a binary locally and install it afterwards, you may use the Makefile.

Initialize a local python virtual environment and build the binary in there using PyInstaller:

```make```

Install the binary to path:

```sudo make install```

(This copies the compiled binary to `/usr/bin`)