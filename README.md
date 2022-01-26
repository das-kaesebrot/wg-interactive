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
_Always takes precedence when also defined in config file_
- `WGCONFPATH`: Path to look for WireGuard config files in. If not specified, defaults to `/etc/wireguard`
- `WGPEERSDIR`: Absolute base path to write generated peer configurations to. See below for defaults if not defined.
#### Config file
If the script detects that it's running as a compiled binary from `/usr/bin`, it will automatically try to read the the configuration file `wg-interactive.ini` from `/etc/wg-interactive` if it exists.

To configure using the config file, uncomment the variables in `/etc/wg-interactive/wg-interactive.ini` and set a value:
```ini
[main]
# WGCONFPATH = /etc/wireguard
# WGPEERSDIR = /your/path/to/peers
```

If the script detects that it's running as a compiled binary from `/usr/bin`, it will write generated peer configuration files to `/etc/wg-interactive/peers/INTERFACENAME/PEERNAME.conf`, otherwise it will resolve the absolute path of the script and write to a subfolder using the pattern `peers/INTERFACENAME/PEERNAME.conf`.

If `WGPEERSDIR` is configured (must be an absolute path), it will use that as a base path for the pattern `WGPEERSDIR/INTERFACENAME/PEERNAME.conf`

## Build and install
To build the script to a binary locally and install it afterwards, you may use the Makefile.

Initialize a local python virtual environment:

```make init```

Build the binary in there using PyInstaller:

```make```

Install the binary to path:

```sudo make install```

(This copies the compiled binary to `/usr/bin`)