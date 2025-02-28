# wg-interactive
[![Upload Python Package](https://github.com/das-kaesebrot/wg-interactive/actions/workflows/python-publish.yml/badge.svg)](https://github.com/das-kaesebrot/wg-interactive/actions/workflows/python-publish.yml)

`wg-interactive` is a command line tool for initializing WireGuard server configuration files as well as adding and deleting peers interactively.

## Installation

Install the module from [PyPI](https://pypi.org/project/wg-interactive/):
```bash
pip install wg-interactive
```

## Usage
Launch wg-interactive via the included command `wg-interactive`.

```
usage: wg-interactive [-h] [-l {critical,fatal,error,warn,info,debug}] [-d DIRECTORY]

An interactive command line tool for modifying and initializing WireGuard server configuration files and adding/deleting peers.

options:
  -h, --help            show this help message and exit
  -l {critical,fatal,error,warn,info,debug}, --logging {critical,fatal,error,warn,info,debug}
                        Set the log level (default: info)
  -d DIRECTORY, --directory DIRECTORY
                        WireGuard config directory (default: /etc/wireguard)
```

## Build and install
Initialize a local python virtual environment:

```bash
mkdir .venv
pipenv install
```

Then build the package:

```bash
pipenv shell
python -m build
```
