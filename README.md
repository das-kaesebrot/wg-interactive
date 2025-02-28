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

## License Attribution

This application uses Open Source components. You can find the source code of their open source projects along with license information below. We acknowledge and are grateful to these developers for their contributions to open source.

[WireGuard](https://www.wireguard.com/) is a registered trademark of Jason A. Donenfeld.

### [wgconfig](https://github.com/towalink/wgconfig)
- Copyright (c) 2020-2025 [Dirk Henrici](https://github.com/towalink).
- [AGPL3 license](https://opensource.org/licenses/AGPL-3.0)

### [termcolor](https://github.com/termcolor/termcolor)
- Copyright (c) 2008-2011 Volvox Development Team.
- [MIT license](https://github.com/termcolor/termcolor/blob/main/COPYING.txt)

### [netifaces-2](https://github.com/SamuelYvon/netifaces-2)
- Copyright (c) 2022 Samuel Yvon.
- [MIT license](https://github.com/SamuelYvon/netifaces-2/blob/dev/LICENSE)
