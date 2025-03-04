import sys
import os
import logging
from termcolor import colored
import argparse
from sys import version_info

from . import __version__
from .utility.clihandler import CliHandler


def main():
    # set up logging config via argparse
    # custom behaviour for python versions < 3.11 as the level names mapping func was only added to the logging lib in 3.11
    if version_info[1] >= 11:
        loglevel_mapping = logging.getLevelNamesMapping().keys()
    else:
        loglevel_mapping = logging._nameToLevel.keys()

    available_levels = [level.lower() for level in loglevel_mapping]
    available_levels.remove(logging.getLevelName(logging.NOTSET).lower())
    available_levels.remove(logging.getLevelName(logging.WARNING).lower())

    parser = argparse.ArgumentParser(
        description="An interactive command line tool for modifying and initializing WireGuard server configuration files and adding/deleting peers.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "-l",
        "--logging",
        help="Set the log level",
        dest="loglevel",
        type=str,
        choices=available_levels,
        default=logging.getLevelName(logging.INFO).lower(),
    )

    parser.add_argument(
        "-d",
        "--directory",
        help="WireGuard config directory",
        type=str,
        required=False,
        default="/etc/wireguard",
    )

    args = parser.parse_args()

    logging.basicConfig(
        format="[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s",
        level=args.loglevel.upper(),
    )
    logger = logging.getLogger(__name__)

    try:
        # Check if program is being run as root
        if not os.geteuid() == 0:
            logger.error("Has to run as root")
            sys.exit(1)

        versionstr = __version__

        banner = f"""{colored(f'wg-interactive v{versionstr}', attrs=['bold'])}

An interactive command line tool for modifying and initializing WireGuard server configuration files and adding/deleting peers.
"""

        print(banner)

        handler = CliHandler(args.directory)
        handler.handle()

    except NotImplementedError as e:
        logger.exception("Not implemented yet")
        sys.exit(0)

    except EOFError or KeyboardInterrupt:
        print()
        logger.info("Detected keyboard interrupt or EOF. Aborting.")
        sys.exit(0)

    except Exception as e:
        logger.exception("Unhandled exception occured")
        sys.exit(1)


if __name__ == "__main__":
    main()
