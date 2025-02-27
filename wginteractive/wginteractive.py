import sys
import os
import logging
from termcolor import colored

from ._version import __version__
from .utility.clihandler import CliHandler


def main():
    logging.basicConfig(
        format="[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s",
        level=logging.DEBUG,
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

        handler = CliHandler()
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
