import ipaddress
import logging
import os

from ipaddress import IPv4Interface, IPv6Interface, IPv4Network, IPv6Network
from typing import Union
from termcolor import colored
from ..classes.wginterface import WireGuardInterface
from .systemd import Systemd
from .validation import Validation
from ..classes.wgpeer import WgInteractivePeer


class InputOutputHandler:

    PROMPT = "> "

    TEMPLATE_PEER_CONF = """[Interface]
Address = {address}
PrivateKey = {privatekey}

[Peer]
PublicKey = {publickey}
Endpoint = {endpoint}
AllowedIPs = {allowedips}
PresharedKey = {presharedkey}
{additional_options}"""

    TEMPLATE_PRETTY_PRINT_PEER = """[{index:02d}] PublicKey: {peer_key}
     AllowedIPs: {allowed_ips}
     Name: {name}
"""

    def __init__(self):
        pass

    @staticmethod
    def print_with_disclaimer(disclaimer: str, text: str):
        width = os.get_terminal_size().columns

        disclaimer = disclaimer.upper()

        padded_chars = ((width - len(disclaimer)) // 2) - 1

        # clip below 0
        padded_chars = max(padded_chars, 0)

        padded_chars_right = padded_chars

        if ((width - len(disclaimer)) % 2) == 1:
            padded_chars_right += 1

        print("#" * width)
        print("#" * padded_chars + f" {disclaimer} " + "#" * padded_chars_right)
        print("#" * width, "")
        print(text)
        print()
        print("#" * width, "")

    @staticmethod
    def pretty_print_peer_with_index(index: int, peer_key: str, peer_dict: dict):
        text = InputOutputHandler.TEMPLATE_PRETTY_PRINT_PEER.format(
            index=index,
            peer_key=peer_key,
            allowed_ips=peer_dict.get("AllowedIPs"),
            name=peer_dict.get("name"),
        )

        print(text)

    @staticmethod
    def format_peer(
        peer: WgInteractivePeer,
        server_publickey: str,
        endpoint: str,
        persistentkeepalive: bool,
    ):
        additional_options = ""

        if persistentkeepalive:
            additional_options = "PersistentKeepalive = 25"

        allowedips_str = ",".join(
            map(lambda iface: iface.compressed, peer.client_allowed_ips)
        )

        text = InputOutputHandler.TEMPLATE_PEER_CONF.format(
            address=peer.primary_ip.compressed,
            privatekey=peer.private_key,
            publickey=server_publickey,
            presharedkey=peer.preshared_key,
            endpoint=endpoint,
            allowedips=allowedips_str,
            additional_options=additional_options,
        )

        return text

    @staticmethod
    def get_str_interactively(text: str) -> str:
        print(text)
        selection = input(InputOutputHandler.PROMPT)
        return selection.strip()

    @staticmethod
    def get_interface_listen_port_interactively(
        text: str, illegal_ports: list[int]
    ) -> int:
        print(text)

        while True:
            selection = input(InputOutputHandler.PROMPT)

            try:
                selection = int(selection)

                if selection < 0 or selection > 65535:
                    raise ValueError(
                        "Port value out of range! Must be between 0 and 65535"
                    )

                if selection in illegal_ports:
                    raise ValueError("Port already in use by a different interface!")

                return selection

            except ValueError as e:
                logging.getLogger(__name__).exception("Invalid input")
                print("Please try again!\n")

    @staticmethod
    def get_endpoint_port_interactively(text: str, suggested_default: int) -> int:
        print(text)

        port_max = (2**16) - 1

        while True:
            InputOutputHandler.print_list_of_options([suggested_default])

            selection = input(InputOutputHandler.PROMPT)

            try:
                selection = int(selection)

                if selection < 0 or selection > port_max:
                    raise ValueError(
                        f"Port value out of range! Must be between 0 and {port_max}"
                    )

                if selection == 0:
                    selection = suggested_default

                return selection

            except ValueError as e:
                logging.getLogger(__name__).exception("Invalid input")
                print("Please try again!\n")

    @staticmethod
    def get_endpoint_host_interactively(
        text: str, suggested_defaults: list[str]
    ) -> str:
        print(text)

        while True:
            InputOutputHandler.print_list_of_options(suggested_defaults)

            selection = input(InputOutputHandler.PROMPT)

            try:
                try:
                    if not Validation.validate_domain(selection):
                        retval = str(ipaddress.ip_address(selection))
                    else:
                        retval = str(selection)

                    return retval
                except:
                    pass

                selection = int(selection)

                retval = suggested_defaults[selection]

                return retval

            except ValueError as e:
                logging.getLogger(__name__).exception("Invalid input")
                print("Please try again!\n")

    @staticmethod
    def get_ip_interface_interactively(
        text: str, illegal_interfaces: list[Union[IPv4Interface, IPv6Interface]]
    ) -> Union[IPv4Interface, IPv6Interface]:
        print(text)

        while True:
            selection = input(InputOutputHandler.PROMPT)

            try:
                iface = ipaddress.ip_interface(selection.strip())

                if iface in illegal_interfaces:
                    raise ValueError(
                        "IP range already in use in a different WireGuard interface!"
                    )

                print(f"Selected interface: {iface}\n")

                return iface

            except ValueError as e:
                print(e)

            print("Invalid input, please try again\n")

    @staticmethod
    def get_ip_interfaces_interactively(
        text: str, suggested_defaults: list[Union[IPv4Interface, IPv6Interface]]
    ) -> list[Union[IPv4Interface, IPv6Interface]]:
        print(text)

        while True:
            InputOutputHandler.print_list_of_options(suggested_defaults)

            selection = input(InputOutputHandler.PROMPT)

            try:
                selection = int(selection)

                retval = [suggested_defaults[selection]]

                print(f"Selected interface(s): {retval}\n")

                return retval

            except ValueError as e:
                pass

            try:
                selection_arr = selection.split(",")

                retval = []

                for entry in selection_arr:
                    retval.append(ipaddress.ip_interface(entry.strip()))

                print(f"Selected interface(s): {retval}\n")

                return retval

            except ValueError as e:
                pass

            print("Invalid input, please try again\n")

    @staticmethod
    def get_ip_networks_interactively(
        text: str, suggested_defaults: list[Union[IPv4Interface, IPv6Interface]]
    ) -> list[Union[IPv4Interface, IPv6Interface]]:
        print(text)

        while True:
            InputOutputHandler.print_list_of_options(suggested_defaults)

            selection = input(InputOutputHandler.PROMPT)

            try:
                selection = int(selection)

                retval = [suggested_defaults[selection]]

                print(f"Selected network(s): {retval}\n")

                return retval

            except ValueError as e:
                pass

            try:
                selection_arr = selection.split(",")

                retval = []

                for entry in selection_arr:
                    retval.append(ipaddress.ip_network(entry.strip()))

                print(f"Selected network(s): {retval}\n")

                return retval

            except ValueError as e:
                pass

            print("Invalid input, please try again\n")

    @staticmethod
    def get_bool(text: str, default: bool = False) -> bool:
        print(text)

        prompt = "[Y/n]"

        if not default:
            prompt = "[y/N]"

        prompt += f" {InputOutputHandler.PROMPT}"

        while True:
            selection = input(prompt)

            try:
                selection = selection.lower()

                if selection == "":
                    return default

                if selection not in ["y", "n"]:
                    raise ValueError("Input needs to be either y or n")

                return selection == "y"

            except ValueError:
                pass

    @staticmethod
    def get_list_entry_interactively(options: list):

        while True:
            selection = input(InputOutputHandler.PROMPT)

            try:
                selection = int(selection)

                retval = options[selection]

                return retval

            except ValueError as e:
                logging.getLogger(__name__).exception("Invalid input")
                print("Please try again!\n")

    @staticmethod
    def print_list_of_options(opts: list) -> None:
        for index, value in enumerate(opts):
            print("[%i] %s" % (index, value))

    @staticmethod
    def print_interface_status(iface: WireGuardInterface, systemd_active: bool) -> None:
        if iface.is_running():
            print(
                f"{colored(iface.ifacename, attrs=['bold'])} is {colored('active', color='green')}. Auto reload after changes enabled."
            )
        else:
            print(
                f"{colored(iface.ifacename, attrs=['bold'])} is {colored('not active', color='red')}. Skipping auto reload after changes are made."
            )

        if systemd_active:
            if iface.is_enabled_on_systemd():
                print(
                    f"Service {colored(f'{Systemd.WG_QUICK_SERVICE}@{iface.ifacename}', attrs=['bold'])} is {colored('enabled', color='green')}"
                )
            else:
                print(
                    f"Service {colored(f'{Systemd.WG_QUICK_SERVICE}@{iface.ifacename}', attrs=['bold'])} is {colored('not enabled', color='red')}"
                )
        else:
            print(f"Seems like host doesn't use systemd, skipping check for service")

    @staticmethod
    def get_next_free_ips(
        iface: WireGuardInterface,
    ) -> list[Union[IPv4Interface, IPv6Interface]]:
        # 255.255.255.255 as an int
        netmask_v4 = ipaddress.ip_address((2**32) - 1)
        netmask_v6 = ipaddress.ip_address((2**128) - 1)

        suggestion_count = 3

        free_ips = []

        server_addresses = iface.iface.interface.get("Address")

        if isinstance(server_addresses, str):
            server_addresses = [server_addresses]

        for server_address in server_addresses:
            server_address = ipaddress.ip_interface(server_address)

            server_network = server_address.network
            possible_ips = list(server_network.hosts())

            possible_ips.remove(server_address.ip)

            for peer in iface.iface.peers.values():
                allowed_ips = peer.get("AllowedIPs")

                if not allowed_ips:
                    continue

                if isinstance(allowed_ips, str):
                    allowed_ips = [allowed_ips]

                for allowed_ip in allowed_ips:
                    try:
                        ip = ipaddress.ip_interface(allowed_ip).ip
                        possible_ips.remove(ip)

                    except ValueError:
                        continue

            if len(possible_ips) != 0:
                for ip in possible_ips:
                    if not (
                        ip.is_reserved
                        or ip.is_multicast
                        or ip.is_link_local
                        or ip.is_loopback
                    ):
                        netmask = netmask_v4
                        if ip.version == 6:
                            netmask = netmask_v6

                        new_ip = ipaddress.ip_interface(f"{ip}/{netmask}")
                        free_ips.append(new_ip)

                        suggestion_count -= 1

                        if suggestion_count <= 0:
                            break

        return free_ips

    @staticmethod
    def get_peer_recommended_allowed_ips(
        iface: WireGuardInterface,
    ) -> list[Union[IPv4Interface, IPv6Interface]]:
        suggested_networks = []

        server_addresses = iface.iface.interface.get("Address")

        if isinstance(server_addresses, str):
            server_addresses = [server_addresses]

        for server_address in server_addresses:
            server_address = ipaddress.ip_interface(server_address)

            suggested_networks.append(server_address.network)

        return suggested_networks
