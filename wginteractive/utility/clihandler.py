import ipaddress
import os
import re
import logging
import ipaddress
from termcolor import colored

from ..classes.wgpeer import WgInteractivePeer
from ..utility.wghandler import WireGuardHandler, WireGuardInterface
from .iohandler import InputOutputHandler
from ..utility.systemd import Systemd
from ..utility.serverinfo import ServerInfo
from ..enums.clihandler_action import CliHandlerAction


class CliHandler:
    USE_SYSTEMD: bool = False

    ACTIONS_MENU_ROOT = {
        CliHandlerAction.INIT_NEW_IFACE: "Initialize a new interface",
    }

    ACTIONS_MENU = {
        CliHandlerAction.ADD: "Add peer",
        CliHandlerAction.LIST: "List all peers and return to this menu",
        CliHandlerAction.RENAME: "Rename peer",
        CliHandlerAction.NEWKEY_CLIENT: "Generate new keypair for peer",
        CliHandlerAction.NEWPSK: "Generate new preshared key between peer and server",
        CliHandlerAction.DELETE: "Delete peer",
        CliHandlerAction.FLIP_SYSTEMD: "Flip enabled state for wg-quick systemd service",
        CliHandlerAction.GO_UP: "Go back to previous menu",
    }

    TEXT_CLIENT_ENDPOINT_PORT = f"""{colored('Endpoint port', attrs=['bold'])}
Please select an endpoint port to use or input your own:"""

    TEXT_CLIENT_ENDPOINT_HOST = f"""{colored('Endpoint host', attrs=['bold'])}
Since it is not required for a WireGuard server to read its own endpoint domain/IP from the config file, this script needs to provide that value.
Please select an endpoint host (this server's IP or a FQDN pointing to it) to use in the peer's config file or input your own.
Examples for valid own inputs:
vpn.example.com
11.22.33.44
Please don't append the port, this will be done automatically!"""

    TEXT_SERVER_ALLOWEDIPS = f"""{colored('AllowedIPs (Server config)', attrs=['bold'])}
Please select a recommended address or give your own (comma-separated for multiple ranges):"""

    TEXT_CLIENT_ADDRESS = f"""{colored('Address (Client config)', attrs=['bold'])}
For the peer sided config - defines the primary IP and subnet for the client.
Please select a recommended address or give your own (comma-separated for multiple ranges):"""

    TEXT_CLIENT_ALLOWEDIPS = f"""{colored('AllowedIPs (Client config)', attrs=['bold'])}
For the peer sided config - defines which network ranges the peer is allowed to access.
Be aware that a user may change this in their config at any time.
Please select a range of AllowedIPs or give your own (comma-separated for multiple ranges):"""

    TEXT_SERVER_PEER_NAME = f"""{colored('Peer name', attrs=['bold'])}
Please input the peer's name:"""

    TEXT_RENAME_NEW_NAME = "Please give a new name for the peer:"

    TEXT_CLIENT_PERSISTENT_KEEPALIVE = (
        "Add 'PersistentKeepalive = 25' to client config?"
    )

    _wghandler: WireGuardHandler
    _wginterfaces: dict[str, WireGuardInterface]

    _logger: logging.Logger
    
    _wireguard_config_dir: str

    def __init__(self, wireguard_config_dir: str) -> None:
        self._logger = logging.getLogger(__name__)
        self._wireguard_config_dir = wireguard_config_dir
        self._wghandler = WireGuardHandler(self._wireguard_config_dir)
        self._refresh_interfaces()

        counter = 0
        for iface in self._wginterfaces.keys():
            self.ACTIONS_MENU_ROOT[str(counter)] = iface
            counter += 1

        self.USE_SYSTEMD = Systemd.host_is_using_systemd()

        if not self.USE_SYSTEMD:
            self.ACTIONS_MENU.pop(CliHandlerAction.FLIP_SYSTEMD)

    def _refresh_interfaces(self):
        self._wginterfaces = self._wghandler.get_interfaces()

    def handle(self) -> None:
                
        while True:
            iface_or_init = self._get_initial_interface_or_action_and_validate()

            if iface_or_init.strip().lower() == CliHandlerAction.INIT_NEW_IFACE:
                if self._create_new_interface():
                    print("Successfully created new interface!")
                return

            iface_or_init = int(iface_or_init)

            wginterface_key = list(self._wginterfaces)[int(iface_or_init)]
            wginterface = self._wginterfaces.get(wginterface_key)

            InputOutputHandler._print_interface_status(wginterface, self.USE_SYSTEMD)
            
            done = False
                    
            while not done:
                done = True
                interface_action = self._get_action_for_interface_and_validate()

                if interface_action == CliHandlerAction.ADD:
                    self._get_new_peer_interactively(wginterface)

                elif interface_action == CliHandlerAction.LIST:
                    self._pretty_print_peers(wginterface)
                    done = False

                elif interface_action == CliHandlerAction.RENAME:
                    self._rename_peer_interactively(wginterface)

                elif interface_action == CliHandlerAction.NEWKEY_CLIENT:
                    self._regenerate_keypair_interactively(wginterface)

                elif interface_action == CliHandlerAction.NEWPSK:
                    self._regenerate_psk_interactively(wginterface)

                elif interface_action == CliHandlerAction.DELETE:
                    self._delete_peer_interactively(wginterface)

                # unreachable if systemd is disabled
                elif interface_action == CliHandlerAction.FLIP_SYSTEMD:
                    print(f"Flipping enabled status for '{wginterface.ifacename}'")
                    wginterface.flip_systemd_status()
                    
                elif interface_action == CliHandlerAction.GO_UP:
                    done = True

    def _create_new_interface(self) -> WireGuardInterface:
        os.makedirs(name=self._wireguard_config_dir, mode=0o600, exist_ok=True)

        illegal_names = list(self._wginterfaces.keys())
        illegal_interfaces = list(
            map(
                lambda iface: iface.get_server_ip_interface(),
                self._wginterfaces.values(),
            )
        )
        illegal_ports = list(
            map(lambda iface: iface.get_listen_port(), self._wginterfaces.values())
        )
        illegal_ports = [
            port for port in illegal_ports if port is not None
        ]  # filter out none values

        iface_name = self._get_interface_name_and_validate(
            f"Please enter an intercae name for the new interface:\nIllegal names: {illegal_names}",
            illegal_names=illegal_names,
        )
        print(f"Selected interface name: '{iface_name}'\n")

        iface_ip_interface = InputOutputHandler._get_ip_interface_interactively(
            f"Please enter an IP address and subnet for the new interface:\nIllegal interfaces: {illegal_interfaces}",
            illegal_interfaces=illegal_interfaces,
        )
        print(f"Selected ip address: '{iface_ip_interface}'\n")

        iface_port = InputOutputHandler._get_interface_listen_port_interactively(
            f"Please enter a listen port for the new interface:\nIllegal ports: {illegal_ports}",
            illegal_ports=illegal_ports,
        )
        print(f"Selected listen port: {iface_port}\n")

        print(
            f"Creating new WireGuard interface at '{os.path.join(self._wireguard_config_dir, iface_name + '.conf')}'"
        )

        return WireGuardInterface.create_new(
            wireguard_basepath=self._wireguard_config_dir,
            ifacename=iface_name,
            address=iface_ip_interface,
            listen_port=iface_port,
        )

    def _get_initial_interface_or_action_and_validate(self) -> str:

        print("Please select an interface to modify or initialize a new interface:")

        while True:
            for k, v in self.ACTIONS_MENU_ROOT.items():
                print("[%s] %s" % (k, v))

            selection = input(InputOutputHandler.PROMPT)

            if selection in self.ACTIONS_MENU_ROOT.keys():
                print(
                    f"Selected operation/interface: {self.ACTIONS_MENU_ROOT.get(selection)}\n"
                )
                return selection

            print("Invalid input, please try again\n")

    def _get_interface_name_and_validate(
        self, text: str, illegal_names: list[str]
    ) -> str:
        while True:
            iface_name = InputOutputHandler._get_str_interactively(text)

            if iface_name in illegal_names:
                print("Interface name already taken, please choose another name!\n")
                continue

            if not re.match(r"^[a-zA-Z0-9_=+.-]{1,15}$", iface_name):
                print("Invalid input, please try again\n")
                continue

            return iface_name

    def _get_action_for_interface_and_validate(self) -> str:

        print("Please select an operation to perform:")

        while True:
            for k, v in self.ACTIONS_MENU.items():
                print("[%s] %s" % (k, v))

            selection = input(InputOutputHandler.PROMPT)

            if selection in self.ACTIONS_MENU.keys():
                print(
                    f"Selected operation: {self.ACTIONS_MENU.get(selection)}\n"
                )
                return selection

            print("Invalid input, please try again\n")

    def _pretty_print_peers(self, iface: WireGuardInterface):
        print(
            f"Peers in WireGuard interface {colored(iface.ifacename, attrs=['bold'])}:"
        )

        peers = iface.get_peers_with_name()
        index = 0
        for peer_key, peer in peers.items():
            InputOutputHandler._pretty_print_peer_with_index(index, peer_key, peer)
            index += 1

    def _rename_peer_interactively(self, iface: WireGuardInterface):
        peer_key = self._get_existing_peer_interactively(iface)
        name = InputOutputHandler._get_str_interactively(self.TEXT_RENAME_NEW_NAME)

        iface.rename_peer(peer_key, name)

    def _delete_peer_interactively(self, iface: WireGuardInterface):
        peer_key = self._get_existing_peer_interactively(iface)
        iface.delete_peer(peer_key)

    def _regenerate_keypair_interactively(self, iface: WireGuardInterface):
        peer_key = self._get_existing_peer_interactively(iface)
        peer_privatekey = iface.regenerate_peer_keypair(peer_key)

        InputOutputHandler._print_with_disclaimer(
            disclaimer="NEW PRIVATE KEY, VALUE WON'T BE SHOWN AGAIN",
            text=peer_privatekey,
        )

    def _regenerate_psk_interactively(self, iface: WireGuardInterface):
        peer_key = self._get_existing_peer_interactively(iface)
        presharedkey = iface.regenerate_presharedkey(peer_key)

        InputOutputHandler._print_with_disclaimer(disclaimer="NEW PRESHARED KEY", text=presharedkey)

    def _get_new_peer_interactively(self, iface: WireGuardInterface):
        clientside_endpoint_port = InputOutputHandler._get_endpoint_port_interactively(
            self.TEXT_CLIENT_ENDPOINT_PORT, int(iface.iface.interface.get("ListenPort"))
        )
        clientside_endpoint_host = InputOutputHandler._get_endpoint_host_interactively(
            self.TEXT_CLIENT_ENDPOINT_HOST, ServerInfo._get_recommended_endpoint_hosts()
        )

        width = os.get_terminal_size().columns

        # wrap host in square brackets if it's an IPv6 address
        try:
            if ipaddress.ip_address(clientside_endpoint_host).version == 6:
                clientside_endpoint_host = f"[{clientside_endpoint_host}]"

        except ValueError:
            pass

        clientside_endpoint = f"{clientside_endpoint_host}:{clientside_endpoint_port}"

        print(f"Selected endpoint: {colored(clientside_endpoint, attrs=['bold'])}\n")

        serverside_peername = InputOutputHandler._get_str_interactively(self.TEXT_SERVER_PEER_NAME)

        serverside_allowedips = InputOutputHandler._get_ip_interfaces_interactively(
            self.TEXT_SERVER_ALLOWEDIPS, InputOutputHandler._get_next_free_ips(iface)
        )
        clientside_allowedips = InputOutputHandler._get_ip_networks_interactively(
            self.TEXT_CLIENT_ALLOWEDIPS, InputOutputHandler._get_peer_recommended_allowed_ips(iface)
        )

        client_ip = serverside_allowedips[0]

        clientside_persistentkeepalive = InputOutputHandler._get_bool(
            self.TEXT_CLIENT_PERSISTENT_KEEPALIVE, True
        )

        peer = WgInteractivePeer(
            serverside_allowedips, clientside_allowedips, client_ip, serverside_peername
        )

        server_pubkey = iface.get_publickey()

        iface.add_peer_to_interface(peer)

        InputOutputHandler._print_with_disclaimer(
            disclaimer="GENERATED PEER CONFIG, PRIVATE KEY WON'T BE SHOWN AGAIN",
            text=InputOutputHandler._format_peer(
                peer, server_pubkey, clientside_endpoint, clientside_persistentkeepalive
            ),
        )

    def _get_existing_peer_interactively(self, iface: WireGuardInterface) -> str:
        self._pretty_print_peers(iface)
        return InputOutputHandler._get_list_entry_interactively(
            [*iface.get_peers_with_name().items()]
        )[0]
