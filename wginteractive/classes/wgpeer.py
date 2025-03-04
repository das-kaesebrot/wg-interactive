from ipaddress import IPv4Interface, IPv6Interface, IPv4Network, IPv6Network
from typing import Union
from wgconfig import wgexec
import ipaddress
import logging


class WgInteractivePeer:
    """Class that represents a single wireguard peer (from the server's point of view)"""

    name: str = "Unnamed Peer"
    server_allowed_ips: list[Union[IPv4Interface, IPv6Interface, None]] = []
    client_allowed_ips: list[Union[IPv4Interface, IPv6Interface, None]] = []
    primary_ip: Union[IPv4Interface, IPv6Interface, None] = None
    private_key: str = None
    public_key: str = None
    preshared_key: str = None

    _logger: logging.Logger

    def __init__(
        self,
        server_allowed_ips: list[Union[IPv4Interface, IPv6Interface, None]],
        client_allowed_ips: list[Union[IPv4Interface, IPv6Interface, None]],
        primary_ip: Union[IPv4Interface, IPv6Interface, None] = None,
        name: str = None,
    ) -> None:
        if name:
            self.name = name

        self.server_allowed_ips = server_allowed_ips
        self.client_allowed_ips = client_allowed_ips
        self.primary_ip = primary_ip

        self._logger = logging.getLogger(__name__)

        self.private_key, self.public_key = wgexec.generate_keypair()
        self.preshared_key = wgexec.generate_presharedkey()

    def set_allowed_ips_from_string(self, list_of_interfaces: str):
        allowed_ips = []

        for iface in list_of_interfaces.split(","):
            try:
                allowed_ips.append(ipaddress.ip_interface(iface.strip(" ")))
            except ValueError as e:
                self._logger.exception(
                    "Exception occured while parsing interface string '%s'" % iface
                )
