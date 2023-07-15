
from ipaddress import IPv4Interface, IPv6Interface
import ipaddress
import logging


class WgInteractivePeer:
    """Class that represents a single wireguard peer (from the server's point of view)"""
    
    name: str = ""
    public_key: str = ""
    allowed_ips: list[(IPv4Interface | IPv6Interface)] = []
    
    _logger: logging.Logger
    
    def __init__(self) -> None:
        self._logger = logging.getLogger(__name__)
        pass
    
    def set_allowed_ips_from_string(self, list_of_interfaces: str):
        allowed_ips = []
        
        for iface in list_of_interfaces.split(','):
            try:
                allowed_ips.append(ipaddress.ip_interface(iface.strip(' ')))
            except ValueError as e:
                self._logger.exception("Exception occured while parsing interface string '%s'" % iface)