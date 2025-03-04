import ipaddress
from typing import Optional
import netifaces
import os

from ipaddress import IPv4Address, IPv6Address


class ServerInfo:

    def __init__(self) -> None:
        pass

    @staticmethod
    def get_hostname() -> Optional[str]:
        hostname = os.uname().nodename

        # Assume that if the nodename contains a dot, it probably is a fully qualified hostname
        if "." in hostname:
            return hostname

        return None

    @staticmethod
    def get_public_ipv4() -> Optional[IPv4Address]:
        for iface in netifaces.interfaces():
            ifaddresses = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in ifaddresses.keys():
                for addr in ifaddresses[netifaces.AF_INET]:
                    address_str = addr.get("addr")

                    # work around bug from the netifaces library which sometimes appends the interface name to an IP
                    if "%" in address_str:
                        address_str = address_str.split("%")[0]

                    address = ipaddress.ip_address(address_str)

                    if address.is_global:
                        return address

        return None

    @staticmethod
    def get_public_ipv6() -> Optional[IPv6Address]:
        for iface in netifaces.interfaces():
            ifaddresses = netifaces.ifaddresses(iface)
            if netifaces.AF_INET6 in ifaddresses.keys():
                for addr in ifaddresses[netifaces.AF_INET6]:
                    address_str = addr.get("addr")

                    # work around bug from the netifaces library which sometimes appends the interface name to an IP
                    if "%" in address_str:
                        address_str = address_str.split("%")[0]

                    address = ipaddress.ip_address(address_str)

                    if address.is_global:
                        return address

        return None

    @staticmethod
    def _get_recommended_endpoint_hosts() -> list[str]:
        retlist = []

        hostname = ServerInfo.get_hostname()
        public_ipv4 = ServerInfo.get_public_ipv4()
        public_ipv6 = ServerInfo.get_public_ipv6()

        if hostname:
            retlist.append(hostname)
        if public_ipv4:
            retlist.append(public_ipv4.compressed)
        if public_ipv6:
            retlist.append(public_ipv6.compressed)

        return retlist
