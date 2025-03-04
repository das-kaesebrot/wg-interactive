import os

from ..classes.wginterface import WireGuardInterface


class WireGuardHandler:

    interfaces: dict[str, WireGuardInterface] = {}
    _wireguard_config_dir: str

    WIREGUARD_CONFIG_EXTENSION = "conf"

    def __init__(self, wireguard_config_dir: str) -> None:
        self._wireguard_config_dir = wireguard_config_dir

    def refresh_interfaces(self) -> dict[str, WireGuardInterface]:
        self.interfaces = {}

        _ = []
        extension = f".{self.WIREGUARD_CONFIG_EXTENSION}"

        for file in os.listdir(self._wireguard_config_dir):
            if file.endswith(extension):
                _.append(file[: -len(extension)])

        _.sort()
        for config in _:
            self.interfaces[config] = WireGuardInterface(
                config, self._wireguard_config_dir
            )

        return self.interfaces
