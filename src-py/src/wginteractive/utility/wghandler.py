import os

from ..classes.wginterface import WireGuardInterface
from ..classes.config import Config

class WireGuardHandler:
    
    interfaces: dict[str, WireGuardInterface] = {}
    _config: Config = None
    
    WIREGUARD_CONFIG_EXTENSION = "conf"
    
    def __init__(self, config: Config) -> None:
        self._config = config
        
    def get_interfaces(self) -> dict[str, WireGuardInterface]:        
        if not self.interfaces:
            _ = []
            extension = f".{self.WIREGUARD_CONFIG_EXTENSION}"
            
            for file in os.listdir(self._config.wireguard_conf_dir):
                if file.endswith(extension):
                    _.append(file[:-len(extension)])
            
            _.sort()
            for config in _:
                self.interfaces[config] = WireGuardInterface(config)
        
        return self.interfaces
