import tempfile
import wgconfig
import os
from subprocess import CompletedProcess

from .wgpeer import WgInteractivePeer
from ..utility.systemd import Systemd
from ..utility.subprocesshandler import SubprocessHandler

class WireGuardInterface:
    
    ifacename = ""
    
    CMD_WG_SHOW = "show"
    CMD_WG_STRIP = "strip"
    CMD_WG_SETCONF = "setconf" # requires an additional filename argument or piping into the command
    
    iface: wgconfig.WGConfig
    iface_conf_path: str
    
    def __init__(self, ifacename: str, wireguard_basepath: str) -> None:
        self.ifacename = ifacename
        self.iface_conf_path = os.path.join(wireguard_basepath, ifacename + ".conf")
        self.iface = wgconfig.WGConfig(self.iface_conf_path)
        self.iface.read_file()
    
    def is_running(self) -> bool:        
        if self._invoke_wg_command_on_iface(self.CMD_WG_SHOW, filename=self.iface_conf_path, capture_output=True) == 0:
            return True
        return False
            
    def is_enabled_on_systemd(self) -> bool | None:
        return Systemd.check_if_wg_interface_is_enabled(self.ifacename)
        
    def reload_if_interface_is_running(self):                
        if self.is_running():
            with tempfile.NamedTemporaryFile(mode="w+") as tf:
                result = self._invoke_wg_command_on_iface(self.CMD_WG_STRIP, capture_output=True)
                tf.write(result.stdout.decode("utf-8"))
                tf.seek(0)
                self._invoke_wg_command_on_iface(self.CMD_WG_SETCONF, filename=tf.name)
                
    def add_peer_to_interface(self, peer: WgInteractivePeer):
        pass

    def _invoke_wg_command_on_iface(self, command: str, filename: str = None, silent: bool = False, capture_output: bool = False) -> CompletedProcess:
        return SubprocessHandler.invoke_command(f"wg {command} {self.ifacename}{' ' + filename if filename else ''}", silent, capture_output)
    