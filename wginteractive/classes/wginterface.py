from ipaddress import IPv4Interface, IPv6Interface, ip_interface
import tempfile
import wgconfig
from wgconfig import wgexec
import os
from subprocess import CompletedProcess
import logging

from .wgpeer import WgInteractivePeer
from ..utility.systemd import Systemd
from ..utility.subprocesshandler import SubprocessHandler


class WireGuardInterface:

    ifacename = ""

    CMD_WG_SHOW = "show"
    CMD_WG_STRIP = "strip"
    CMD_WG_SETCONF = (
        "setconf"  # requires an additional filename argument or piping into the command
    )

    iface: wgconfig.WGConfig
    iface_conf_path: str
    
    _publickey: str

    def __init__(self, ifacename: str, wireguard_basepath: str) -> None:
        self.ifacename = ifacename
        self.iface_conf_path = os.path.join(wireguard_basepath, ifacename + ".conf")
        self.iface = wgconfig.WGConfig(self.iface_conf_path)
        self.iface.read_file()
        self._logger = logging.getLogger(self.ifacename)
        
        self._publickey = wgexec.get_publickey(self.iface.interface.get("PrivateKey"))

    def is_running(self) -> bool:
        if (
            self._invoke_wg_command_on_iface(
                self.CMD_WG_SHOW, filename=self.iface_conf_path, capture_output=True
            )
            == 0
        ):
            return True
        return False

    def is_enabled_on_systemd(self) -> bool | None:
        return Systemd.wg_interface_is_enabled(self.ifacename)
    
    def flip_systemd_status(self):
        Systemd.flip_wg_interface_enabled_status(self.ifacename)

    def get_publickey(self) -> str:
        return wgexec.get_publickey(self.iface.interface.get("PrivateKey"))

    def get_server_ip_interface(self) -> IPv4Interface | IPv6Interface:
        return ip_interface(self.iface.interface.get("Address"))

    def get_listen_port(self) -> int | None:
        listenport_str = self.iface.interface.get("ListenPort")

        if listenport_str:
            return int(listenport_str)

        return None

    def reload_if_interface_is_running(self):
        if self.is_running():
            with tempfile.NamedTemporaryFile(mode="w+") as tf:
                result = self._invoke_wg_command_on_iface(
                    self.CMD_WG_STRIP, capture_output=True
                )
                tf.write(result.stdout.decode("utf-8"))
                tf.seek(0)
                self._invoke_wg_command_on_iface(self.CMD_WG_SETCONF, filename=tf.name)

    def add_peer_to_interface(self, peer: WgInteractivePeer):
        allowedips_str = ",".join(
            map(lambda iface: iface.compressed, peer.client_allowed_ips)
        )

        self.iface.add_peer(peer.public_key, f"# {peer.name}")
        self.iface.add_attr(peer.public_key, "AllowedIPs", allowedips_str)
        self.iface.add_attr(peer.public_key, "PresharedKey", peer.preshared_key)
        self._save()
        
    def get_peers_with_name(self):
        peers = {}
        
        for peer_key in self.iface.peers.keys():
            peers[peer_key] = self.get_peer_with_name(peer_key)
            
        return peers
    
    def get_peer_with_name(self, peer_key: str) -> dict:
        peer = self.iface.get_peer(peer_key, include_details=True)
        
        name = None
            
        for entry in peer.get('_rawdata'):
            if entry.startswith('#') and len(entry) > 2:
                name = entry[2:]
            
        peer["name"] = name
        
        return peer
    
    def rename_peer(self, peer_key: str, name: str):
        peer = self.iface.get_peer(peer_key, include_details=False)
        
        self.iface.del_peer(peer_key)
        self.iface.add_peer(key=peer_key, leading_comment=f"# {name}")
        
        for attr, value in peer.items():
            if attr == "PublicKey":
                continue
            
            self.iface.add_attr(key=peer_key, attr=attr, value=value)
        
        self._save()
        
    
    def delete_peer(self, peer_key: str):
        self.iface.del_peer(peer_key)
        self._save()
        

    def _save(self):
        self.iface.write_file(self.iface_conf_path)
        self.reload_if_interface_is_running()

    def _invoke_wg_command_on_iface(
        self,
        command: str,
        filename: str = None,
        silent: bool = False,
        capture_output: bool = False,
    ) -> CompletedProcess:
        return SubprocessHandler.invoke_command(
            f"wg {command} {self.ifacename}{' ' + filename if filename else ''}",
            silent,
            capture_output,
        )

    @staticmethod
    def create_new(
        *,
        wireguard_basepath: str,
        ifacename: str,
        address: IPv4Interface | IPv6Interface,
        listen_port: int,
    ):
        iface_conf_path = os.path.join(wireguard_basepath, ifacename + ".conf")
        iface = wgconfig.WGConfig(iface_conf_path)
        privkey = wgexec.generate_privatekey()
        iface.initialize_file()
        iface.add_attr(key=None, attr="Address", value=address)
        iface.add_attr(key=None, attr="ListenPort", value=listen_port)
        iface.add_attr(key=None, attr="PrivateKey", value=privkey)
        iface.write_file(iface_conf_path)

        return WireGuardInterface(
            ifacename=ifacename, wireguard_basepath=wireguard_basepath
        )
