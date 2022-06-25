from subprocess import CompletedProcess
from utility.systemd import Systemd
from utility.subprocesshandler import SubprocessHandler
from termcolor import colored

class WireGuardHandler:
    
    ifacename = ""
    
    CMD_WG_SHOW = "show"
    
    def __init__(self, ifacename: str) -> None:
        self.ifacename = ifacename
    
    def check_if_interface_is_running(self):        
        if self._invoke_wg_command_on_iface(self.CMD_WG_SHOW, True) == 0:
            print(f"{colored(self.ifacename, attrs=['bold'])} is {colored('active', color='green')}. Auto reload after changes enabled.")
        else:
            print(f"{colored(self.ifacename, attrs=['bold'])} is {colored('not active', color='red')}. Skipping auto reload after changes are made.")
            
    def check_if_wg_interface_is_enabled_on_systemd(self) -> bool | None:
        # Check if host is using systemd
        if Systemd.check_if_host_is_using_systemd(self.ifacename):
            if Systemd.check_if_wg_interface_is_enabled():
                print(f"Service {colored(f'wg-quick@{self.ifacename}', attrs=['bold'])} is {colored('enabled', color='green')}")
                return True
            else:
                print(f"Service {colored(f'wg-quick@{self.ifacename}', attrs=['bold'])} is {colored('not enabled', color='red')}")
                return False
        else:
            print(f"Seems like host doesn't use systemd, skipping check for service")
            return None
    
    def _invoke_wg_command_on_iface(self, command: str, silent: bool = False) -> tuple[int, CompletedProcess]:
        return SubprocessHandler.invoke_command(f"wg {command} {self.ifacename}", silent)
    