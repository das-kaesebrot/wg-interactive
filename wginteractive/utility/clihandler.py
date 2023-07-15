import ipaddress
import readline
import logging
from ipaddress import IPv4Interface, IPv6Interface
from termcolor import colored

from ..classes.config import Config
from ..utility.wghandler import WireGuardHandler, WireGuardInterface

class CliHandler:
    USE_SYSTEMD: bool = False

    PROMPT = "> "

    ACTION_INIT_NEW_IFACE = 'i' # unused

    ACTIONS_MENU_ROOT = {
            ACTION_INIT_NEW_IFACE:
            {
                'desc': 'Initialize a new interface'
            }
        }

    ACTION_ADD = 'a'
    ACTION_LIST = 'l'
    ACTION_RENAME = 'r'
    ACTION_NEWKEY_CLIENT = 'k'
    ACTION_NEWKEY_SERVER = 'ks' # unused
    ACTION_DELETE = 'd'
    ACTION_FLIP_SYSTEMD = 's'

    ACTIONS_MENU = {
            ACTION_ADD:
            {
                'desc': 'Add peer'
            },
            ACTION_LIST:
            {
                'desc': 'List all peers and return to this menu'
            },
            ACTION_RENAME:
            {
                'desc': 'Rename peer'
            },
            ACTION_NEWKEY_CLIENT:
            {
                'desc': 'Generate new keypair for peer'
            },
            ACTION_DELETE:
            {
                'desc': 'Delete peer',
            },
            ACTION_FLIP_SYSTEMD:
            {
                'desc': 'Flip enabled state for wg-quick systemd service',
            }
        }
    
    TEXT_SERVER_ALLOWEDIPS = f"""{colored('AllowedIPs (Server config)', attrs=['bold'])}
Please select a recommended address or give your own (comma-separated for multiple ranges):"""

    TEXT_CLIENT_ADDRESS = f"""{colored('Address (Client config)', attrs=['bold'])}
For the peer sided config - defines the primary IP and subnet for the client.
Please select a recommended address or give your own (comma-separated for multiple ranges):"""
    
    TEXT_CLIENT_ALLOWEDIPS = f"""{colored('AllowedIPs (Client config)', attrs=['bold'])}
For the peer sided config - defines which network ranges the peer is allowed to access.
Be aware that a user may change this in their config at any time.
Please select a range of AllowedIPs or give your own (comma-separated for multiple ranges):"""

    _wghandler: WireGuardHandler
    _wginterfaces: dict[str, WireGuardInterface]
    
    def __init__(self, is_using_systemd = False) -> None:
        config = Config()
        self._wghandler = WireGuardHandler(config)
        self._wginterfaces = self._wghandler.get_interfaces()
        
        counter = 0
        for iface in self._wginterfaces.keys():
            self.ACTIONS_MENU_ROOT[str(counter)] = { 'desc' :iface }
            counter += 1

        self.USE_SYSTEMD = is_using_systemd

        if not self.USE_SYSTEMD:
            self.ACTIONS_MENU.pop(CliHandler.ACTION_FLIP_SYSTEMD)
        

    def handle(self) -> None:

        iface_or_init = self._get_initial_interface_or_action_and_validate()

        if (iface_or_init == self.ACTION_INIT_NEW_IFACE):
            raise NotImplementedError("Not supported yet")
        
        iface_or_init = int(iface_or_init)
        
        wginterface_key = list(self._wginterfaces)[int(iface_or_init)]
        wginterface = self._wginterfaces.get(wginterface_key)
        wginterface.check_if_interface_is_running()
        if (self.USE_SYSTEMD): wginterface.check_if_wg_interface_is_enabled_on_systemd()
        
        interface_action = self._get_action_for_interface_and_validate()
        
        if interface_action == self.ACTION_ADD:
            self._get_new_peer_interactively(wginterface)
            
        elif interface_action == self.ACTION_RENAME:
            # renamePeerInInterface(wc, selectedWGName, absWGPath)
            pass
            
        elif interface_action == self.ACTION_NEWKEY_CLIENT:
            # regeneratePeerPublicKey(wc, selectedWGName, absWGPath)
            pass
        
        elif interface_action == self.ACTION_DELETE:
            # deletePeerFromInterface(wc, selectedWGName, absWGPath)
            pass
        
        elif interface_action == self.ACTION_FLIP_SYSTEMD:
            # Systemd.flip_enabled_status(selectedWGName)
            pass
    
        
    def _get_initial_interface_or_action_and_validate(self) -> str:

        print("Please select an interface to modify or initialize a new interface:")
        
        while True:
            for k, v in self.ACTIONS_MENU_ROOT.items():
                print("[%c] %s" % (k, v.get('desc')))
                
            selection = input(CliHandler.PROMPT)

            if selection in self.ACTIONS_MENU_ROOT.keys():
                print(f"Selected operation/interface: {self.ACTIONS_MENU_ROOT.get(selection).get('desc')}\n")
                return selection

            print("Invalid input, please try again\n")

    def _get_action_for_interface_and_validate(self) -> str:

        print("Please select an operation to perform:")

        while True:
            for k, v in self.ACTIONS_MENU.items():
                print("[%c] %s" % (k, v.get('desc')))

            selection = input(CliHandler.PROMPT)

            if selection in self.ACTIONS_MENU.keys():
                print(f"Selected operation: {self.ACTIONS_MENU.get(selection).get('desc')}\n")
                return selection
            
            print("Invalid input, please try again\n")
        
        
    def _get_new_peer_interactively(self, iface: WireGuardInterface):
        clientside_endpoint_port = self._get_endpoint_port_interactively(int(iface.iface.get('ListenPort')))
        clientside_endpoint_host = None
        
        serverside_allowedips = self._get_ip_interfaces_interactively(self.TEXT_SERVER_ALLOWEDIPS)
        pass
    
    @staticmethod
    def _get_endpoint_port_interactively(text: str, suggested_default: int) -> int:
        print(text)

        while True:
            CliHandler._print_list_of_options([suggested_default])

            selection = input(CliHandler.PROMPT)
            
            try:
                selection = int(selection)
                
                if selection < 0 or selection > 65535:
                    raise ValueError("Port value out of range! Must be between 0 and 65535")
            
                if selection == 0:
                    selection = suggested_default
            
                print(f"Selected port: {selection}\n")
                
                return selection
                
            except ValueError as e:
                logging.getLogger(__name__).exception("Invalid input")
                print("Please try again!\n")
                
    
    @staticmethod
    def _get_ip_interfaces_interactively(text: str, suggested_defaults: list[IPv4Interface | IPv6Interface]) -> list[(IPv4Interface | IPv6Interface)]:
        print(text)

        while True:
            CliHandler._print_list_of_options(suggested_defaults)

            selection = input(CliHandler.PROMPT)
            
            try:
                selection = int(selection)
                
                retval = [suggested_defaults[selection]]
                
                print(f"Selected interface(s): {retval}\n")
                
                return retval
                
            except ValueError as e:
                pass
            
            
            try:
                selection_arr = selection.split(',')
                
                retval = []
                
                for entry in selection_arr:
                    retval.append(ipaddress.ip_interface(entry.strip()))
                
                print(f"Selected interface(s): {retval}\n")
                
                return retval
                
            except ValueError as e:
                pass
            
            print("Invalid input, please try again\n")
           
    @staticmethod 
    def _print_list_of_options(opts: list) -> None:
        for index, value in enumerate(opts):
            print("[%i] %s" % (index, value))