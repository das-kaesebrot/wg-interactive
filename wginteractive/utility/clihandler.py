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
        
        if interface_action == self.ACTION_ADD: addNewPeerToInterface(wc, selectedWGName, absWGPath, wgConfPath)
        elif interface_action == self.ACTION_RENAME: renamePeerInInterface(wc, selectedWGName, absWGPath)
        elif interface_action == self.ACTION_NEWKEY_CLIENT: regeneratePeerPublicKey(wc, selectedWGName, absWGPath)
        elif interface_action == self.ACTION_DELETE: deletePeerFromInterface(wc, selectedWGName, absWGPath)
        elif interface_action == self.ACTION_FLIP_SYSTEMD: Systemd.flip_enabled_status(selectedWGName)
        
    def _get_initial_interface_or_action_and_validate(self) -> str:

        print("Please select an interface to modify or initialize a new interface:")
        
        while True:
            for k, v in self.ACTIONS_MENU_ROOT:
                print("[%c] %s" % (k, v.get('desc')))
                
            selection = input(CliHandler.PROMPT)

            if selection in self.ACTIONS_MENU_ROOT.keys():
                print(f"Selected operation/interface: {self.ACTIONS_MENU_ROOT.get(selection).get('desc')}\n")
                return selection

            print("Invalid input")

    def _get_action_for_interface_and_validate(self) -> str:

        print("Please select an operation to perform:")

        while True:
            for k, v in self.ACTIONS_MENU:
                print("[%c] %s" % (k, v.get('desc')))

            selection = input(CliHandler.PROMPT)

            if selection in self.ACTIONS_MENU.keys():
                print(f"Selected operation: {self.ACTIONS_MENU.get(selection).get('desc')}\n")
                return selection
            
            print("Invalid input")
