import sys
import os
import wgconfig
import ipaddress
import netifaces
import validators
from typing import OrderedDict
from wgconfig import wgexec
from termcolor import colored, cprint
from pathlib import Path

from importlib import metadata

from .classes.wginterface import WireGuardInterface
from .utility.wghandler import WireGuardHandler
from .utility.systemd import Systemd
from .classes.config import Config

def getAbsWGPath (wgConfPath, selectedWGName, defaultExt):
    return Path(wgConfPath, selectedWGName + defaultExt)

def getClientIPWithMaskFromPreviousPeers(wc, ipAddr):
    if len(list(wc.peers.keys())) > 0:
        return ipaddress.ip_interface(str(ipAddr) + "/" + str(ipaddress.ip_interface(wc.peers.get(list(wc.peers.keys())[-1]).get('AllowedIPs')).netmask))
    else:
        print("Defaulting to server-side netmask of /32 since no previous peers could be found.")
        return ipaddress.ip_interface(str(ipAddr) + "/32")

# TODO add init function
def initNewInterface():
    raise NotImplementedError("Init not implemented yet")

def deletePeerFromInterface(wc, selectedWGName, absWGPath):
    if wc.peers == {}:
        sys.stderr.write('No peers found in config. Exiting.\n')
        sys.exit(1)

    peersByName = OrderedDict({})
    for peerKey in wc.peers.keys():
        name = 'Unnamed Peer'
        peer = wc.peers.get(peerKey)
        publicKey = peer.get('PublicKey')
        for entry in peer.get('_rawdata'):
            if entry.startswith('#'):
                name = entry[2:]        
        if not publicKey in peersByName.keys():
            peersByName[publicKey] = {
                'Name': name,
                'AllowedIPs': peer.get('AllowedIPs')
            }

    selection = 0
    validInput = False

    peersByNameAsList = []
    for key in peersByName.keys():
        peersByNameAsList.append({
            'PublicKey': key,
            'Name': peersByName.get(key).get('Name'),
            'AllowedIPs': peersByName.get(key).get('AllowedIPs')
            })
    
    while not validInput:
        print("Please select a peer to delete:")
        for x in range(len(peersByNameAsList)):
            print("[%2d] PublicKey: %s\n     AllowedIPs: %s\n     Name: %s\n" % (x, peersByNameAsList[x].get('PublicKey'), peersByNameAsList[x].get('AllowedIPs'), peersByNameAsList[x].get('Name')))
        selection = input(prompt)
        
        try:
            selection = int(selection)
            if (selection >= 0 ) and (selection < len(peersByNameAsList)):
                validInput = True
                peerToBeDeleted = peersByNameAsList[selection]
                wc.del_peer(peerToBeDeleted.get('PublicKey'))
                wc.write_file(absWGPath)
                print(f"Deleted peer {colored(peerToBeDeleted.get('PublicKey') + ' (' + peerToBeDeleted.get('Name') + ')', attrs=['bold'])}")
                
                reloadWGInterfaceIfRunning(selectedWGName)
                
                print("Done!")
                sys.exit()
            else:
                cprint("Invalid input", 'red')
        except ValueError:
            cprint("Input needs to be a number", 'red')

def addNewPeerToInterface(wc, selectedWGName, absWGPath, wgConfPath):
    listenPorts = [int(wc.interface.get('ListenPort'))]

    recommendedEndpoints = []
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs.keys():
            for addr in addrs[netifaces.AF_INET]:
                addrGet = addr.get('addr')
                # work around bug from the netifaces library which sometimes appends the interface name to an IP
                if '%' in addrGet:
                    addrGet = addrGet.split('%')[0]
                if ipaddress.ip_address(addrGet).is_global:
                    recommendedEndpoints.append(addrGet)
        if netifaces.AF_INET6 in addrs.keys():
            for addr in addrs[netifaces.AF_INET6]:
                addrGet = addr.get('addr')
                # work around bug from the netifaces library which sometimes appends the interface name to an IP
                if '%' in addrGet:
                    addrGet = addrGet.split('%')[0]
                if ipaddress.ip_address(addrGet).is_global:
                    recommendedEndpoints.append(addrGet)

    if '.' in os.uname()[1]:
        recommendedEndpoints.append(os.uname()[1])

    selection = 0
    validInput = False
    while not validInput:
        print(f"{colored('Endpoint port', attrs=['bold'])}\nPlease select an endpoint port to use or input your own:")
        for x in range(len(listenPorts)):
            print("[%2d] %s" % (x, listenPorts[x]))

        selection = input(prompt)
        inputIsNotPort = False
        try:
            try:
                selection = int(selection)
                if (selection >= 0 ) and (selection < len(listenPorts)):
                    selectedListenPort = listenPorts[selection]
                    validInput = True
                    inputIsNotPort = True
            except:
                pass
            if not inputIsNotPort:                    
                selection = int(selection)
                if (selection >= 1) and (selection <= 65535):
                    selectedListenPort = selection
                    validInput = True
                else:
                    cprint("Invalid input", 'red')
        except ValueError:
            cprint("Input needs to be a valid port number", 'red')

    selection = 0
    validInput = False
    while not validInput:
        print(f"{colored('Endpoint host', attrs=['bold'])}\nSince it is not required for a WireGuard server to read its own endpoint domain/IP from the config file, this script needs to provide that value.\nPlease select an endpoint host (this server's IP or a FQDN pointing to it) to use in the peer's config file or input your own.\nExamples for valid own inputs:\nvpn.example.com\n11.22.33.44\nPlease don't append the port, this will be done automatically!")
        for x in range(len(recommendedEndpoints)):
            print("[%2d] %s" % (x, recommendedEndpoints[x]))

        selection = input(prompt)
        inputIsDomainOrIP = False
        try:
            try:
                if not validators.domain(selection):
                    test = ipaddress.ip_address(selection)
                    selectedAddr = str(selection)
                else:
                    selectedAddr = str(selection)
                validInput = True
                inputIsDomainOrIP = True
            except:
                pass
            if not inputIsDomainOrIP:
                selection = int(selection)
                if (selection >= 0 ) and (selection < len(recommendedEndpoints)):
                    selectedAddr = recommendedEndpoints[selection]
                    validInput = True
                else:
                    cprint("Invalid input", 'red')                    
        except ValueError:
            cprint("Input needs to be either a domain, a number or an IP without a subnet range", 'red')

    endpoint = selectedAddr + ':' + str(selectedListenPort)
    print(f"Selected endpoint: {colored(endpoint, attrs=['bold'])}\n")

    print("Please input the peer\'s name:")
    peerName = input(prompt)

    # Create peers dir if it doesn't exist yet
    # use /etc folder if running from binary
    if useEtcFolderForPeersOutput:
        os.makedirs(Path(etcConfigDir, "peers", selectedWGName), mode=0o644, exist_ok=True)
        peerFilePath = Path(etcConfigDir, "peers", selectedWGName, peerName + defaultExt)
    else:
        os.makedirs(Path(peersDir, selectedWGName), mode=0o644, exist_ok=True)
        peerFilePath = Path(peersDir, selectedWGName, peerName + defaultExt)
    print(f"Peer file will be written to: {colored(peerFilePath, attrs=['bold'])}\n")
    collectedAddresses = []
    recommendedAddresses = []
    if wc.peers == {}:
        addrRange = wc.interface.get('Address')
        if isinstance(addrRange, list):
            for ipIface in addrRange:
                collectedAddresses.append(ipaddress.ip_interface(ipIface))
        else:
            collectedAddresses.append(ipaddress.ip_interface(addrRange))
    else:
        
        tempIPList = []
        for peer in wc.peers:
            allowedIPsFromPeer = wc.peers.get(peer).get('AllowedIPs')
            if isinstance(allowedIPsFromPeer, list):
                for allowedIPEntry in allowedIPsFromPeer:
                    tempIPList.append(ipaddress.ip_interface(allowedIPEntry))
            else:
                tempIPList.append(ipaddress.ip_interface(allowedIPsFromPeer))
            tempIPList.sort()
        
        gapFound = False
        for x in range(len(tempIPList)):
            # check if gap between IPs is bigger than 1 to help fill gaps
            # allows finding multiple gaps
            if x != 0 and not (tempIPList[x] - 1 == tempIPList[x-1]):
                collectedAddresses.append(tempIPList[x-1])
                gapFound = True
        if not gapFound:
            collectedAddresses.append(tempIPList[-1])
                    
    
    for x in range(len(collectedAddresses)):
        addr = collectedAddresses[x]        
        addr = ipaddress.ip_interface(addr + 1)
        if not (
                addr.is_reserved
            or addr.is_multicast
            or addr.is_link_local
            or addr.is_loopback
        ):
            recommendedAddresses.append(addr.ip)
    
    
    selection = 0
    validInput = False
    while not validInput:
        print(f"{colored('Peer IP', attrs=['bold'])}\nPlease select a recommended address or input your own:")
        for x in range(len(recommendedAddresses)):
            print("[%2d] %s" % (x, recommendedAddresses[x]))
            
        selection = input(prompt)
        inputIsIP = False
        try:
            try:
                peerIP = ipaddress.ip_address(selection)
                validInput = True
                inputIsIP = True
            except:
                pass
            if not inputIsIP:
                selection = int(selection)
                if (selection >= 0 ) and (selection < len(recommendedAddresses)):
                    peerIP = recommendedAddresses[selection]
                    validInput = True
                else:
                    cprint("Invalid input", 'red')                    
        except ValueError:
            cprint("Input needs to be a number or an IP without a subnet range", 'red')
    
    print(f"Selected peer IP: {colored(str(peerIP), attrs=['bold'])}\n")

    # Guessing the AllowedIPs from the interface subnet mask and the selected peer IP
    clientAllowedIPs = [ipaddress.ip_interface(str(peerIP) +  "/" + str(ipaddress.ip_interface(wc.interface.get('Address')).netmask)).network]

    selection = 0
    validInput = False
    while not validInput:
        print(f"{colored('AllowedIPs', attrs=['bold'])}\nFor the peer sided config, as in which network ranges the peer is allowed to access.\nBe aware that a user may change this in their config at any time.\nPlease select a range of AllowedIPs or give your own (comma-separated for multiple ranges, no spaces):")
        for x in range(len(clientAllowedIPs)):
            print("[%2d] %s" % (x, clientAllowedIPs[x]))
            
        selection = input(prompt)
        inputIsNet = False
        try:
            try:
                if ',' in selection:
                    selectionList = selection.split(',')
                    selectedNetworks = []
                    for ipNet in selectionList:
                        _ = ipaddress.ip_network(ipNet)
                        selectedNetworks.append(ipNet)
                else:
                    selectedNetworks = ipaddress.ip_network(selection)
                validInput, inputIsNet = True, True
            except:
                pass
            if not inputIsNet:
                selection = int(selection)
                if (selection >= 0 ) and (selection < len(clientAllowedIPs)):
                    selectedNetworks = clientAllowedIPs[selection]
                    validInput = True
                else:
                    cprint("Invalid input", 'red')
        except ValueError:
            cprint("Input needs to be a number or an IP network", 'red')
    
    print(f"Selected AllowedIPs (Peer config): {colored(selectedNetworks, attrs=['bold'])}\n")

    persistentKeepalive = True

    selection = 0
    validInput = False
    while not validInput:
        selection = input(f"Add 'PersistentKeepalive = 25' to client config? [Y/n] {prompt}")

        try:
            if not selection == '':
                selection = selection.lower()
                if selection == 'y':
                    validInput = True
                elif selection == 'n':
                    persistentKeepalive = False
                    validInput = True
                else:
                    cprint("Invalid input", 'red')
            else:
                validInput = True
        except ValueError:
            cprint("Input needs to be either y or n", 'red')


    privateKey, publicKey = wgexec.generate_keypair()

    clientIPWithNetmaskForConfig = getClientIPWithMaskFromPreviousPeers(wc, peerIP)

    peerConfig = f"""[Interface]
Address = {clientIPWithNetmaskForConfig}
PrivateKey = {privateKey}

[Peer]
PublicKey = {wgexec.get_publickey(wc.interface.get('PrivateKey'))}
Endpoint = {endpoint}
AllowedIPs = {','.join(selectedNetworks) if isinstance(selectedNetworks, list) else selectedNetworks}
{"PersistentKeepalive = 25" if persistentKeepalive else ""}\n"""

    wc.add_peer(publicKey, f"# {peerName}")
    wc.add_attr(publicKey, 'AllowedIPs', str(clientIPWithNetmaskForConfig))
    wc.write_file(absWGPath)
    
    with open(peerFilePath, 'w') as peerfile:
        peerfile.write(peerConfig)
        print(f"Wrote peer config to {colored(f'{peerFilePath}', attrs=['bold'])}")
    
    reloadWGInterfaceIfRunning(selectedWGName)
    print("Done!")
    sys.exit()
    
def listPeersFromInterface(wc, selectedWGName):
    peersByName = OrderedDict({})
    for peerKey in wc.peers.keys():
        name = 'Unnamed Peer'
        peer = wc.peers.get(peerKey)
        publicKey = peer.get('PublicKey')
        for entry in peer.get('_rawdata'):
            if entry.startswith('#'):
                name = entry[2:]        
        if not publicKey in peersByName.keys():
            peersByName[publicKey] = {
                'Name': name,
                'AllowedIPs': peer.get('AllowedIPs')
            }

    peersByNameAsList = []
    for key in peersByName.keys():
        peersByNameAsList.append({
            'PublicKey': key,
            'Name': peersByName.get(key).get('Name'),
            'AllowedIPs': peersByName.get(key).get('AllowedIPs')
            })
    
    print(f"Peers in WireGuard interface {colored(selectedWGName, attrs=['bold'])}:")
    for x in range(len(peersByNameAsList)):
        print("[%2d] PublicKey: %s\n     AllowedIPs: %s\n     Name: %s\n" % (x, peersByNameAsList[x].get('PublicKey'), peersByNameAsList[x].get('AllowedIPs'), peersByNameAsList[x].get('Name')))
    print("")

def renamePeerInInterface(wc, selectedWGName, absWGPath):
    peersByName = OrderedDict({})
    for peerKey in wc.peers.keys():
        name = 'Unnamed Peer'
        peer = wc.peers.get(peerKey)
        publicKey = peer.get('PublicKey')
        for entry in peer.get('_rawdata'):
            if entry.startswith('#'):
                name = entry[2:]        
        if not publicKey in peersByName.keys():
            peersByName[publicKey] = {
                'Name': name,
                'AllowedIPs': peer.get('AllowedIPs')
            }

    peersByNameAsList = []
    for key in peersByName.keys():
        peersByNameAsList.append({
            'PublicKey': key,
            'Name': peersByName.get(key).get('Name'),
            'AllowedIPs': peersByName.get(key).get('AllowedIPs')
            })
    
    selection = 0
    validInput = False
    while not validInput:
        print("Please select a peer to rename:")
        for x in range(len(peersByNameAsList)):
            print("[%2d] PublicKey: %s\n     AllowedIPs: %s\n     Name: %s\n" % (x, peersByNameAsList[x].get('PublicKey'), peersByNameAsList[x].get('AllowedIPs'), peersByNameAsList[x].get('Name')))
        selection = input(prompt)
        
        try:
            selection = int(selection)
            if (selection >= 0 ) and (selection < len(peersByNameAsList)):
                validInput = True
                peerToBeRenamed = wc.peers.get(peersByNameAsList[selection].get('PublicKey'))
                wc.del_peer(peerToBeRenamed.get('PublicKey'))
                wc.write_file(absWGPath)
                newPeerName = input(f"\nPlease give a new name for the peer:\n{prompt}")
                renamedPeerRaw = f"\n# {newPeerName}\n"
                for entry in peerToBeRenamed.get('_rawdata'):
                    if not entry.startswith('#'):
                        renamedPeerRaw += f"{entry}\n"

                with open(absWGPath, "a") as configFile:
                    configFile.write(renamedPeerRaw)
                                    
                reloadWGInterfaceIfRunning(selectedWGName)
                
                print("Done!")
                sys.exit()
            else:
                cprint("Invalid input", 'red')
        except ValueError:
            cprint("Input needs to be a number", 'red')

def regeneratePeerPublicKey(wc, selectedWGName, absWGPath):
    peersByName = OrderedDict({})
    for peerKey in wc.peers.keys():
        name = 'Unnamed Peer'
        peer = wc.peers.get(peerKey)
        publicKey = peer.get('PublicKey')
        for entry in peer.get('_rawdata'):
            if entry.startswith('#'):
                name = entry[2:]        
        if not publicKey in peersByName.keys():
            peersByName[publicKey] = {
                'Name': name,
                'AllowedIPs': peer.get('AllowedIPs')
            }

    peersByNameAsList = []
    for key in peersByName.keys():
        peersByNameAsList.append({
            'PublicKey': key,
            'Name': peersByName.get(key).get('Name'),
            'AllowedIPs': peersByName.get(key).get('AllowedIPs')
            })
    
    selection = 0
    validInput = False
    while not validInput:
        print("Please select a peer to regenerate keypair for:")
        for x in range(len(peersByNameAsList)):
            print("[%2d] PublicKey: %s\n     AllowedIPs: %s\n     Name: %s\n" % (x, peersByNameAsList[x].get('PublicKey'), peersByNameAsList[x].get('AllowedIPs'), peersByNameAsList[x].get('Name')))
        selection = input(prompt)
        
        try:
            selection = int(selection)
            if (selection >= 0 ) and (selection < len(peersByNameAsList)):
                validInput = True
                peerToBeRegenerated = wc.peers.get(peersByNameAsList[selection].get('PublicKey'))
                wc.del_peer(peerToBeRegenerated.get('PublicKey'))
                wc.write_file(absWGPath)
                
                privateKey, publicKey = wgexec.generate_keypair()
                
                peerSection = "\n"
                publicKeyRaw = f"PublicKey = {publicKey}\n"
                for entry in peerToBeRegenerated.get('_rawdata'):
                    if entry.startswith('PublicKey'):
                        peerSection += publicKeyRaw
                    else:
                        peerSection += f"{entry}\n"

                with open(absWGPath, "a") as configFile:
                    configFile.write(peerSection)
                                    
                reloadWGInterfaceIfRunning(selectedWGName)
                
                print(f"Done!\nPlease give the following private key to the peer to swap out in their config file:\n{privateKey}")
                cprint("WARNING! After this, the private key is lost and will not be shown again!", 'red')
                sys.exit()
            else:
                cprint("Invalid input", 'red')
        except ValueError:
            cprint("Input needs to be a number", 'red')

def main():
    # Check if program is being run as root
    if not os.geteuid() == 0:
        print("You need to execute this program as root")
        sys.exit(1)
    
    versionstr = metadata.version("wg-interactive")
    
    banner = f"""{colored(f'wg-interactive v{versionstr}', attrs=['bold'])}

An interactive command line tool for modifying and initializing WireGuard server configuration files and adding/deleting peers."""

    print(banner)        
        
    config = Config()
    wghandler = WireGuardHandler(config)
    interfaces = wghandler.get_interfaces()

    selection = 0
    validInput = False
    while not validInput:
        print("Please select an interface to modify or initialize a new interface:")
        for x in range(len(wgList)):
            print("[%2d] %s" % (x, wgList[x]))
        
        initOp = {
                'letter': 'i',
                'text': 'Init new interface',
                'short': 'init'
            }
        print("[%2c] %s" % (initOp.get('letter'), initOp.get('text')))
        selection = input(prompt)
        try:
            if selection == initOp.get('letter'):
                validInput = True
                
            else:
                selection = int(selection)
                if (selection >= 0 ) and (selection < len(wgList)):
                    validInput = True
                else:
                    cprint("Invalid input", 'red')
        except ValueError:
            cprint("Input needs to be a number or a single letter", 'red')
    
    if selection == 'i':
        initNewInterface()

    selectedWGName = wgList[selection]
    absWGPath = getAbsWGPath(wgConfPath, selectedWGName, defaultExt)

    print(f"\nSelected interface: {colored(absWGPath, attrs=['bold'])}")
    
    wginterface = WireGuardInterface(selectedWGName)
    
    wginterface.check_if_interface_is_running()
    wginterface.check_if_wg_interface_is_enabled_on_systemd()
    
    wc = wgconfig.WGConfig(absWGPath)
    wc.read_file()

    ops = []

    selection = 0
    validInput = False
    while not validInput:
        print("Please select an operation to perform:")
        ops = [
            {
                'letter': 'a',
                'text': 'Add peer',
                'short': 'add'
            },
            {
                'letter': 'l',
                'text': 'List all peers and return to this menu',
                'short': 'list'
            },
            {
                'letter': 'r',
                'text': 'Rename peer',
                'short': 'rename'
            },
            {
                'letter': 'k',
                'text': 'Generate new keypair for peer',
                'short': 'keypair'
            },
            {
                'letter': 'd',
                'text': 'Delete peer',
                'short': 'delete'
            }]
        if Systemd.check_if_host_is_using_systemd():
            ops.append({
                'letter': 's',
                'text': 'Flip enabled state for wg-quick systemd service',
                'short': 'systemd-enabled'
            })
        for x in range(len(ops)):
            print("[%c] %s" % (ops[x].get('letter'), ops[x].get('text')))
        selection = input(prompt)
        for operation in ops:
            if selection == operation.get('letter'):
                selectedOperation = operation
                validInput = True
        if not validInput:
            cprint("Invalid input", 'red')
        elif validInput and selectedOperation.get('short') == 'list':
            print(f"Selected operation: {colored(selectedOperation.get('short'), attrs=['bold'])}\n")
            listPeersFromInterface(wc, selectedWGName)
            validInput = False

    
    print(f"Selected operation: {colored(selectedOperation.get('short'), attrs=['bold'])}\n")

    if selectedOperation.get('short') == "add": addNewPeerToInterface(wc, selectedWGName, absWGPath, wgConfPath)
    elif selectedOperation.get('short') == 'rename': renamePeerInInterface(wc, selectedWGName, absWGPath)
    elif selectedOperation.get('short') == 'keypair': regeneratePeerPublicKey(wc, selectedWGName, absWGPath)
    elif selectedOperation.get('short') == 'delete': deletePeerFromInterface(wc, selectedWGName, absWGPath)
    elif selectedOperation.get('short') == 'systemd-enabled': Systemd.flip_enabled_status(selectedWGName)


if __name__ == "__main__":
    try:
        main()
    
    except NotImplementedError as e:
        print(f"{e=}")
        sys.exit(0)
    
    except EOFError or KeyboardInterrupt:
        print("Detected keyboard interrupt or EOF. Aborting.")
        sys.exit(0)

    except Exception as e:
        print(f"{e=}")
        sys.exit(1)