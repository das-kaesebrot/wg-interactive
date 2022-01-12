import sys
import os
import subprocess
import wgconfig
import ipaddress
import netifaces
import validators
import qrcode
from typing import OrderedDict
from wgconfig import wgexec
from termcolor import colored, cprint
from pathlib import Path


def reloadWGInterfaceIfRunning(ifaceName, absWGPath):                
    if subprocess.run(["wg", "show", ifaceName], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT).returncode == 0:
        subprocess.run(["wg", "setconf", ifaceName, absWGPath])
        print(f"Detected that selected WireGuard config is running\nReloaded wireguard interface {colored(ifaceName, attrs=['bold'])}")
    else:
        print(f"Selected WireGuard config isn't running, skipping reload")

    
def getWGInterfaces(wgConfPath, defaultExt):
    returnList = []
    for file in os.listdir(wgConfPath):
        if file.endswith(defaultExt):
            returnList.append(file[:-len(defaultExt)])
            
    return returnList


def getAbsWGPath (wgConfPath, selectedWGName, defaultExt):
    return Path(wgConfPath, selectedWGName + defaultExt)


def getClientIPWithMaskFromPreviousPeers(wc, ipAddr):
    return ipaddress.ip_interface(str(ipAddr) + "/" + str(ipaddress.ip_interface(wc.peers.get(list(wc.peers.keys())[-1]).get('AllowedIPs')).netmask))


def generateQRCodeFromConfigAndSave(config, peerQRCodeFile):
    qrcode.make(data=config).save(peerQRCodeFile)
    print(f"Wrote peer QR code to {colored(f'{peerQRCodeFile}', attrs=['bold'])}")


# TODO add init function
def initNewInterface():
    print("Sorry, this hasn't been implemented yet. Exiting.")
    raise NotImplementedError


def deletePeerFromInterface(wc, selectedWGName, absWGPath):
    if wc.peers == {}:
        sys.stderr.write('No peers found in config. Exiting.\n')
        sys.exit(1)

    peersByName = OrderedDict({})
    for peerKey in wc.peers.keys():
        peer = wc.peers.get(peerKey)
        publicKey = peer.get('PublicKey')
        for entry in peer.get('_rawdata'):
            if entry.startswith('#'):
                name = entry[2:]
                if not publicKey in peersByName.keys():
                    peersByName[publicKey] = {
                        'Name': name,
                    }

    selection = 0
    validInput = False

    peersByNameAsList = []
    for key in peersByName.keys():
        peersByNameAsList.append({
            'PublicKey': key,
            'Name': peersByName.get(key).get('Name')
            })
    
    while not validInput:
        print("Please select a peer to delete:")
        for x in range(len(peersByNameAsList)):
            print("[%2d] PublicKey: %s (%s)" % (x, peersByNameAsList[x].get('PublicKey'), peersByNameAsList[x].get('Name')))
        selection = input(prompt)
        
        try:
            selection = int(selection)
            if (selection >= 0 ) and (selection < len(peersByNameAsList)):
                validInput = True
                peerToBeDeleted = peersByNameAsList[selection]
                wc.del_peer(peerToBeDeleted.get('PublicKey'))
                wc.write_file(absWGPath)
                print(f"Deleted peer {colored(peerToBeDeleted.get('PublicKey') + ' (' + peerToBeDeleted.get('Name') + ')', attrs=['bold'])}")
                
                reloadWGInterfaceIfRunning(selectedWGName, absWGPath)
                
                print("Done!")
                exit
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
                if ipaddress.ip_address(addr.get('addr')).is_global:
                    recommendedEndpoints.append(addr.get('addr'))
        if netifaces.AF_INET6 in addrs.keys():
            for addr in addrs[netifaces.AF_INET6]:
                if ipaddress.ip_address(addr.get('addr')).is_global:
                    recommendedEndpoints.append(addr.get('addr'))

    if '.' in os.uname()[0]:
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
        print(f"{colored('Endpoint host', attrs=['bold'])}\nPlease select an endpoint host to use or input your own:")
        for x in range(len(recommendedEndpoints)):
            print("[%2d] %s" % (x, recommendedEndpoints[x]))

        selection = input(prompt)
        inputIsDomainOrIP = False
        try:
            try:
                if not validators.domain(selection):
                    raise ValueError
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
            cprint("Input needs to be a number or an IP without a subnet range", 'red')

    endpoint = selectedAddr + ':' + str(selectedListenPort)
    print(f"Selected endpoint: {colored(endpoint, attrs=['bold'])}\n")

    print("Please input the peer\'s name:")
    peerName = input(prompt)

    # Create peers dir if it doesn't exist yet
    os.makedirs(Path(peersDir, selectedWGName), mode=644, exist_ok=True)
    peerFilePath = Path(peersDir, selectedWGName, peerName + defaultExt)
    peerQRCodePath = Path(peersDir, selectedWGName, peerName + "-qr.png")
    print(f"Peer file will be written to: {colored(peerFilePath, attrs=['bold'])}\n")
    print(f"Peer QR code will be written to: {colored(peerQRCodePath, attrs=['bold'])}\n")
    collectedAddresses = []
    recommendedAddresses = []
    if wc.peers == {}:
        addrRange = wc.interface.get('Address')
        if type(addrRange) == list:
            for ipIface in addrRange:
                collectedAddresses.append(ipaddress.ip_interface(ipIface))
        else:
            collectedAddresses.append(ipaddress.ip_interface(addrRange))
    else:
        
        tempIPList = []
        for peer in wc.peers:
            allowedIPsFromPeer = wc.peers.get(peer).get('AllowedIPs')
            if type(allowedIPsFromPeer) == list:
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
        print(f"{colored('AllowedIPs (Peer config)', attrs=['bold'])}\nPlease select a range of AllowedIPs or give your own (comma-separated for multiple ranges, no spaces):")
        for x in range(len(clientAllowedIPs)):
            print("[%2d] %s" % (x, clientAllowedIPs[x]))
            
        selection = input(prompt)
        inputIsNet = False
        try:
            try:
                if ',' in selection:
                    selectionList = selection.split(',')
                    for ipNet in selectionList:
                        selectedNetworks = []
                        selectedNetworks.append(ipaddress.ip_network(ipNet))
                else:
                    selectedNetworks = ipaddress.ip_network(ipNet)
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
AllowedIPs = {selectedNetworks}
{"PersistentKeepalive = 25" if persistentKeepalive else ""}\n"""

    wc.add_peer(publicKey, f"# {peerName}")
    wc.add_attr(publicKey, 'AllowedIPs', str(clientIPWithNetmaskForConfig))
    wc.write_file(absWGPath)
    
    with open(peerFilePath, 'w') as peerfile:
        peerfile.write(peerConfig)
        print(f"Wrote peer config to {colored(f'{peerFilePath}', attrs=['bold'])}")
    
    generateQRCodeFromConfigAndSave(peerConfig, peerQRCodePath)
    
    reloadWGInterfaceIfRunning(selectedWGName, wgConfPath)
    print("Done!")
    exit


def main():
    # Check if program is being run as root
    if not 'SUDO_UID' in os.environ.keys():
        print("You need to execute this program as root")
        sys.exit(1)

    # Static vars
    if os.getenv("WGCONFPATH"): wgConfPath = Path(os.getenv("WGCONFPATH"))
    else: wgConfPath = Path("/etc/wireguard")    
    
    global prompt
    global defaultExt
    global peersDir
    
    defaultExt = '.conf'
    prompt = "> "
    peersDir = "peers"

    wgList = []
    
    version = "0.1.0"
    twitterhandle = "das_kaesebrot"
    website = "https://github.com/das-kaesebrot/wg-interactive"
    
    banner = f"""{colored(f'wg-interactive.py v{version}', attrs=['bold'])}

An interactive command line tool for modifying and initializing WireGuard server configuration files and adding/deleting peers.
by @{twitterhandle}
Source: {website}"""
    
    print(banner, f"\n\nUsing WireGuard config path {colored(wgConfPath, attrs=['bold'])}")
    
    wgList = getWGInterfaces(wgConfPath, defaultExt)

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
    print(f"Selected interface: {colored(absWGPath, attrs=['bold'])}\n")

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
                'letter': 'd',
                'text': 'Delete peer',
                'short': 'delete'
            }]
        for x in range(len(ops)):
            print("[%c] %s" % (ops[x].get('letter'), ops[x].get('text')))
        selection = input(prompt)
        for operation in ops:
            if selection == operation.get('letter'):
                selectedOperation = operation
                validInput = True
        if not validInput:
            cprint("Invalid input", 'red')

    
    print(f"Selected operation: {colored(selectedOperation.get('short'), attrs=['bold'])}\n")

    if selectedOperation.get('short') == "add": addNewPeerToInterface(wc, selectedWGName, absWGPath, wgConfPath)
    elif selectedOperation.get('short') == 'delete': deletePeerFromInterface(wc, selectedWGName, absWGPath)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nDetected keyboard interrupt. Aborting.")
        sys.exit(1)