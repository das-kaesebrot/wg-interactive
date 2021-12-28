import sys
import os
import subprocess
import wgconfig
import ipaddress
import netifaces
import validators
from typing import OrderedDict
from wgconfig import wgexec
from termcolor import colored, cprint
from pathlib import Path


def main():
    # Check if program is being run as root
    if not 'SUDO_UID' in os.environ.keys():
        print("You need to execute this program as root")
        sys.exit(1)

    # Static vars
    if os.getenv("WGCONFPATH"): wgConfPath = Path(os.getenv("WGCONFPATH"))
    else: wgConfPath = Path("/etc/wireguard")    
    
    defaultExt = '.conf'
    prompt = "> "
    peersDir = "peers"

    wgList = []
    
    version = "0.1.0"
    twitterhandle = "das_kaesebrot"
    website = "https://github.com/das-kaesebrot/wg-interactive"
    
    banner = f"""{colored(f'wg-interactive.py v{version}', attrs=['bold'])}

An interactive script for modifying and initializing WireGuard server configuration files and adding/deleting peers.
by @{twitterhandle}
Source: {website}"""
    
    print(banner, f"\n\nUsing WireGuard config path {colored(wgConfPath, attrs=['bold'])}")

    for file in os.listdir(wgConfPath):
        if file.endswith(defaultExt):
            wgList.append(file[:-len(defaultExt)])

    selection = 0
    validInput = False
    while not validInput:
        print("Please select an interface to modify:")
        for x in range(len(wgList)):
            print("[%2d] %s" % (x, wgList[x]))
        selection = input(prompt)
        try:
            selection = int(selection)
            if (selection >= 0 ) and (selection < len(wgList)):
                validInput = True
            else:
                cprint("Invalid input", 'red')
        except ValueError:
            cprint("Input needs to be a number", 'red')

    selectedWGName = wgList[selection]
    absWGPath = Path(wgConfPath, selectedWGName + defaultExt)
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

    if selectedOperation.get('short') == "add":

        listenPorts = [int(wc.interface.get('ListenPort'))]

        recommendedEndpoints = []
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs.keys():
                for addr in addrs[netifaces.AF_INET]:
                    if ipaddress.ip_address(addr.get('addr')).is_global:
                        recommendedEndpoints.append(ipaddress)
            if netifaces.AF_INET6 in addrs.keys():
                for addr in addrs[netifaces.AF_INET6]:
                    if ipaddress.ip_address(addr.get('addr')).is_global:
                        recommendedEndpoints.append(ipaddress)

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
        os.makedirs(peersDir, mode=644, exist_ok=True)
        peerFilePath = Path(peersDir, peerName + defaultExt)
        print(f"Peer file will be written to: {colored(peerFilePath, attrs=['bold'])}\n")
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

            # TODO implement support for multiple values in AllowedIPs coming from existing config
            tempIPList = []
            for peer in wc.peers:
                tempIPList.append(ipaddress.ip_interface(wc.peers.get(peer).get('AllowedIPs')))
                tempIPList.sort()
            
            gapFound = False
            for x in range(len(tempIPList)):
                # check if gap between IPs is bigger than 1 to help fill gaps
                # allows finding multiple gaps
                if x != 0 and not (tempIPList[x] - 1 == tempIPList[x-1]):
                    collectedAddresses.append(tempIPList[x-1])
                    gapFound = True
                    # break
            if not gapFound:
                collectedAddresses.append(tempIPList[:-1])
                        
        
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
                    selectedAddr = ipaddress.ip_address(selection)
                    validInput = True
                    inputIsIP = True
                except:
                    pass
                if not inputIsIP:
                    selection = int(selection)
                    if (selection >= 0 ) and (selection < len(recommendedAddresses)):
                        selectedAddr = recommendedAddresses[selection]
                        validInput = True
                    else:
                        cprint("Invalid input", 'red')                    
            except ValueError:
                cprint("Input needs to be a number or an IP without a subnet range", 'red')
        
        print(f"Selected peer IP: {colored(str(selectedAddr), attrs=['bold'])}\n")

        # Guessing the AllowedIPs from the interface subnet mask and the selected peer IP
        clientAllowedIPs = [ipaddress.ip_interface(str(selectedAddr) +  "/" + str(ipaddress.ip_interface(wc.interface.get('Address')).netmask)).network]

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
            selection = input(f"Add 'PersistentKeepalive = 25' to client config? [Y/n]{prompt} ")

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


        # TODO generate the keypair
        # TODO write out files
        privateKey, publicKey = wgexec.generate_keypair()

        peerConfig = f"""[Interface]
Address = {selectedAddr}
PrivateKey = {privateKey}

[Peer]
PublicKey = {wc.interface.get('PublicKey')}
Endpoint = {endpoint}
AllowedIPs = {clientAllowedIPs}
{"PersistentKeepalive = 25" if persistentKeepalive else ""}"""


    elif selectedOperation.get('short') == 'init':
        print("Sorry, this hasn't been implemented yet. Exiting.")
        raise NotImplementedError
        
    
    elif selectedOperation.get('short') == 'delete':
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
                    
                    if subprocess.run(["wg", "show", selectedWGName], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT).returncode == 0:
                        subprocess.run(["wg", "setconf", selectedWGName, absWGPath])
                        print(f"Detected that selected WireGuard config is running\nReloaded wireguard interface {colored(selectedWGName, attrs=['bold'])}")
                    else:
                        print(f"Selected WireGuard config isn't running, skipping reload")
                    
                    print("Done!")
                    exit
                else:
                    cprint("Invalid input", 'red')
            except ValueError:
                cprint("Input needs to be a number", 'red')


if __name__ == "__main__":
    main()