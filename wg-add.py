import sys
import os
from typing import OrderedDict
import wgconfig
from wgconfig import wgexec
# import wireguard
from termcolor import colored, cprint
from pathlib import Path
from subnet import (
    IPv4Address,
    IPv6Address,
    IPv4Network,
    IPv6Network,
    ip_address,
    ip_network,
)

def main():
    # Check if program is being run as root
    if not 'SUDO_UID' in os.environ.keys():
        print("You need to execute this program as root")
        sys.exit(1)

    # Static vars
    wgConfPath = Path("/etc/wireguard")
    defaultExt = '.conf'
    prompt = "> "
    peersDir = "peers"

    wgList = []

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
        print("Please input the peer\'s name:")
        peerName = input(prompt)

        # Create peers dir if it doesn't exist yet
        os.makedirs(peersDir, exist_ok=True)
        peerFilePath = Path(peersDir, peerName + defaultExt)
        print(f"Peer file will be written to: {colored(peerFilePath, attrs=['bold'])}")
        
    
    elif selectedOperation.get('short') == 'delete':
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
                    print("Done!")
                    exit
                else:
                    cprint("Invalid input", 'red')
            except ValueError:
                cprint("Input needs to be a number", 'red')


if __name__ == "__main__":
    main()