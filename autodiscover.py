import requests
import urllib3
urllib3.disable_warnings()
import multiprocessing
import itertools
import quantaskylake
import sys
from netmiko import ConnectHandler
import cisconexus
import brocadefc
import aristaeos
from pexpect.popen_spawn import PopenSpawn
import pexpect
import socket
import lawcompliance
import time
import minios
import esxi
import copy
import concurrent.futures
import badtime
import helper
import json
import networkconfig
import vsphere
import prettytable
import ipaddress
import atos

# SubModule Logging
import logging
logger = logging.getLogger(__name__)

def getPassword(theinput = "default"):
    thedict = {
        "default" : "UCPMSP.",
        "esxi" : "UCPESXI."
    }
    return thedict[theinput]

def getNICInterfaces():
    interfacelist = []
    if 'win' in sys.platform:
        # Start route print
        session = PopenSpawn('route print')
        # Get output from session
        output = session.read(2000)
        # Convert to utf-8
        output = output.decode('utf-8')
        # Split by =====
        output = output.split('===========================================================================')
        if len(output) < 4:
            raise ValueError('Route print returned incorrect output.')
        # Get Interface Line and parse output
        for line in output:
            # Go to line with Interface List string
            if 'Interface List' in line:
                # Split everything by newline
                splitline = line.splitlines()
                # Remove lines without ...
                # https://stackoverflow.com/questions/3416401/removing-elements-from-a-list-containing-specific-characters
                splitline = [x for x in splitline if "..." in x]
                # Get NIC Number and append to interfacelist
                for nic in splitline:
                    # Get the index number from line
                    index = nic[:3].lstrip()
                    # Once list gets to loopback, break
                    if index is '1':
                        break
                    # Add index to list
                    interfacelist.append(nic[:3].lstrip())
    # Assuming everything else is linux
    else:
        session = pexpect.spawn('ls /sys/class/net')
        output = session.read(2000)
        output = output.decode('utf-8')
        output = output.split()
        for item in output:
            if 'lo' not in item:
                interfacelist.append(item)
    return interfacelist

def getIPv6Neighbors(interface = None):
    # Get Interfaces if interface is None, otherwise program Interface from input
    NICs = []
    if interface is None:
        NICs = getNICInterfaces()
    else:
        NICs.append(str(interface))
    # Send link-local ping to each NIC
    print('Discovering IPv6 devices on the following interfaces:')
    print(NICs)
    # Set and start ping threads
    hosts = []
    if 'win' in sys.platform:
        for NIC in NICs:
            host = 'ff02::1%' + NIC
            hosts.append((host,))
        pool = multiprocessing.Pool(processes=10)
        pool.starmap(ping, hosts)
        pool.close()
        pool.join()
        # Get IPv6 Neighbors for each NIC
        IPv6Devices = []
        for NIC in NICs:
            print('Getting IPv6 Neighbors for NIC#' + NIC)
            # Get output from netsh command
            session = PopenSpawn('netsh interface ipv6 show neighbors ' + NIC)
            output = session.read(200000)
            # Split output by newlines
            splitline = output.splitlines()
            # Remove lines without ...
            # https://stackoverflow.com/questions/3416401/removing-elements-from-a-list-containing-specific-characters
            splitline = [x for x in splitline if b'fe80::' in x]
            # Create IPv6 Regular Expression
            for line in splitline:
                # Get IPv6 Device from line
                IPv6Device = line[:44].rstrip().decode("utf-8") + '%' + NIC
                print(IPv6Device)
                IPv6Devices.append(IPv6Device)
    # Assume everything else is linux platform
    else:
        IPv6Devices = []
        for NIC in NICs:
            session = pexpect.spawn('ping6 -c 2 ff02::1%' + str(NIC))
            session.wait()
            output = session.read(20000)
            output = output.decode('utf-8')
            output = output.splitlines()
            for line in output:
                if line.startswith("64 bytes from fe80:"):
                    IPv6Devices.append(line.split()[3][:-1] + '%' + str(NIC))

    #return IPv6Devices
    return ['fe80::dac4:97ff:feb6:b262%27','fe80::dac4:97ff:feb5:ccc7%27','fe80::dac4:97ff:feb6:b276%27']

def getIPv4Interfaces():
    cmd = "netsh interface ip show config"
    session = PopenSpawn(cmd)
    output = session.read(200000)
    lines = output.splitlines()
    intname = None
    intjson = {}
    outputjson = {}
    for line in lines:
        line = line.decode("utf-8")
        splited = line.split(': ')
        if "Configuration for interface " in line:
            intname = line.split("Configuration for interface ")[-1].replace('"',"")
            # print('Found ' + intname)
            intjson = {}
            continue
        elif "" == line:
            if intname is not None:
                outputjson.update({intname:intjson})
            intname = None
            intjson = {}
            continue

        if intname:
            intjson.update({splited[0].strip():splited[-1].strip()})

    return outputjson

def getIPv4Neighbors(interface = None):
    # Get all the interface details
    interfacedetails = getIPv4Interfaces()
    # Get the Interface Address
    if interface not in interfacedetails:
        raise Exception("Interface doesn't exist")
    else:
        interfacedetail = interfacedetails[interface]

    # Get the Subnet
    subnet = interfacedetail['Subnet Prefix'].split()[0]

    # If the check IP addresses list is longer than 512, return Error
    if int(subnet.split('/')[-1]) < 23:
        raise Exception("Too many IP Addresses to check")

    # Create the IP Obhect
    ipnetwork = ipaddress.IPv4Network(subnet)

    # Create List of IPAddresses
    iplist = list(ipnetwork)

    print('Looking for IPv4 neighbors on ' + str(ipnetwork))

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=128) as executor:
        futures = [executor.submit(pingIPv4, ipaddress) for ipaddress in iplist]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    # Remove the none results
    results = [ip for ip in results if ip]
    return results

def getARPTable():
    cmd = "arp -a"
    session = PopenSpawn(cmd)
    output = session.read(20000)
    output = output.decode('utf-8')
    lines = output.splitlines()
    macjson = {}
    for line in lines:
        if "dynamic" in line:
            splited = line.split()
            mac = splited[1].strip().replace("-","")
            mac = mac[0:4] + "." + mac[4:8] + "." + mac[8:12]
            macjson.update({splited[0].strip():mac})
    return macjson


def pingIPv4(host):
    session = PopenSpawn('ping -n 1 ' + str(host))
    output = session.read(2000)
    output = output.decode('utf-8')
    if "100% loss" in output or "timed out" in output or "unreachable" in output:
        return None
    else:
        return str(host)

# For ATOS only
def discoverIPv4Nodes(IPv4nodes = [], usernames=['super'], passwords=['pass']):
    arptable = getARPTable()

    # Create all combinations of commands with MAC address in middle
    tuples = []
    for combination in itertools.product(IPv4nodes, usernames, passwords):
        try:
            combination = combination[:1] + (arptable[combination[0]],) + combination[1:]
            tuples.append(combination)
        except:
            pass

    pool = multiprocessing.Pool(processes=30)
    results = pool.starmap(discoverIPv4NodeType, tuples)
    pool.close()
    pool.join()
    # https://stackoverflow.com/questions/16096754/remove-none-value-from-a-list-without-removing-the-0-value
    results = [x for x in results if x is not None]
    # Add forwarding ports for linux applications that do not support IPv6 Link-Local Addressing
    return results

def discoverIPv4NodeType(IPv4node, mac, username = 'super', password = 'pass'):
    # Check if IPMI Port is Open
    # https://stackoverflow.com/questions/4030269/why-doesnt-a-en0-suffix-work-to-connect-a-link-local-ipv6-tcp-socket-in-python
    '''
    addrinfo = socket.getaddrinfo(IPv4node, 623, socket.AF_INET, socket.SOCK_STREAM)
    (family, socktype, proto, canonname, sockaddr) = addrinfo[0]
    sock = socket.socket(family, socktype, proto)
    sock.settimeout(2)
    result = sock.connect_ex(sockaddr)
    sock.close()
    print(result)
    if result == 0:
        print('IPMI   ' + IPv4node)
    else:
        print('NoIPMI ' + IPv4node)
        return None
    '''

    passwords = [password]
    try:
        passwords.append(lawcompliance.generatepassword(mac, getPassword()))
    except:
        pass

    for password in passwords:
        print("Trying " + username + " " + password + " at " + IPv4node)
        IPMIPre = 'ipmitool -I lanplus -H ' + IPv4node + ' -U ' + username + ' -P ' + password + ' '
        cmd = IPMIPre + "fru print 0"
        try:
            session = PopenSpawn(cmd, timeout=5)
            output = session.read(2000)
        except:
            continue
        output = output.decode('utf-8')
        # print(output)
        if "Advanced Server DS7000" in output:
            print("Found DS7000 " + IPv4node)
            node = atos.AtosServer(IPv4node, username, password)
            node.mgmtMAC = mac
            return node

    return None

def ping(host):
    # For Windows, IPv6 neighbors can be discovered by sending a link-local packet across the whole L2 network.
    # Response time should be <1ms since the toolkit needs to physically be near the nodes.
    session = PopenSpawn('ping -w 1 -n 8 ' + host)
    output = session.read(2000)
    output = output.decode('utf-8')
    print(output)
    return output

def discoverNodes(IPv6nodes, usernames=['admin'], passwords=['cmb9.admin']):
    print('Starting Quanta Discovery against ' + str(len(IPv6nodes)) + ' IPv6 Devices')
    # time.sleep(5)

    # Create all combinations of commands
    tuples = []
    for combination in itertools.product(IPv6nodes, usernames, passwords):
        tuples.append(combination)

    pool = multiprocessing.Pool(processes=30)
    results = pool.starmap(discoverNodeType, tuples)
    pool.close()
    pool.join()
    # https://stackoverflow.com/questions/16096754/remove-none-value-from-a-list-without-removing-the-0-value
    results = [x for x in results if x is not None]
    # Add forwarding ports for linux applications that do not support IPv6 Link-Local Addressing
    return results

def discoverNodeType(IPv6node, username, password):
    # Output the address, username and password
    temp = IPv6node + ' ' + username + ' ' + password
    print('Start  ' + temp)

    # Check if IPMI Port is Open
    # https://stackoverflow.com/questions/4030269/why-doesnt-a-en0-suffix-work-to-connect-a-link-local-ipv6-tcp-socket-in-python
    addrinfo = socket.getaddrinfo(IPv6node, 623, socket.AF_INET6, socket.SOCK_STREAM)
    (family, socktype, proto, canonname, sockaddr) = addrinfo[0]
    sock = socket.socket(family, socktype, proto)
    sock.settimeout(0.1)
    result = sock.connect_ex(sockaddr)
    sock.close()
    if result == 0:
        print('IPMI   ' + IPv6node)
    else:
        print('NoIPMI ' + IPv6node)
        return None

    # Set the address
    # Also %25 has to be used for URLs instead of % due to URL Encoding rules.
    redfishapi = 'https://[' + IPv6node.replace('%','%25') + ']/redfish/v1/'
    # Have to remove the lin-local zone ID for correct curl command
    redfishheader = {
        'Content-Type': 'application/json',
        'User-Agent': 'curl/7.54.0',
        'Host': '[' + IPv6node.split('%')[0] + ']'
    }

    # Attempt to login with two passwords
    passwords = [password, lawcompliance.passwordencode(IPv6node, getPassword())]
    session = None
    members = None

    for password in passwords:
        # Let user know we are checking this username and password
        temp = IPv6node + ' ' + username + ' ' + password
        print("Check  " + temp)

        # Attempt to connect. If specific force password change is required, change password.
        try:
            session = requests.get(redfishapi + 'Systems', auth=(username, password), verify=False,
                                   headers=redfishheader, timeout=30)
            try:
                j = session.json()
                if j['error']['code'] == "Base.1.0.PasswordChangeFromIPMI":
                    # Create a temp node and update the password. Destroy Node
                    tempNode = quantaskylake.QuantaSkylake(IPv6node, 'admin', 'cmb9.admin')
                    password = lawcompliance.passwordencode(IPv6node, getPassword())
                    # tempNode.forcePasswordChange(password)
                    print("CPASS  " + IPv6node + " Changing Password to " + password)
                    tempNode.forcePasswordChange(password)
                    del tempNode
            except:
                pass
            try:
                members = j['Members']
                break
            except:
                pass
        except:
            print('NoRF   ' + temp)
            continue

        '''
        # If Session is not good, return nothing
        if not session.ok:
            print('NoRF   ' + temp)
            session = None
            continue
        else:
            break
        '''
    # Return nothing if nothing is found
    if session is None or members is None:
        return None

    print('RFDATA ' + IPv6node + ' ' + str(j))

    # Loop through members and get first member
    for member in members:
        try:
            redfishapi = 'https://[' + IPv6node.replace('%','%25') + ']' + member['@odata.id']
            break
        except:
            # Return nothing if @odata.id key doesn't exist
            return None

    ''' Discover which type of node this is '''
    # Try to get first member details
    try:
        session = requests.get(redfishapi, auth=(username, password), verify=False,
                               headers=redfishheader, timeout=30)
    except:
        print('Error  ' + temp)
        return None
    # If Session is not good, return nothing
    if not session.ok:
        print('Error  ' + temp)
        return None

    # Attempt to decode JSON data
    try:
        j = session.json()
    except:
        # If return data isn't JSON, return nothing.
        print('Error  ' + temp)
        return None

    print('RFDATA ' + IPv6node + ' ' + str(j))

    # Attempt to get SKU Data
    try:
        SKU = j['SKU']
    except:
        print('NOSKU   ' + temp)
        return None

    if ' ' is SKU:
        cmd = 'ipmitool -I lanplus -H ' + IPv6node + ' -U ' + username + ' -P ' + password + ' fru print'
        session = PopenSpawn(cmd)
        output = session.read(2000)
        output = output.decode('utf-8')
        if 'Error' in output:
            print('ErrIPMI ' + temp)
            return None
        lines = output.splitlines()
        for line in lines:
            if 'Product Name' in line:
                try:
                    SKU = line.split(':', 1)[1].strip()
                    break
                except:
                    continue

    # Decode which node this is
    # If its a D52B Series, return Skylake Server
    if 'DS120' in SKU:
        print('Found  ' + temp)
        return quantaskylake.DS120(IPv6node, username, password)
    elif 'DS220' in SKU:
        print('Found  ' + temp)
        return quantaskylake.DS220(IPv6node, username, password)
    elif 'DS225' in SKU:
        print('Found  ' + temp)
        return quantaskylake.DS225(IPv6node, username, password)
    elif 'DS240' in SKU:
        print('Found  ' + temp)
        return quantaskylake.DS240(IPv6node, username, password)
    elif 'D52BV' in SKU:
        print('Found  ' + temp)
        return quantaskylake.D52BV(IPv6node, username, password)
    elif 'D52B' in SKU:
        print('Found  ' + temp)
        return quantaskylake.D52B(IPv6node, username, password)
    elif 'Q72D' in SKU:
        print('Found  ' + temp)
        return quantaskylake.Q72D(IPv6node, username, password)
    else:
        # If it doesn't match anything, return nothing
        print('QError ' + temp + ' SKU=\'' + SKU + '\'')
        return None

def discoverSwitches(IPv6Addresses, usernames=['admin'], passwords=['Passw0rd!']):
    print('Starting Switch Discovery against ' + str(len(IPv6Addresses)) + ' IPv6 Devices')
    # Create all combinations of commands
    tuples = []
    for combination in itertools.product(IPv6Addresses, usernames, passwords):
        tuples.append(combination)
    pool = multiprocessing.Pool(processes=30)
    results = pool.starmap(discoverSwitchType, tuples)
    pool.close()
    pool.join()
    # https://stackoverflow.com/questions/16096754/remove-none-value-from-a-list-without-removing-the-0-value
    results = [x for x in results if x is not None]
    # Add forwarding ports for linux applications that do not support IPv6 Link-Local Addressing
    return results

def discoverSwitchType(IPv6Address, username, password):
    # Attempt to login with two passwords
    passwords = [password, lawcompliance.passwordencode(IPv6Address, getPassword())]

    for password in passwords:
        # Output the address, username and password
        temp = IPv6Address + ' ' + username + ' ' + password
        print('Start  ' + temp)

        net_connect = None

        # SSH Into Switch as generic SSH device
        try:
            net_connect = ConnectHandler(device_type='terminal_server', ip=IPv6Address, username=username, password=password, timeout=30)
            break
        except:
            # If we failed to connect, return nothing
            print('Finish ' + temp)

    if net_connect is None:
        return None

    # Check for Cisco Nexus/Arista EOS switches and Brocade FOS
    cmds = ["show version", "chassisshow"]
    for cmd in cmds:
        try:
            output = net_connect.send_command(cmd, delay_factor=10, max_loops=50)
        except:
            output = 'Failed'
        # output = net_connect.send_command(cmd, delay_factor=5)
        # If Nexus 3048 is in output, return Nexus Object
        if 'Nexus 3048 Chassis' in output:
            print('Data   ' + IPv6Address + ' Found a Nexus3048 Switch')
            net_connect.disconnect()
            return cisconexus.Nexus3048(IPv6Address, username, password)
        # If the 9k YC switch is in the output, return 9k YC object.
        elif '93180YC-EX ' in output:
            print('Data   ' + IPv6Address + ' Found a Nexus93180YC-EX Switch')
            net_connect.disconnect()
            return cisconexus.Nexus93180YCEX(IPv6Address, username, password)
        # If the 9k LC switch is in the output, return 9k LC object.
        elif '93180LC-EX ' in output:
            print('Data   ' + IPv6Address + ' Found a Nexus93180LC-EX Switch')
            net_connect.disconnect()
            return cisconexus.Nexus93180LCEX(IPv6Address, username, password)
        # If the part number for a G620 is found, return G620 Object
        elif 'BROCAD0000G62' in output:
            print('Data   ' + IPv6Address + ' Found a G620 Switch')
            net_connect.disconnect()
            return brocadefc.G620(IPv6Address, username, password)
        # If their is a DCS-7010T-48-R in the output, return DCS7010 object
        elif '7010T' in output:
            print('Data   ' + IPv6Address + ' Found a DCS-7010 Switch')
            net_connect.disconnect()
            return aristaeos.DCS7010(IPv6Address, username, password)
        elif '7050SX3' in output:
            print('Data   ' + IPv6Address + ' Found a DCS-7050SX3 Switch')
            net_connect.disconnect()
            return aristaeos.DCS7050SX3(IPv6Address, username, password)
        elif '7050CX3' in output:
            print('Data   ' + IPv6Address + ' Found a DCS-7050CX3 Switch')
            net_connect.disconnect()
            return aristaeos.DCS7050CX3(IPv6Address, username, password)

def discoverOS(nodes, potentialpassword = "Passw0rd!"):
    print('Starting OS Discovery against ' + str(len(nodes)) + ' Server Devices')
    nodes = copy.deepcopy(nodes)
    instances = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        futures = [executor.submit(discoverOSType, node, potentialpassword) for node in nodes]
        for future in concurrent.futures.as_completed(futures):
            instances.append(future.result())

    return instances

def discoverOSType(node, potentialpassword = "Passw0rd!"):
    # The CTRL-C, Enter, and logout command in string format
    cmds = ['\x03', '\n', 'exit']
    count = 0
    tnode = copy.deepcopy(node)
    del node
    node = tnode
    while count < 10:
        # Attempt to get the login prompt output.
        # If Ubuntu is found, return MiniOS object. If ESXi is found, return ESXi object after logging in.
        output = ''
        for cmd in cmds:
            node.SOLActivate()
            node.SOLSession.sendline(cmd)
            time.sleep(2)
            node.SOLDeactivate()
            output += node.SOLSession.read(20000)
        if "Ubuntu" in output or "ubuntu" in output:
            print(node.host + " Found a MiniOS Instance")
            instance = minios.minios(node)
            instance.login()
            return instance
        elif "ESXi" in output:
            print(node.host + " Found a ESXi Instance")
            # The known passwords so far in UCP lineup
            passwords = [potentialpassword, lawcompliance.passwordencode(node.host, getPassword('esxi')), 'Passw0rd!', 'Hitachi2019!']
            instance = esxi.ESXi(node, 'root','')
            for password in passwords:
                print(node.host + " Attempting to log into ESXi with \"root\" and \"" + password + "\"")
                instance.password = password
                try:
                    instance.login()
                    print(node.host + " Logged into ESXi with \"root\" and \"" + password + "\" successfully")
                    return instance
                except:
                    print(node.host + " Failed to log into ESXi with \"root\" and \"" + password + "\"")
                    continue
            del instance
        else:
            print(node.host + " No OS detected. Waiting 30 seconds to try again")
            count += 1
            time.sleep(30)
            continue
    return None

def discover(nodesnum = 0, usernames = ['admin'], passwords = ['cmb9.admin']):
    nodesnum = int(nodesnum)
    # Get the nodes
    print('I\'m going to use all your NIC interfaces to detect IPv6 devices.')
    if nodesnum > 0:
        input('Hit enter to continue!')

    while True:
        nodes = None
        # Get Any Nodes
        nodes = discoverNodes(getIPv6Neighbors(), usernames, passwords)

        print('\nGetting IPv4 Addresses via IPv6 Link-Local Addresses')
        for node in nodes:
            node.getIPv4Address()
        print(' ')

        # Nodesnum override I.E. Just return any discovered node
        if nodesnum < 1:
            return nodes

        # Let the user know about the detected nodes
        if len(nodes) < 1:
            input('Uffff.... I wasn\'t able to detect any nodes man. Sorry about that. Hit enter to try again.')
        elif len(nodes) != int(nodesnum):
            input('Uh oh, I have detected a ' + str(len(
                nodes)) + ' node(s) in the rack, instead of ' + str(nodesnum) + '.\nPlease make sure all the BMC connections are connected or disconnected on the same flat network. Hit enter to try again.')
        else:
            input('Perfect! I have detected ' + str(len(nodes)) + '!!! Hit enter to continue!')
            return nodes
'''
test = discoverType('fe80::aa1e:84ff:fea5:339b%enp0s8', 'admin', 'cmb9.admin')

test = discoverType('fe80::aa1e:84ff:fea5:32c9%13', 'admin', 'cmb9.admin')
print(test)

testfunc()

test = discoverSwitchType('fe80::a23d:6fff:fefe:2b40%13', 'admin', 'Passw0rd!')
print(test)
'''

def main():
    # Print welcome screen
    badtime.hitachi()
    badtime.version()

    print("This autodiscover tool will attempt to detect nodes, switches and the ESXi instances.\n\nPlease make sure all equipment is powered on")
    input("Hit enter to continue")

    # Ask the user which rack number they are working on
    racknum = helper.askRackNumber()

    # Ask the user how many nodes that rack has
    nodesnum = helper.askNodeQuantity()

    # Ask the user if there are any switches
    checkswitches = helper.askForSwitches()



    while True:
        # Get D52B Nodes
        nodes = discoverNodes(getIPv6Neighbors(), ['admin'], ['cmb9.admin'])

        logger.info('\nGetting IPv4 Addresses via IPv6 Link-Local Addresses')
        for node in nodes:
            node.getIPv4Address()
        logger.info(' ')

        # Let the user know about the detected nodes
        if len(nodes) < 1:
            input('Uffff.... I wasn\'t able to detect any nodes man. Sorry about that. Hit enter to try again.')
        elif len(nodes) != int(nodesnum):
            input('Uh oh, I have detected a ' + str(len(nodes)) + ' node(s) in the rack, instead of ' + nodesnum + '.\nPlease make sure all the BMC connections are connected or disconnected on the same flat network. Hit enter to try again.')
        else:
            print('Perfect! I have detected ' + str(len(nodes)) + '!!!')
            break
    '''
    ipv6addresses = [  # 'fe80::aa1e:84ff:fecf:34e',  # Leo
        # 'fe80::dac4:97ff:fe28:e25f', # Jose
        'fe80::aa1e:84ff:fe73:ba49%19',
        'fe80::dac4:97ff:fe1c:4d86%19',
        'fe80::dac4:97ff:fe1c:4e26%19'
        # 'fe80::dac4:97ff:fe28:ffa1',
        # 'fe80::dac4:97ff:fe28:e223',
        # 'fe80::aa1e:84ff:fea5:3418',
        # 'fe80::aa1e:84ff:fea5:3364',
        # 'fe80::dac4:97ff:fe29:82',
        # 'fe80::aa1e:84ff:fe73:ba35',
        # '%11'
    ]  # ENGR Rack

    temp_nodes = []
    for node in nodes:
        for address in ipv6addresses:
            if address in node.host:
                temp_nodes.append(node)

    nodes = temp_nodes

    '''

    if checkswitches:
        # Attempt to get rack details
        try:
            # Read the JSON File
            filename = "networkconfig.json"
            with open(filename) as json_file:
                networkconfigjson = json.load(json_file)
            rackjson = networkconfigjson['rack'][str(racknum)]
        except:
            logger.info("Rack #" + str(racknum) + " doesn't exist in the networkconfig.json file. Please make sure you enter the correct rack number.")
            return False
        # Discover the switches
        switches = discoverSwitches(getIPv6Neighbors(), ['admin'], ['Passw0rd!'])
        UCPNet = networkconfig.networkstack(racknum, switches, networkconfigjson)
        UCPNet.detectOrder()
        UCPNet.getDetails()
    else:
        UCPNet = None

    answer = input("Shall I attempt to detect ESXi instances? (y/n) :")
    if "y" in answer or "Y" in answer:
        logger.info("Attempting to detect OS nodes")
        detectESXi = True
    else:
        detectESXi = False

    thecluster = None
    if detectESXi:
        # Create vSphere Cluster object
        thecluster = vsphere.cluster()
        # Detect the ESXi instances within nodes
        thecluster.detectESXi(nodes)
        # Get the details (Mainly for ipv4 details)
        thecluster.getDetails()

    # Print out the username and passwords
    thetable = prettytable.PrettyTable()
    thetable.field_names = ["Equipment Type", "Name", "Serial", "IPv4 Address", "Username", "Password"]
    thetable.sortby = "Name"

    # Populate Node Details
    for node in nodes:
        thetable.add_row([str(type(node).__name__), node.host, node.SystemsJSONCache['SerialNumber'], node.ipv4Address, node.username, node.password])

    # Populate Switch Details
    if UCPNet:
        for switch in UCPNet.switches_cache:
            thetable.add_row([str(type(switch).__name__), switch.name, "N/A", switch.hostIPv4Address, switch.username, switch.password])

    # Populate ESXi Details
    if thecluster:
        for instance in thecluster.esxiinstances:
            thetable.add_row([str(type(instance).__name__), instance.node.host, instance.node.SystemsJSONCache['SerialNumber'], instance.ipv4Interfaces[0]["IPv4 Address"], instance.user, instance.password])

    print(thetable)
if __name__ == "__main__":
    count = 0
    main()
