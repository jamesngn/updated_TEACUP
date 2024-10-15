# Copyright (c) 2013-2015 Centre for Advanced Internet Architectures,
# Swinburne University of Technology. All rights reserved.
#
# Author: Sebastian Zander (sebastian.zander@gmx.de)
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
## @package hostint
# Functions to determine the network interface based on an IP address
#
# $Id: hostint.py,v e7ea179b29d8 2015/05/25 04:28:23 sebastian $

import socket
import config

from fabric.api import task as fabric_task, warn, local, run, execute, abort, hosts, env, \
    puts
from hosttype import get_type_cached
from hostmac import get_netmac, get_netmac_cached

# UPDATED: 2024-10-10
from typing import List, Dict

from fabric2 import Connection, task as fabric_v2_task

from hosttype import get_type_cached_v2
from hostmac import get_netmac_v2, get_netmac_v2

## Map external IPs or host names to internal network interfaces
## (automatically populated) dictionary of lists since there can be more
## than one interface per host
host_internal_int: Dict[str, List[str]] = {}

## Map external IPs or host names to external network interfaces
## (automatically populated) dictionary of lists since there can be more
## than one interface per host
host_external_int: Dict[str, List[str]] = {}

## Map internal IPs or host names to external network interfaces
## (automatically populated)
host_external_ip = {}

for external, v in config.TPCONF_host_internal_ip.items():
    for internal in config.TPCONF_host_internal_ip[external]:
        host_external_ip.update({internal: external})


## Map external IPs or host names to internal Windows interfaces for
## windump (automatically populated)
host_internal_windump_int = {}

## Map external IPs or host names to internal Windows interfaces for
## windump (automatically populated)
host_external_windump_int = {}


## Get network interface (the first by default)
#  @param host Host name/identifier used by Fabric
#  @param int_no Interface number starting from 0 or -1 to get a list of
#               all interface
#  @param internal_int Set to '0' to get external interface,
#                     set to '1' to get internal interface(s) (default)
#  @return Interface name string, e.g. "em0"
def get_netint_cached(host='', int_no=0, internal_int='1'):
    global host_internal_int
    global host_external_int

    if internal_int == '1':
        if host not in host_internal_int:
            host_internal_int.update({host: []})
            for i in range(len(config.TPCONF_host_internal_ip[host])):
                host_internal_int[host].append(
                    execute(
                        get_netint,
                        int_no=i,
                        internal_int='1',
                        hosts=host)[host])

        res = host_internal_int.get(host, '')

        if int_no == -1:
            return res
        else:
            if len(res) > int_no:
                return [ res[int_no] ]
            else:
                return ['']

    else:
        if host not in host_external_int:
            host_external_int.update({host: []})
            host_external_int[host].append(
                execute(
                    get_netint,
                    int_no=0,
                    internal_int='0',
                    hosts=host)[host])

        res = host_external_int.get(host, '')

        return res

def get_netint_cached_v2(c: Connection, int_no: int = 0, internal_int: str = '1') -> List[str]:
    """
    Get network interface (the first by default).
    
    Args:
        c (Connection): Fabric connection object.
        host (str): Host name/identifier.
        int_no (int): Interface number starting from 0 or -1 to get a list of all interfaces.
        internal_int (str): Set to '0' to get external interface, '1' for internal interface(s) (default).

    Returns:
        List[str]: Interface name(s), e.g., "em0".
    """
    
    print(f"[{c.host}]: Executing get_netint_cached_v2")
    
    global host_internal_int, host_external_int
    
    if internal_int == '1':
        if c.host not in host_internal_int:
            host_internal_int.update({c.host: []})
            # Fetch the internal interfaces
            for i in range(len(config.TPCONF_host_internal_ip[c.host])):
                result = get_netint_v2(c,int_no=i,internal_int='1')
                host_internal_int[c.host].append(result.strip())

        res = host_internal_int.get(c.host, [])

        if int_no == -1:
            return res
        else:
            if len(res) > int_no:
                return [res[int_no]]
            else:
                return ['']
    else:
        if c.host not in host_external_int:
            host_external_int[c.host] = []
            # Fetch the external interfaces
            result = get_netint_v2(c,int_no=0,internal_int='0')
            host_external_int[c.host].append(result.strip())

        return host_external_int.get(c.host, [])

## Get network interface for windump (the first by default)
## We need this function since windump uses a differently ordered list than
## windows itself
#  @param host Host name/identifier used by Fabric
#  @param int_no Interface number starting from 0 or -1 to get a list of all
#               interfaces
#  @param internal_int Set to '0' to get external interface,
#                     set to '1' to get internal interface(s) (default)
#  @return Interface name string (which is always a number), e.g. "1"
def get_netint_windump_cached(host='', int_no=0, internal_int='1'):
    global host_internal_windump_int
    global host_external_windump_int

    # get type of current host
    htype = get_type_cached(env.host_string)

    if internal_int == '1':
        if htype == 'CYGWIN' and host not in host_internal_windump_int:
            host_internal_windump_int.update({host: []})
            for i in range(len(config.TPCONF_host_internal_ip[host])):
                host_internal_windump_int[host].append(
                    execute(
                        get_netint,
                        int_no=i,
                        windump='1',
                        internal_int='1',
                        hosts=host)[host])

        res = host_internal_windump_int.get(host, '')

        if int_no == -1:
            return res
        else:
            if len(res) > int_no:
                return [ res[int_no] ]
            else:
                return ['']

    else:
        if htype == 'CYGWIN' and host not in host_external_windump_int:
            host_external_windump_int.update({host: []})
            host_external_windump_int[host].append(
                execute(
                    get_netint,
                    int_no=0,
                    windump='1',
                    internal_int='0',
                    hosts=host)[host])

        res = host_external_windump_int.get(host, '')

        return res
    

def get_netint_windump_cached_v2(c: Connection, host: str = '', int_no: int = 0, internal_int: str = '1') -> List[str]:
    """
    Get network interface for windump (the first by default).
    We need this function since windump uses a differently ordered list than Windows itself.

    Args:
        c (Connection): Fabric connection object.
        host (str): Host name/identifier.
        int_no (int): Interface number starting from 0 or -1 to get a list of all interfaces.
        internal_int (str): Set to '0' to get external interface, '1' for internal interface(s) (default).

    Returns:
        List[str]: Interface name(s), e.g., "1".
    """
    
    print(f"[{c.host}]: Executing get_netint_windump_cached_v2")
    
    global host_internal_windump_int, host_external_windump_int

    # Get the type of the current host
    htype = get_type_cached_v2(c)

    if internal_int == '1':
        if htype == 'CYGWIN' and host not in host_internal_windump_int:
            host_internal_windump_int[host] = []
            # Fetch the internal interfaces
            for i in range(len(config.TPCONF_host_internal_ip[host])):
                result = get_netint_v2(c,int_no=i, windump='1', internal_int='1')
                host_internal_windump_int[host].append(result.strip())

        res = host_internal_windump_int.get(host, [])

        if int_no == -1:
            return res
        else:
            if len(res) > int_no:
                return [res[int_no]]
            else:
                return ['']
    else:
        if htype == 'CYGWIN' and host not in host_external_windump_int:
            host_external_windump_int[host] = []
            # Fetch the external interfaces
            result = get_netint_v2(c,int_no=0, windump='1', internal_int='0')
            host_external_windump_int[host].append(result.strip())

        return host_external_windump_int.get(host, [])



## Get host network interface name (TASK)
#  @param int_no Interface number starting from 0 (internal only)
#  @param windump Set to '0' to get interface names used by Windows, set to
#                 '1' get interface name used by windump
#  @param internal_int Set to '0' to get external interface,
#                      set to '1' to get internal interface(s) (default)
#  @return Interface name string, e.g. "em0"
@fabric_task
def get_netint(int_no=0, windump='0', internal_int='1'):
    "Get network interface name"

    # need to convert if we run task from command line
    int_no = int(int_no)

    # check int_no paramter
    if int_no < 0:
        int_no = 0
    if int_no >= len(config.TPCONF_host_internal_ip[env.host_string]):
        int_no = len(config.TPCONF_host_internal_ip[env.host_string]) - 1

    # get type of current host
    htype = get_type_cached(env.host_string)

    if htype == 'FreeBSD' or htype == 'Linux' or htype == 'Darwin':
        # get  ip and set last octet to 0
        if internal_int == '1':
            iip = config.TPCONF_host_internal_ip[env.host_string][int_no]
        else:
            iip = socket.gethostbyname(env.host_string.split(':')[0])

        a = iip.split('.')
        del a[3]
        iip = '.'.join(a)
        
        int_name = ''
        field_idx = -1
        lines = run('netstat -nr', shell=False)
        for line in lines.split('\n'):
                if line != '':
                    fields = line.split()
                    if len(fields) > 0 and fields[0] == 'Destination' and  \
                        int_name == '' :
                        for i in range(len(fields)) :
                            if fields[i] == 'Netif' :
                                field_idx = i 
                    if len(fields) > 0 and (fields[0].split('/')[0] == iip + '.0' or 
                                            fields[0].split('/')[0] == iip) :
                        int_name = fields[field_idx]

            #puts('Interface: %s' % int_name)
        return int_name

    elif htype == "CYGWIN":
        # on windows we have two numbers
        # windows numbering of interfaces
        # numbering used by windump

        if windump == '0':

            # get interface IPs and numbers
            output = run(
                'ipconfig | egrep "Local Area|IPv4" | grep -v "Tunnel"',
                pty=False)

            lines = output.split("\n")
            for i in range(0, len(lines), 2):
                int_num = lines[i].replace(":", "").split(" ")[-1]
                if int_num == "": # XXX not sure what we are doing here
                    int_num = "1"
                int_ip = lines[i + 1].split(":")[1].strip()

                if internal_int == '1' and int_ip == config.TPCONF_host_internal_ip[
                        env.host_string][int_no] or \
                   internal_int == '0' and int_ip == socket.gethostbyname(
                        env.host_string.split(':')[0]):
                    puts('Interface: %s' % int_num)
                    return int_num

        else:
            # get list of interface numbers and interface IDs
            output = run(
                'winDUmp -D | sed "s/\([0-9]\)\.[^{]*{\([^}]*\).*/\\1 \\2/"',
                pty=False)

            # get list of interface macs and interface IDs
            output2 = run(
                'getmac | '
                'grep "^[0-9]" | sed "s/^\([0-9A-Fa-f-]*\)[^{]*{\([^}]*\).*/\\1 \\2/"',
                pty=False)

            # get mac of the internal/external interface
            mac = execute(
                get_netmac,
                internal_int=internal_int,
                hosts=[env.host_string]).values()[0]

            # find interface ID
            int_id = ''
            lines = output2.split("\n")
            for line in lines:
                _int_mac, _int_id = line.split(' ')

		# get mac print with '-' instead of ':'
                _int_mac = _int_mac.replace('-', ':').lower()
                if _int_mac == mac:
                    int_id = _int_id
                    break

            # get interface number (could use ID but it's a bit long)
            lines = output.split("\n")
            for line in lines:
                _int_num, _int_id = line.split(' ')
                if _int_id == int_id:
                    puts('Interface: %s' % _int_num)
                    return _int_num

    else:
        abort('Cannot determine network interface for OS %s' % htype)
        
@fabric_v2_task
def get_netint_v2(c: Connection, int_no=0, windump='0', internal_int='1'):
    """
    Get network interface name.
    
    Args:
        c (Connection): Fabric 2 connection object for the host.
        int_no (int): Interface number starting from 0 (internal only).
        windump (str): Set to '0' to get interface names used by Windows, 
                       set to '1' to get interface name used by windump.
        internal_int (str): Set to '0' to get external interface,
                            set to '1' to get internal interface(s) (default).
    
    Returns:
        str: Interface name string, e.g. "em0".
    """
    
    print(f"[{c.host}]: Running get_netint_v2")
    
    # Need to convert if we run task from command line
    int_no = int(int_no)

    # Check int_no parameter
    if int_no < 0:
        int_no = 0
    if int_no >= len(config.TPCONF_host_internal_ip[c.host]):
        int_no = len(config.TPCONF_host_internal_ip[c.host]) - 1
        
    # get type of current host    
    htype = get_type_cached_v2(c)
    
    if htype in ['FreeBSD', 'Linux', 'Darwin']:
        # Get IP and set last octet to 0
        if internal_int == '1':
            iip = config.TPCONF_host_internal_ip[c.host][int_no]
        else:
            iip = socket.gethostbyname(c.host.split(':')[0])
            
        a = iip.split('.')
        del a[3]
        iip = '.'.join(a)
        
        int_name = ''
        field_idx = -1
        lines = c.run('netstat -nr').stdout
        for line in lines.split('\n'):
            if line:
                fields = line.split()
                if len(fields) > 0 and fields[0] == 'Destination' and int_name == '':
                    for i in range(len(fields)):
                        if fields[i] == 'Netif':
                            field_idx = i 
                if len(fields) > 0 and (fields[0].split('/')[0] == iip + '.0' or fields[0].split('/')[0] == iip):
                    int_name = fields[field_idx]
                    
        print(f'Interface: {int_name}')

        return int_name
    elif htype == 'CYGWIN':
        # On Windows we have two numbers: 
        # windows numbering of interfaces 
        # numbering used by windump
        
        if windump == '0':
            
            # Get interface IPs and numbers
            output = c.run('ipconfig | egrep "Local Area|IPv4" | grep -v "Tunnel"', hide=True).stdout
            
            lines = output.split("\n")
            for i in range(0, len(lines), 2):
                int_num = lines[i].replace(":", "").split(" ")[-1]
                if int_num == "":  # XXX not sure what we are doing here
                    int_num = "1"
                int_ip = lines[i + 1].split(":")[1].strip()

                if (internal_int == '1' and int_ip == config.TPCONF_host_internal_ip[c.host][int_no]) or \
                   (internal_int == '0' and int_ip == socket.gethostbyname(c.host.split(':')[0])):
                    print(f'Interface: {int_num}')
                    return int_num
    
        else:
             # Get list of interface numbers and interface IDs
            output = c.run('winDUmp -D | sed "s/\\([0-9]\\)\\.[^{]*{\\([^}]*\\).*/\\1 \\2/"', hide=True).stdout
            
             # Get list of interface MACs and interface IDs
            output2 = c.run('getmac | grep "^[0-9]" | sed "s/^\\([0-9A-Fa-f-]*\\)[^{]*{\\([^}]*\\).*/\\1 \\2/"', hide=True,echo=True, echo_format=f"[{c.host}]: run {{command}}").stdout


            # Get MAC of the internal/external interface
            mac = get_netmac_v2(c, internal_int=internal_int)
            
            # Find interface ID
            int_id = ''
            lines = output2.split("\n")
            for line in lines:
                _int_mac, _int_id = line.split(' ')
                # Convert MAC to lower case with colons
                _int_mac = _int_mac.replace('-', ':').lower()
                if _int_mac == mac:
                    int_id = _int_id
                    break

            # Get interface number (could use ID but it's a bit long)
            lines = output.split("\n")
            for line in lines:
                _int_num, _int_id = line.split(' ')
                if _int_id == int_id:
                    print(f'Interface: {_int_num}')
                    return _int_num
    else:
        raise RuntimeError(f'Cannot determine network interface for OS {htype}')

            


    


## Get testbed address of host if parameter host is external address,
## otherwise return given address
#  @param host External (or internal) address or host name
#  @return FIRST testbed address if host is external address, host if 
#          host is external address
def get_internal_ip(host):
    addresses = config.TPCONF_host_internal_ip.get(host, [])
    if len(addresses) > 0:
        iaddr = addresses[0]
    else:
        iaddr = host

    return iaddr

def get_internal_ip_v2(host: str) -> str:
    """
    Get the testbed internal address of the host if the provided host is an external address.
    If the host is an internal address, return the host as is.

    Args:
        host (str): The external or internal address or hostname.

    Returns:
        str: The first internal testbed address if the host is an external address, 
             or the given host if it's already an internal address.
    """
    # Get internal IP addresses from the configuration, defaulting to an empty list if not found
    addresses = config.TPCONF_host_internal_ip.get(host, [])

    # Return the first internal address if available, otherwise return the provided host
    return addresses[0] if addresses else host



## Get host external IP or host name for an internal/testbed address or host name
#  @param ihost Internal address or host name
#  @param do_abort Set to '0' do not abort if no external address found, set to 
#                  '1' abort if no external address found
#  @return External address
def get_external_ip(ihost, do_abort='1'):

    # return dummy value if prefix is present, should only happen if called
    # from init_pipe() and in this case we _don't_ need any external address
    if ihost.find('/') > -1:
        return 'invalid'

    addr = host_external_ip.get(ihost, '')
    if addr == '' and do_abort == '1':
        abort('No external address for internal address %s' % ihost)

    return addr

def get_external_ip_v2(ihost: str, do_abort: bool = True) -> str:
    """
    Get the external IP or hostname for an internal/testbed address or hostname.

    Args:
        ihost (str): The internal address or hostname.
        do_abort (bool): If set to True, abort if no external address is found.
                         If False, return a default 'invalid' value.

    Returns:
        str: The external address or 'invalid' if no external address is found and do_abort is False.
    """
    # Return a dummy value if the prefix is present, which should only happen if called from init_pipe()
    if '/' in ihost:
        return 'invalid'

    # Fetch the external IP from the host_external_ip dictionary
    addr = host_external_ip.get(ihost, '')

    # If no address is found and abort is requested, raise an error
    if addr == '' and do_abort:
        raise ValueError(f'No external address for internal address {ihost}')

    return addr



## Get external and internal address
#  @param host Internal or external address
#  @param do_abort If set to '0' do not abort if no external address found, if 
#                  set to '1' abort if no external address found
#  @return tuple of  external address, internal address
def get_address_pair(host, do_abort='1'):

    internal = get_internal_ip(host)
    if internal == host:
        external = get_external_ip(host, do_abort)
    else:
        external = host

    return (external, internal)

def get_address_pair_v2(host: str, do_abort: bool = True) -> tuple:
    """
    Get the external and internal address for a given host.

    Args:
        host (str): The internal or external address.
        do_abort (bool): If set to True, abort if no external address is found.
                         If False, return the internal address even if no external address is found.

    Returns:
        tuple: A tuple containing the external address and internal address.
    """
    # Get the internal IP address
    internal = get_internal_ip_v2(host)
    
    # Determine the external address
    if internal == host:
        external = get_external_ip_v2(host, do_abort)
    else:
        external = host

    return external, internal



