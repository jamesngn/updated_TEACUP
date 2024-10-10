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
## @package hostmac
# Functions to determine the MACs of the control interface
#
# $Id: hostmac.py,v e7ea179b29d8 2015/05/25 04:28:23 sebastian $

import re
import socket
import config

from fabric2 import Connection, task as fabric_task_v2
from invoke import UnexpectedExit

from fabric.api import task as fabric_task, warn, local, run, execute, abort, hosts, env
from hosttype import get_type_cached, get_type_cached_v2


## Map external IPs or host names to MAC addresses (automatically populated)
host_external_mac = {}


## Get network interface MAC
#  @param host Host name/identifier used by Fabric
#  @return Interface MAC string in lower case, e.g. "d4:85:64:bf:5c:90"
def get_netmac_cached(host=''):
    global host_external_mac

    if host not in host_external_mac:
        host_external_mac = dict(
            host_external_mac.items() +
            execute(
                get_netmac,
                hosts=host).items())

    res = host_external_mac.get(host, '')

    return res

def get_netmac_cached_v2(c:Connection) -> str:
    """
    Get network interface MAC address for the given host.
    
    Args:
        c (Connection): Fabric 2 connection object for the host
    
    Returns:
        str: MAC address of the network interface in lower case.
    """
    
    print(f"[{c.host}] Running get_netmac_cached_v2")
    
    global host_external_mac

    if c.host not in host_external_mac:
        try:
            # Establish a connection to the host
            # Execute the get_netmac task to fetch the MAC address
            mac = get_netmac_v2(c)

            # Store the MAC address in the global cache
            host_external_mac[c.host] = mac

        except UnexpectedExit as e:
            print(f"Error retrieving MAC address for {c.host}: {e}")
            return ''

    return host_external_mac.get(c.host, '')


## Get MAC of host internal/external network interface (TASK)
## Limitation: if env.host_string is localhost (e.g. VM connected via NAT)
## we return the MAC of the first interface
#  @param internal_int If '0' get MAC for internal interface (non-router only),
#                     if '1' get MAC for external/control interface (non-router only)
#  @return Interface MAC string in lower case, e.g. "d4:85:64:bf:5c:90"
@fabric_task
def get_netmac(internal_int='0'):
    "Get MAC address for external/ctrl network interface"

    # not so easy to get local mac address for all different OS
    # use following approach:
    # get all non-router macs via the router using arp -a
    # get router mac using ifconfig
    # if host is a vm which we access via localhost then use ifconfig not arp
    # method
    # XXX windows: getmac, ipconfig /all

    host_string = env.host_string

    # if we have a port then strip off port
    if host_string.find(':') > -1:
        host_string = host_string.split(':')[0]

    if host_string == 'localhost':
        host_string = '127.0.0.1'

    if host_string in config.TPCONF_router or host_string == '127.0.0.1':
        # get MAC of router

        htype = get_type_cached(env.host_string)

        # complicated awk code to get pairs of ip and mac addresses from
        # ifconfig
        if htype == 'FreeBSD':
            macips = run(
                'ifconfig | awk \'/ether / { printf("%s ", $0); next } 1\' | ' +
                'grep ether | grep "inet " | ' +
                'awk \'{ printf("%s %s\\n", $2, $4) }\'',
                shell=False)
        elif htype == 'Linux':
            macips = run(
                'ifconfig | awk \'/HWaddr / { printf("%s ", $0); next } 1\' | ' +
                'grep HWaddr | grep "inet " | ' +
                'awk \'{ printf("%s %s\\n", $5, $7) }\' | sed -e "s/addr://"')
        else:
            abort("Can't determine MAC address for OS %s" % htype)

        ip_mac_map = {}
        for line in macips.split('\n'):
            a = line.split(' ')
            ip_mac_map.update({a[1].strip(): a[0].strip()})
        # print(ip_mac_map)

        # check if it looks like a name
        if not re.match('[0-9.]+', host_string):
            # try dns and assume we get an answer
            ip = socket.gethostbyname(host_string) 
        else:
            ip = host_string

        if ip != '127.0.0.1':
            mac = ip_mac_map.get(ip)
        else:
            # guess it's the first NIC
            # XXX should return MAC based on router IP, not simply the first
            mac = ip_mac_map.get(ip_mac_map.keys()[0])

    else:
        # get MAC of non-router

        if internal_int == '0':
            host_string = env.host_string
        else:
            host_string = config.TPCONF_host_internal_ip.get(
                env.host_string,
                '')[0]
        mac = execute(_get_netmac, host_string.split(':')[0], 
            hosts = [ config.TPCONF_router[0] ])[config.TPCONF_router[0]]

    return mac.lower()


@fabric_task_v2
def get_netmac_v2(c: Connection, internal_int='0') -> str:
    """
    Get MAC address of the host's internal or external network interface.

    Args:
        c (Connection): Fabric 2 connection object for the host.
        internal_int (str): If '0', get the MAC address for the internal interface (non-router only).
            If '1', get the MAC address for the external/control interface (non-router only).
    
    Returns:
        str: MAC address string.
    """
    
    print(f"[{c.host}] Running get_netmac_v2 for internal_int={internal_int}")

    host_string = c.host

    # if we have a port then strip off port
    if ':' in host_string:
        host_string = host_string.split(':')[0]
        
     # Set localhost if necessary
    if host_string == 'localhost':
        host_string = '127.0.0.1'
        
    if host_string in config.TPCONF_router or host_string == '127.0.0.1':
        # Get the MAC address of the router

        htype = get_type_cached_v2(c)
        
        # complicated awk code to get pairs of ip and mac addresses from
        # ifconfig
        if htype == 'FreeBSD':
            macips = c.run(
                "ifconfig | awk '/ether / { printf(\"%s \", $0); next } 1' | "
                "grep ether | grep 'inet ' | "
                "awk '{ printf(\"%s %s\\n\", $2, $4) }'",
                hide=True, echo=True, echo_format=f"[{c.host}]: {{command}}").stdout
        elif htype == 'Linux':
            # macips = c.run(
            #     "ifconfig | awk '/HWaddr / { printf(\"%s \", $0); next } 1' | "
            #     "grep HWaddr | grep 'inet ' | "
            #     "awk '{ printf(\"%s %s\\n\", $5, $7) }' | sed -e 's/addr://'",
            #     pty=False, echo=True, echo_format=f"[{c.host}]: {{command}}").stdout.strip()
            
            macips = c.run(
                "ifconfig eth0 | awk '/ether/ {mac=$2} /inet / && !/inet6/ {ip=$2} END {if (mac && ip) print mac, ip}' | sed -e 's/addr://'",
                pty=False, echo=True, echo_format=f"[{c.host}]: {{command}}").stdout.strip()
            
            
            
        else:
            raise RuntimeError(f"Can't determine MAC address for OS {htype}")

        ip_mac_map = {}
        for line in macips.split('\n'):
            if line:
                a = line.split(' ')
                ip_mac_map[a[1].strip()] = a[0].strip()
                
        print (f"[{c.host}]: IP-MAC map: {ip_mac_map}")
                
        # Resolve hostname to IP if necessary
        print(f"[{c.host}]: Resolving IP for {host_string}")
        if not re.match(r'[0-9.]+', host_string):
            ip = socket.gethostbyname(host_string)  # Try DNS resolution
        else:
            ip = host_string
            
        print(f"[{c.host}]: Resolved IP: {ip}")

        if ip != '127.0.0.1':
            mac = ip_mac_map.get(ip)
        else:
            # Guess it's the first NIC
            mac = list(ip_mac_map.values())[0] if ip_mac_map else None
            
        print(f"[{c.host}]: MAC address: {mac}")

    else:
        # Get MAC of non-router
        if internal_int == '0':
            host_string = c.host
        else:
            host_string = config.TPCONF_host_internal_ip.get(c.host, [None])[0]
            
        print(f"[{c}]: Getting MAC address for {host_string} from router {config.TPCONF_router[0]}")

        mac = _get_netmac_v2(c, host_string)


    print(f"[{c.host}]: Returning MAC address: {mac.lower() if mac else None}")

    return mac.lower() if mac else None


## Get MAC address of non-router by pinging host (and thereby populating the
## ARP table) and reading the MAC from the ARP table on the first router
#  @param host Host to get MAC for
@fabric_task
def _get_netmac(host=''):

    htype = get_type_cached(env.host_string)

    # resolve to ip if name
    host = socket.gethostbyname(host)

    # populate arp table
    run('ping -c 1 %s' % host)

    # get mac address
    if htype == 'FreeBSD':
        mac = run("arp %s | cut -d' ' -f 4 | head -1" % host)
    elif htype == 'Linux':
        mac = run("arp -a %s | cut -d' ' -f 4 | head -1" % host)
    else:
        abort("Can't determine MAC address for OS %s" % htype)

    return mac


@fabric_task_v2
def _get_netmac_v2(c: Connection, host='') -> str:
    """
    Get MAC address of non-router by pinging the host (and thereby populating the ARP table)
    and reading the MAC from the ARP table on the first router.

    Args:
        c (Connection): Fabric 2 connection object for the host.
        host (str): Hostname or IP address to get the MAC address for.
    
    Returns:
        str: MAC address string.
    """
    
    htype = get_type_cached_v2(c)  # Get the host type using the Fabric 2 connection

    # Resolve hostname to IP if necessary
    host_ip = socket.gethostbyname(host)
    
    # Populate ARP table by pinging the host
    c.run(f'ping -c 1 {host_ip}', hide=True, echo=True, echo_format=f"[{c.host}]: {{command}}")

    # Get MAC address from the ARP table depending on the OS type
    if htype == 'FreeBSD':
        mac = c.run(f"arp {host_ip} | cut -d' ' -f 4 | head -1", hide=True, echo=True, echo_format=f"[{c.host}]: {{command}}").stdout.strip()
    elif htype == 'Linux':
        mac = c.run(f"arp -a {host_ip} | cut -d' ' -f 4 | head -1", hide=True, echo=True, echo_format=f"[{c.host}]: {{command}}").stdout.strip()
    else:
        raise RuntimeError(f"Can't determine MAC address for OS {htype}")

    return mac