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
## @package hosttype
# Functions to determine the type of host
#
# $Id: hosttype.py,v e7ea179b29d8 2015/05/25 04:28:23 sebastian $

from fabric2 import Connection, task as fabric_task_v2
from fabric.api import task, warn, local, run, execute, abort, hosts, hide

## Map external ips/names to OS (automatically determined)
host_os = {}

## OS of control host (automatically determined)
ctrl_host_os = ''


## Get host type and populate host_os, ctrl_host_os
#  @param host Host IP or name
#  @param for_local If '0' get type of remote host,
#                   if '1' get type of local host (where we execute script)
#  @return Operating system string, e.g. "FreeBSD" or "Linux" or "CYGWIN"
def get_type_cached(host='', for_local='0'):
    global host_os
    global ctrl_host_os

    if for_local == '1':
        if ctrl_host_os == '':
            ctrl_host_os = local('uname -s', capture=True)
        return ctrl_host_os
    else:
        if host not in host_os:
            host_os = dict(
                list(host_os.items()) +  # Convert to list for concatenation
                list(execute(
                    get_type,
                    hosts=host).items()))  # Convert to list for concatenation
        return host_os.get(host, '')

def get_type_cached_v2(c: Connection, for_local='0') -> str:
    """Get host type and populate host_os, ctrl_host_os

    Args:
        c (Connection): Fabric Connection object
        for_local (str, optional):  If '0' get type of remote host, if '1' get type of local host (where we execute script). Defaults to '0'.

    Returns:
        str: Operating system string, e.g. "FreeBSD" or "Linux" or "CYGWIN"
    """
    
    print(f"[{c.host}]: Running get_type_cached_v2")
    
    global host_os
    global ctrl_host_os
    
    host = c.host

    if for_local == '1':
        if ctrl_host_os == '':
            ctrl_host_os = c.local('uname -s', hide=True).stdout.strip()  # Correct way to capture local output
        return ctrl_host_os
    else:
        if host not in host_os:
            # Get the OS type from the remote host and store it in the dictionary
            os_type = get_type_v2(c)
            host_os[host] = os_type  # Store it in the host_os dictionary
        return host_os.get(host, '')

## Get host operating system type (TASK)
#  @return Operating system string, e.g. "FreeBSD" or "Linux" or "CYGWIN"
@task
def get_type():
    "Get type/OS of host, e.g. Linux"

    with hide('debug', 'warnings'):
        htype = run('uname -s', pty=False)

    # ignore Windows version bit of output
    if htype[0:6] == "CYGWIN":
        htype = "CYGWIN"

    return htype

@fabric_task_v2
def get_type_v2(c: Connection) -> str:
    """
    Get host operating system type (TASK)

    Args:
        c (Connection: Fabric Connection object

    Returns:
        str: Operating system string, e.g. "FreeBSD" or "Linux" or "CYGWIN"
    """
    
    print(f"[{c.host}]: Running get_type_v2")
    
    # Run the command and get the Result object
    result = c.run('uname -s', pty=False, echo=True, echo_format=f"[{c.host}]: {{command}}")
    
    # Extract the output from the result
    htype = result.stdout.strip()  # Remove any extra whitespace or newlines

    # Ignore Windows version bit of output
    if htype[0:6] == "CYGWIN":
        htype = "CYGWIN"

    return htype


## Clear host type cache
def clear_type_cache():
    print("Running clear_type_cache")
    
    global host_os

    host_os.clear()

