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
## @package util
# utility functions
#
# $Id: util.py,v e7ea179b29d8 2015/05/25 04:28:23 sebastian $
# 
# Copyright (c) 2024 
# Author: Mitchell Lowe (101607237@student.swin.edu.au)
#         
# 

import os

import time
import config
from fabric2 import task, Connection
from invoke import run, put

def _copy_file(c, file_name='', remote_path='', method='put'):
    '''
    Copy file to remote hosts.

    Args:
        c (Connection): Fabric Connection object.
        file_name (str): Name of the file to be copied.
        remote_path (str): Path on the remote host where the file will be copied.
        method (str): Copy method ('put' or 'scp').
    '''
    if remote_path == '':
        remote_path = os.path.dirname(os.path.abspath(file_name))
    
    if method == 'scp':
        run(f'scp {file_name} {c.user}@{c.host}:{remote_path}')
    else:
        put(file_name, remote_path)


@task
def copy_file(c, file_name='', remote_path='', method='put'):
    '''
    Copy file to a specified set of hosts.
    Uses hosts specified on command line, or hosts specified in config

    Args:
        c (Connection): Fabric Connection object.
        file_name (str): Name of the file to be copied.
        remote_path (str): Path on the remote host where the file will be copied.
        method (str): Copy method ('put' or 'scp').
    '''
    if not c.host:
        # If no hosts are specified on the command, use all hosts specified in config
        hosts = config.TPCONF_router + config.TPCONF_hosts
        for host in hosts:
            conn = Connection(host)
            _copy_file(conn, file_name, remote_path, method)
    else:
        _copy_file(c, file_name, remote_path, method)


@task
def authorize_key(c: Connection):
    '''
    Add current user public key to authorized keys
    Assumes ~/.ssh/id_rsa.pub exists

    Args:
        c (Connection): Fabric Connection object.
    '''
    put('~/.ssh/id_rsa.pub', '/tmp')
    run(
        'touch ~/.ssh/authorized_keys && '
        'cat ~/.ssh/authorized_keys /tmp/id_rsa.pub > /tmp/authorized_keys && '
        'mv /tmp/authorized_keys ~/.ssh/authorized_keys && rm -f /tmp/id_rsa.pub',
        pty=False
    )


def _exec_cmd(c, cmd: str):
    '''
    General method to execute a command on a set of hosts

    Args:
        c (Connection): Fabric Connection object.
        cmd (str): Command to be executed.
    '''
    with c.cd():
        run(cmd, warn=True, pty=False)


@task
def exec_cmd(c, cmd=''):
    '''
    Execute specified command on specified set of hosts.

    Args:
        c (Connection): Fabric Connection object.
        cmd (str): Command to be executed.
    '''
    if not c.host:
        # If no hosts specified on the command, use all hosts specified in config
        hosts = config.TPCONF_router + config.TPCONF_hosts
        for host in hosts:
            conn = Connection(host)
            _exec_cmd(conn, cmd)
    else:
        _exec_cmd(c, cmd)