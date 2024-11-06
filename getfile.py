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
## @package getfile
# Get log/dump file from remote
#
# $Id: getfile.py,v e7ea179b29d8 2015/05/25 04:28:23 sebastian $
# 
# Copyright (c) 2024 
# Author: Mitchell Lowe (101607237@student.swin.edu.au)
#         
# 

#Provides functions for interacting with the operating system, such as file operations.
import os
import subprocess
from fabric import Connection
from hosttype import get_type_cached


## Get MD5 hash for file
#  @param file_name Name of the file to compute MD5 over
#  @param for_local If '0' run on remote host, fi '1' run on local host
#  @return MD5 hash
# Computes the MD5 hash of a file. It determines the appropriate command to use based on the host's operating system (FreeBSD/Darwin, Linux/CYGWIN) and executes it either locally or remotely.
def _get_md5val(file_name='', for_local='0', c=None):
    "Get MD5 hash for file depending on OS"

    # get type of current host
    htype = get_type_cached(c.host, for_local)

    if htype in ['FreeBSD', 'Darwin']:
        md5_command = f"md5 {file_name} | awk '{{ print $NF }}'"
    elif htype in ['Linux', 'CYGWIN']:
        md5_command = f"md5sum {file_name} | awk '{{ print $1 }}'"
    else:
        md5_command = ''

    if for_local == '1':
        md5_hash = c.run(md5_command, hide=True)
    else:
        md5_hash = c.run(md5_command, hide=True, pty=False)

    return md5_hash.stdout.strip()

## Collect log file
#  @param file_name Name of the log file
#  @param local_dir Local directory to copy log file into
# Retrieves a file from the remote server. It constructs the full path of the file on the remote server if necessary, 
#compresses the file using gzip, downloads it to the specified local directory, calculates the MD5 hash on the remote 
#and local files, compares them, and removes the compressed file from the remote server.
def getfile(c, file_name='', local_dir='.'):
    "Get file from remote and check that file is not corrupt"

    if not file_name:
        raise ValueError('Must specify file name')
    #if not file_name:
       # raise ValueError('Must specify file name')

    if file_name[0] != '/':
        # get type of current host
        htype = get_type_cached(c.host)

        # need to guess the path
        if c.user == 'root' and htype != 'CYGWIN':
            remote_dir = '/root'
        else:
            remote_dir = f'/home/{c.user}'

        file_name = f'{remote_dir}/{file_name}'
    else:
        remote_dir = os.path.dirname(file_name)
       #remote_dir = '/root' if env.user == 'root' and not htype == 'CYGWIN' else f'/home/{env.user}'
       #file_name = os.path.join(remote_dir, file_name)



    # gzip and download (XXX could use bzip2 instead, slower but better
    # compression)
    c.run(f'gzip -f {file_name}', pty=False)
    #run('gzip -f {file_name}', pty=False)
    file_name += '.gz'
    local_file_name = c.get(file_name, local_dir)[0]

    # get MD5 on remote
    md5_val = _get_md5val(c, file_name, '0')
    if md5_val:
        # get MD5 for downloaded file
        local_md5_val = _get_md5val(None, local_file_name, '1')
        # check if MD5 is correct
        if md5_val != local_md5_val:
            raise ValueError('Failed MD5 check')
        else:
            print('MD5 OK')

    c.run(f'rm -f {file_name}', pty=False)
    #if md5_val:
     #   local_md5_val = _get_md5val(local_file_name, '1')
      #  if md5_val != local_md5_val:
       #     raise ValueError('Failed MD5 check')
        #else:
         #   print('MD5 OK')

   # run(f'rm -f {file_name}', pty=False)
##The getfile function first checks if a file name is provided and constructs the full remote file path if necessary.
#It then compresses the file using gzip on the remote server.
#The compressed file is then downloaded to the local directory specified.
#MD5 hashes are calculated for both the remote and local files using the _get_md5val function.
#If the MD5 hashes match, it prints "MD5 OK"; otherwise, it aborts the process.
#Finally, it removes the compressed file from the remote server.