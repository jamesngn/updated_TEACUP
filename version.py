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
## @package version
# Print version number and revision info
#
# $Id: version.py,v ebb0800b2910 2015/05/26 01:07:47 sebastian $
# 
# Copyright (c) 2024 
# Author: Mitchell Lowe (101607237@student.swin.edu.au)
#         
# 

import os
import sys
from invoke import run
import config
from fabric2 import Connection, Config, task

## Print out TEACUP version (TASK)
@task
def get_version(c):
    '''
    Print TEACUP version information.
    '''
    # Print version info from VERSION file
    sys.stdout.write('TEACUP Version ')
    version_file_path = os.path.join(config.TPCONF_script_path, 'VERSION')
    with open(version_file_path, 'r') as f:
        ver_info = f.readlines()

    # If no revision info in VERSION, possibly a checked-out copy.
    # Try to get hg revision info.
    if 'NN:MMMMMMMMMMMM' in ver_info[1]:
        if os.path.exists(os.path.join(config.TPCONF_script_path, '.hg/')):
            curr_dir = os.getcwd()
            try:
            # Change to the script path and get the revision info using the script

                os.chdir(config.TPCONF_script_path)
                rev_info = run('./get_hg_info.sh', hide=True).stdout
            finally:
                 # Go back to the original directory
                os.chdir(curr_dir)
            ver_info = [ver_info[0] + rev_info + '\n']

    sys.stdout.writelines(ver_info)
    sys.stdout.write('Copyright (c) 2013-2015 Centre for Advanced Internet Architectures\n')
    sys.stdout.write('Swinburne University of Technology. All rights reserved.\n')