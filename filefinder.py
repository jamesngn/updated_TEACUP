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
## @package filefinder
# Functions to find files (used by analysis functions) 
#
# $Id: filefinder.py,v d884760177c8 2015/11/05 09:46:53 s $
# 
# Copyright (c) 2024 
# Author: Mitchell Lowe (101607237@student.swin.edu.au)
#         
# 

import os
import config
from fabric import task
from invoke import run, UnexpectedExit
from internalutil import _list

# 
# Directory cache functions
#

## Cache file name
CACHE_FILE_NAME = 'teacup_dir_cache.txt'
## Cache
dir_cache = {}

## Read cachfile if exists
def read_dir_cache():
    '''
    Read cache file if it exists
    '''
    if not os.path.isfile(CACHE_FILE_NAME):
        return

    with open(CACHE_FILE_NAME, 'r') as f:
        lines = f.readlines()
        for line in lines:
            fields = line.split()
            dir_cache[fields[0]] = fields[1]


## Append to cache if entry not in there yet 
#  @param test_id Test ID
#  @param directory Directory which has files of the experiment with ID = test ID
def append_dir_cache(test_id, directory):

    if test_id not in dir_cache:
        try:
            with open(CACHE_FILE_NAME, 'a') as f:
                f.write(f'{test_id} {directory}\n')
        except Exception as e:
            # Handle file permission issues without crashing
            print(f"Warning: Could not write to cache file: {e}")


## Perform cache lookup, if we have entry for test id return directory. Otherwise
# return '.'
#  @param test_id Test ID
def lookup_dir_cache(test_id):

    # load cache first if cache is empty
    if len(dir_cache) == 0:
        read_dir_cache()

    if test_id in dir_cache:
        return dir_cache[test_id]
    else:
        return '.'


def filter_duplicates(file_list):
    '''
    Filter out duplicates (if we accidentally have copies lying around in different subdirectories)

    Args:
        file_list (list[str]): List of file names

    Returns:
        list[str]: The filtered list
    '''
    file_names = {}
    filtered_file_list = []

    for f in file_list:
        base_name = os.path.basename(f)
        if base_name not in file_names:
            file_names[base_name] = 1
            filtered_file_list.append(f)

    return filtered_file_list


def get_testid_file_list(c, file_list_fname='', test_id='', file_ext='', pipe_cmd='',
                         search_dir='.', no_abort=False):
    '''
    Return list of files that match search criteria

    Args:
        file_list_fname (str, optional): Name of file containing a list of full log file names . Defaults to ''.
        test_id (str, optional): Semicolon separated list of test ids. Defaults to ''.
        file_ext (str, optional): Characteristic rightmost part of file (file extension) we are searching for. Defaults to ''.
        pipe_cmd (str, optional): One or more shell command that are executed in pipe with the find command. Defaults to ''.
        search_dir (str, optional): Directory from where we start the search. Defaults to '.'.
        no_abort (bool, optional): 
            Set to false means abort if no matching files are found (default)
            
            Set to true means don't abort if no matching files are found.
            
            Defaults to False.

    Raises:
        Exit: If no test ids are provided
        Exit: If `file_list_fname` fails to open
        Exit: If the provided file names cannot be found

    Returns:
        list: List of matching files found
    '''
    
    file_list = []

    if pipe_cmd != '':
        pipe_cmd = ' | ' + pipe_cmd

    # if search dir is not specified try to find it in cache
    if search_dir == '.':
        search_dir = lookup_dir_cache(test_id)

        # if not in cache try to locate the directory based on the uname file
        if search_dir == '.':
            _files = _list(
                run(
                    f'find -L {search_dir} -name "{test_id}*uname.log*" -print | sed -e "s/^\.///"{pipe_cmd}',
                    hide=True).stdout.splitlines())
            if len(_files) > 0:
                search_dir = os.path.dirname(_files[0])
                append_dir_cache(test_id, search_dir)

    if file_list_fname == '':
        # read from test_id list specified, this always overrules list in file if
        # also specified

        test_id_arr = test_id.split(';')

        if len(test_id_arr) == 0 or test_id_arr[0] == '':
            raise ValueError('Must specify test_id parameter')

        for test_id in test_id_arr:
            _files = _list(
                run(
                    f'find -L {search_dir} -name "{test_id}*{file_ext}" -print | sed -e "s/^\.///"{pipe_cmd}',
                    hide=True).stdout.splitlines())

            _files = filter_duplicates(_files)
 
            file_list += _files
    else:
        # read list of test ids from file 

        try:
            lines = []
            with open(file_list_fname) as f:
                lines = f.readlines()
            for fname in lines:
                fname = fname.rstrip()
                _files = _list(
                    run(
                        f'find -L {search_dir} -name "{fname}" -print | sed -e "s/^\.///"',
                        hide=True).stdout.splitlines())

                _files = filter_duplicates(_files)

                file_list += _files

        except IOError:
            raise ValueError(f"Cannot open experiment list file {file_list_fname}")

    if not no_abort and len(file_list) == 0:
        raise ValueError(f"Cannot find any matching data files.\nRemove outdated {CACHE_FILE_NAME} if files were moved.") 

    return file_list