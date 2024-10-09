# Copyright (c) 2013-2015 Centre for Advanced Internet Architectures,
# Swinburne University of Technology. All rights reserved.
#
# Author: Sebastian Zander (sebastian.zander@gmx.de)
#         Grenville Armitage (garmitage@swin.edu.au)
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
## @package analyseutil
# Analyse utility functions 
#
# $Id: analyseutil.py,v 1920bf13a9bf 2018/02/07 09:03:39 garmitage $

import os
import errno
import time
import datetime
import re
import importlib.util
import tempfile
from fabric.api import task, warn, put, puts, get, local, run, execute, \
    settings, abort, env, runs_once, parallel, hide

import config
from internalutil import mkdir_p
from hostint import get_address_pair
from filefinder import get_testid_file_list

import gzip


## Figure out directory for output files and create if it doesn't exist
## If out_dir is a relative path, the actual out_dir will be the directory where
## the file fname is concatenated with out_dir. If out_dir is an absolute path
## then the final out_dir will be out_dir. 
#  @param fname Path name of file
#  @param out_dir Output directory supplied by user
#  @return Path name
def get_out_dir(fname, out_dir):

    #print(fname, out_dir)
    if out_dir == '' or out_dir[0] != '/':
        dir_name = os.path.dirname(fname)
        out_dir = dir_name + '/' + out_dir

    if len(out_dir) > 0 and out_dir[-1] != '/':
        out_dir += '/'

    mkdir_p(out_dir)

    return out_dir


## Get graph output file name
#  @param test_id_arr List of test IDs
#  @param out_name Output file name prefix
#  @return Output file name
def get_out_name(test_id_arr=[], out_name=''):
    if len(test_id_arr) > 1:
        if out_name != '':
            return out_name + '_' + test_id_arr[0] + '_comparison'
        else:
            return test_id_arr[0] + '_comparison'
    else:
        if out_name != '':
            return out_name + '_' + test_id_arr[0]
        else:
            return test_id_arr[0]


## Check number of data rows and include file if over minimum
#  @param fname Data file name
#  @param min_values Minimum number of values required
#  @return True if file has more than minimum rows, False otherwise
def enough_rows(fname='', min_values='3'):

    min_values = int(min_values)

    #rows = int(local('wc -l %s | awk \'{ print $1 }\'' %
    #               fname, capture=True))
    rows = 0
    with open(fname, 'r') as f:
        while f.readline():
            rows += 1
            if rows > min_values:
                break

    if rows > min_values:
        return True
    else:
        return False


## Filter out data files with fewer than min_values data points
#  @param files File names indexed by flow names
#  @param groups Group ids indexed by file names
#  @param min_values Minimum number of values required
#  @return Filtered file names and groups
def filter_min_values(files={}, groups={}, min_values='3'):

    out_files = {}
    out_groups = {}

    for name in files:
        fname = files[name]

        if isinstance(fname, list) :
            # the ackseq method actually creates a name to list of file names
            # mapping, i.e. multiple file names per dataset name
            for _fname in fname:
                if enough_rows(_fname, min_values):
                    if not name in out_files:
                        out_files[name] = []
                    out_files[name].append(_fname)
                    out_groups[_fname] = groups[_fname]

        else:
            if enough_rows(fname, min_values):
                out_files[name] = fname
                out_groups[fname] = groups[fname]

    return (out_files, out_groups)



## Extract data per incast burst
#  @param data_file File with data
#  @param burst_sep Time between bursts (0.0 means no burst separation)
#  @param normalize 0: leave metric values as they are (default)
#                  1: normalise metric values on first value or first value
#                     fo each burst (if burst_sep > 0.0)        
#  @return List of file names (one file per burst)
def extract_bursts(data_file='', burst_sep=0.0, normalize=0):

    # New filenames (source file + ".0" or ".1,.2,....N" for bursts)
    new_fnames = []

    # Internal variables
    burstN = 1
    firstTS = -1
    prev_data = -1

    if burst_sep == 0.0 and normalize == 0:
        new_fnames.append(data_file)
        return new_fnames

    try:
            lines = []
            # First read the entire contents of a data file, using
            # gzip.open() if the extract_* task has generated .gz
            # intermediate files.
            if data_file.endswith(".gz"):
                gzip_output = 1
                with gzip.open(data_file) as f:
                    lines = f.readlines()
            else:
                gzip_output = 0
                with open(data_file) as f:
                    lines = f.readlines()

            # Create the first .N output file
            if burst_sep != 0 :
                out_fname = data_file + "." + "1"
            else:
                out_fname = data_file + "." + "0"
                
            if gzip_output:
                # Don't append .gz as the R script's burst handling
                # currently relies on the trailing ".N". Note that
                # R subsequentely auto-detects gzip'd file contents
                # without relying on .gz suffix.
                out_f = gzip.open(out_fname, "w")
            else:
                out_f = open(out_fname, "w")
                
            new_fnames.append(out_fname)

            # Now walk through every line of the data file
            for oneline in lines:
                # fields[0] is the timestamp, fields[1] is the statistic 
                fields = oneline.split()

                if firstTS == -1 :
                    # This is first time through the loop, so set some baseline
                    # values for later offsets
                    firstTS = fields[0]
                    prevTS = firstTS
                    if normalize == 1:
                        first_data = fields[1]
                    else:
                        first_data = '0.0'

                # If burst_sep == 0 the only thing we're calculating is a
                # cumulative running total, so we only do burst
                # identification if burst_sep != 0

                if burst_sep != 0 :

                    if burst_sep < 0 :
                        # gap is time since first statistic of this burst
                        # (i.e. relative to firstTS)
                        gap = float(fields[0]) - float(firstTS)
                    else:
                        gap = float(fields[0]) - float(prevTS)

                    # New burst begins when time between this statistic and previous
                    # exceeds abs(burst_sep)
                    if (gap >= abs(burst_sep)) :
                        # We've found the first one of the _next_ burst

                        # Close previous burst output file
                        out_f.close()

                        # Move on to the next burst
                        burstN += 1

                        print ("Burst: %3i, ends at %f sec, data: %f bytes, gap: %3.6f sec" %
                        ( (burstN - 1),  float(prevTS), float(prev_data) - float(first_data), gap ) )

                        # Reset firstTS to the beginning (first timestamp) of this new burst
                        firstTS = fields[0]

                        # first data value of next burst must be considered relative to the last 
                        # data value of the previous burst if we normalize 
                        if normalize == 1:
                            first_data = prev_data

                        # Create the next .N output file
                        out_fname = data_file + "." + str(burstN)
                        if gzip_output:
                            # Don't append .gz as the R script's burst handling
                            # currently relies on the trailing ".N". Note that
                            # R subsequentely auto-detects gzip'd file contents
                            # without relying on .gz suffix.
                            out_f = gzip.open(out_fname, "w")
                        else:
                            out_f = open(out_fname, "w")
                            
                        new_fnames.append(out_fname)
                        
                # data value (potentially normalised based on first value / first value of burst
                data_gap = float(fields[1]) - float(first_data)

                # Write to burst-specific output file
                # <time>  <data>
                out_f.write(fields[0] + " " + str(data_gap) + "\n")

                # Store the seq number for next time around the loop
                prev_data = fields[1]
                prevTS = fields[0]

            # Close the last output file
            out_f.close()

    except IOError:
        print('extract_bursts(): File access problem while working on %s' % data_file)

    return new_fnames


## Select bursts to plot and add files to out_files and out_groups 
#  @param name Flow name
#  @param group Flow group
#  @param data_file Data file for flow
#  @param burst_sep Time between bursts in seconds
#  @param sburst First burst in output
#  @param eburst Last burst in output
#  @param out_files Map of flow names to file names
#  @param out_groups Map of file names to group numbers
#  @return Updated file and group lists (with burst file data)
def select_bursts(name='', group='', data_file='', burst_sep='0.0', sburst='1', eburst='0',
                  out_files={}, out_groups={}):

    burst_sep = float(burst_sep)
    sburst = int(sburst)
    eburst = int(eburst)

    # do the burst extraction here,
    # return a new vector of one or more filenames, pointing to file(s) containing
    # <time> <statistic> 
    #
    out_burst_files = extract_bursts(data_file = data_file, burst_sep = burst_sep)
    # Incorporate the extracted .N files
    # as a new, expanded set of filenames to be plotted.
    # Update the out_files dictionary (key=interim legend name based on flow, value=file)
    # and out_groups dictionary (key=file name, value=group)
    if burst_sep == 0.0:
        # Assume this is a single plot (not broken into bursts)
        # The plot_time_series() function expects key to have a single string
        # value rather than a vector. Take the first (and presumably only)
        # entry in the vector returned by extract_bursts()
        out_files[name] = out_burst_files[0]
        out_groups[out_burst_files[0]] = group
    else:
        # This trial has been broken into one or more bursts.
        # plot_incast_ACK_series() knows how to parse a key having a
        # 'vector of strings' value.
        # Also filter the selection based on sburst/eburst nominated by user
        if eburst == 0 :
            eburst = len(out_burst_files)
        # Catch case when eburst was set non-zero but also > number of actual bursts
        eburst = min(eburst,len(out_burst_files))
        if sburst <= 0 :
            sburst = 1
        # Catch case where sburst set greater than eburst
        if sburst > eburst :
            sburst = eburst

        out_files[name] = out_burst_files[sburst-1:eburst]
        for tmp_f in out_burst_files[sburst-1:eburst] :
            out_groups[tmp_f] = group

    return (out_files, out_groups)


## Merge several data files into one data file 
#  @param in_files List of file names
#  @return List with merged file name 
def merge_data_files(in_files):

    # resulting file name will be the first file name with the flow tuple replaced by
    # 0.0.0.0_0_0.0.0.0_0 indicating a merged file 
    merge_fname = re.sub('_[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*_[0-9]*_[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*_[0-9]*',
                        '_0.0.0.0_0_0.0.0.0_0', in_files[0])
    merge_fname += '.all'
    #print(merge_fname)

    f_out = open(merge_fname, 'w')

    for fname in sorted(in_files):
        with open(fname) as f:
            lines = f.readlines()
        f_out.writelines(lines)

    f_out.close()

    return [merge_fname]


## global list of participating hosts for each experiment
part_hosts = {}

## Get list of hosts that participated in experiment
#  @param test_id Experiment id
#  @return List of hosts 
def get_part_hosts(test_id):
    global part_hosts

    if test_id not in part_hosts:

        part_hosts[test_id] = []

        # first process tcpdump files (ignore router and ctl interface tcpdumps)
        uname_files = get_testid_file_list('', test_id,
                                   'uname.log.gz', '')

        for f in uname_files:
            res = re.search('.*_(.*)_uname.log.gz', f)
            if res:
                part_hosts[test_id].append(res.group(1))

    return part_hosts[test_id]


## map test IDs or directory names to TPCONF_host_internal_ip structures
host_internal_ip_cache = {}
## map test IDs or directory names to list of hosts (TPCONF_router + TPCONF_hosts) 
host_list_cache = {}

## Get external and internal address for analysis functions
#  @param test_id Experiment id
#  @param host Internal or external address
#  @param do_abort '0' do not abort if no external address found, '1' abort if no
#                  external address found
#  @return Pair of external address and internal address, or pair of empty strings
#          if host not part of experiment
def get_address_pair_analysis(test_id, host, do_abort='1'):
    global host_internal_ip_cache
    global host_list_cache
    internal = ''
    external = ''
    TMP_CONF_FILE = tempfile.mktemp(suffix='_oldconfig.py', dir='/tmp/')

    # XXX the whole old config access should be moved into separate module as 
    # similar code is also in clockoffset

    # prior to TEACUP version 0.9 it was required to run the analysis with a config
    # file that had config.TPCONF_host_internal_ip as it was used to run the experiment
    # (or a superset of it). Since version 0.9 we use config.TPCONF_host_internal_ip
    # (as well as config.TPCONF_hosts and config.TPCONF_router) from the file 
    # <test_id_prefix>_tpconf_vars.log.gz in the test experiment directory.

    if test_id not in host_internal_ip_cache:
        # first find the directory but looking for mandatory uname file
        uname_file = get_testid_file_list('', test_id,
                                          'uname.log.gz', '')
        dir_name = os.path.dirname(uname_file[0])

        if dir_name in host_internal_ip_cache:
            # create test id cache entry from directory entry 
            host_internal_ip_cache[test_id] = host_internal_ip_cache[dir_name]
            if host_internal_ip_cache[test_id] != None:
                host_list_cache[test_id] = host_list_cache[dir_name]
        else:
            # try to find old config information

            # look for tpconf_vars.log.gz file in that directory 
            var_file = local('find -L %s -name "*tpconf_vars.log.gz"' % dir_name,
                             capture=True)

            if len(var_file) > 0:
                # new approach without using config.py

                # unzip archived file
                local('gzip -cd %s > %s' % (var_file, TMP_CONF_FILE))

                # load the TPCONF_variables into oldconfig
                oldconfig = imp.load_source('oldconfig', TMP_CONF_FILE)

                # remove temporary unzipped file 
                try:
                    os.remove(TMP_CONF_FILE)
                    os.remove(TMP_CONF_FILE + 'c') # remove the compiled file as well
                except OSError:
                    pass

                # store data in cache (both under test id and directory name)
                host_internal_ip_cache[test_id] = oldconfig.TPCONF_host_internal_ip
                host_list_cache[test_id] = oldconfig.TPCONF_hosts + oldconfig.TPCONF_router
                host_internal_ip_cache[dir_name] = oldconfig.TPCONF_host_internal_ip
                host_list_cache[dir_name] = oldconfig.TPCONF_hosts + oldconfig.TPCONF_router
            else:
                # old approach using the functions in hostint.py that access config.py
                # store empty value in cache (both under test id and directory name)
                host_internal_ip_cache[test_id] = None
                host_internal_ip_cache[dir_name] = None

    if host_internal_ip_cache[test_id] != None:
        # new approach

        # pretend it is an external name and perform lookup
        internal = host_internal_ip_cache[test_id].get(host, [])
        if len(internal) == 0:
            # host is internal name, so need to find external name
            internal = host
            for e, i in host_internal_ip_cache[test_id].items():
                if i[0] == host:
                    external = e
        else:
            # host is external name
            internal = internal[0]
            external = host

        hosts = host_list_cache[test_id]

    else:
        # old approach

        (external, internal) = get_address_pair(host, do_abort)

        hosts = get_part_hosts(test_id)

    if external not in hosts:
        return ('', '')
    else:
        return (external, internal)

