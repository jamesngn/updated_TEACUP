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
## @package analyse
# Analyse experiment data -- time series plots
#
# $Id: analyse.py,v ccc2b17c6f89 2018/02/07 19:42:21 garmitage $

import os
import errno
import datetime
import re
import importlib.util
from fabric.api import task, warn, put, puts, get, local, run, execute, \
settings, abort, hosts, env, runs_once, parallel, hide

import config
from internalutil import _list
from clockoffset import adjust_timestamps
from filefinder import get_testid_file_list
from flowcache import append_flow_cache, lookup_flow_cache
from sourcefilter import SourceFilter
from analyseutil import get_out_dir, get_out_name, filter_min_values, \
    select_bursts, get_address_pair_analysis
from plot import plot_time_series, plot_dash_goodput, plot_incast_ACK_series

import gzip
import socket
import csv
from ctypes import *


# structure for ttprobe binary format
class TTprobe(Structure):
    _fields_ = [
            ('tv_sec', c_uint64),
            ('tv_usec', c_uint64),
            ('src_addr', c_uint8 * 16),
            ('dst_addr', c_uint8 * 16),
            ('src_port', c_uint16),
            ('dst_port', c_uint16),
            ('length', c_uint16),
            ('snd_nxt', c_uint32),
            ('snd_una', c_uint32),
            ('snd_wnd', c_uint32),
            ('rcv_wnd', c_uint32),
            ('snd_cwnd', c_uint32),
            ('ssthresh', c_uint32),
            ('srtt', c_uint32),
            ('mss_cache', c_uint32),
            ('sock_state', c_uint8),
            ('direction', c_uint8),
            ('addr_family', c_uint8),
            ]

## Guess ttprobe file format
#  @param file_name ttprobe File name to be checked
#  @return ttprobe file format i.e. 'ttprobe' or 'binary'
def guess_ttprobe_file_format(ttprobe_file=''):

    puts('Gussing ttprobe file format: %s' % ttprobe_file)
    try:
        with gzip.open(ttprobe_file, 'rb') as f:
            tmp = f.read(20)
    except IOError:
        print('Cannot open file %s' % ttprobe_file)
    for i in range(0, 19):
        if ord(tmp[i]) < 32 or ord(tmp[i]) > 127:
            return 'binary'
    if tmp[0] == 'i' or tmp[0] == 'o':
        return 'ttprobe'
    else:
        return ''


## Convert array of u8 to IPv4 or IPv6 address format
#  @param ip IP address to be converted (array of u8)
#  @param addr_family Family type of the address i.e. IPv4
#         or IPv6
#  @return A string contains a formated IP address
def arraytoIP(ip, addr_family):
    if addr_family == 2:
        return '%s.%s.%s.%s' % (ip[0], ip[1], ip[2], ip[3])
    elif addr_family == 10:
        return '%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:' % (
            ip[1], ip[0],
            ip[2], ip[3],
            ip[4], ip[5],
            ip[6], ip[7],
            ip[8], ip[9],
            ip[10], ip[11],
            ip[12], ip[13],
            ip[14], ip[15],
            )


## Get unique TCP flows from ttprobe file
#  @param ttprobe_file ttprobe file name
#  @return A list of flows
def get_ttprobe_flows(ttprobe_file=''):
    # guss ttprobe file format
    ttprobe_format = guess_ttprobe_file_format(ttprobe_file)
    if ttprobe_format == 'binary':
        x = TTprobe()
        # the idea of using set data stracture is to get a unique flow without need
        # for duplication checking
        flows_set = set()
        try:
            with gzip.open(ttprobe_file, 'rb') as f:
                while f.readinto(x) == sizeof(x):
                    flow = '%s,%s,%s,%s' % (arraytoIP(x.src_addr, x.addr_family),
                        socket.ntohs(x.src_port),
                        arraytoIP(x.dst_addr, x.addr_family),
                        socket.ntohs(x.dst_port)
                        )
                    flows_set.add(flow)
        except IOError:
            print('Cannot open file %s' % ttprobe_file)
        # convert set to list and then sort it
        flows = list(flows_set)
        flows.sort()
        return flows

    elif ttprobe_format == 'ttprobe':
        flows_set = set()
        try:
            with gzip.open(ttprobe_file, 'rb') as f:
                ttprobe_cvs_reader = csv.reader(f, delimiter=',')
                for row in ttprobe_cvs_reader:
                    flow = '%s,%s,%s,%s' % (row[2], row[3], row[4], row[5])
                    flows_set.add(flow)
        except IOError:
            print('Cannot open file %s' % ttprobe_file)
        # convert set to list and then sort it
        flows = list(flows_set)
        flows.sort()
        return flows


## extract fileds from tprobe file
#  @param ttprobe_file ttprobe file name
#  @param attributes Fields to be extracted
#  @param rflow Flows to be filtered on
#  @param out the output file
def extract_ttprobe_fields_data(ttprobe_file, attributes, rflow, io_filter, out):

    puts('Extracting fields (%s) from ttprobe file %s' % (attributes, ttprobe_file))
    fields = attributes.split(',')
    ttprobe_format = guess_ttprobe_file_format(ttprobe_file)
    if ttprobe_format == 'binary':
        x = TTprobe()
        try:
            with gzip.open(ttprobe_file, 'rb') as f:
                with open(out, 'w') as fout:
                    while f.readinto(x) == sizeof(x):
                        # ignore the values when TCP socket state is SYN_SENT (==2)
                        if x.sock_state == 2:
                            continue
                        if chr(x.direction) in io_filter:
                            flow = '%s,%s,%s,%s' % (arraytoIP(x.src_addr, x.addr_family),
                                socket.ntohs(x.src_port),
                                arraytoIP(x.dst_addr, x.addr_family),
                                socket.ntohs(x.dst_port)
                                )
                            if rflow == flow:
                                fval = ''
                                fout.write('%u.%06u' % (x.tv_sec, x.tv_usec))
                                for field in fields:
                                    if field == '1':
                                        fval = x.direction
                                    if field == '8':
                                        fval = x.mss_cache
                                    if field == '9':
                                        fval = x.srtt / 1000.0
                                    if field == '10':
                                        fval = x.snd_cwnd * x.mss_cache
                                    elif field == '11':
                                        fval = x.ssthresh
                                    elif field == '12':
                                        fval = x.snd_wnd * x.mss_cache
                                    elif field == '13':
                                        fval = x.rcv_wnd * x.mss_cache
                                    elif field == '14':
                                        fval = x.sock_state
                                    elif field == '15':
                                        fval = x.snd_una
                                    elif field == '16':
                                        fval = x.snd_nxt
                                    elif field == '17':
                                        fval = x.length
                                    fout.write(',' + str(fval))
                                fout.write('\n')

        except IOError:
            print('Cannot open file %s' % ttprobe_file)

        return 0

    elif ttprobe_format == 'ttprobe':
        try:
            with gzip.open(ttprobe_file, 'rb') as f:
                with open(out, 'w') as fout:
                    ttprobe_cvs_reader = csv.reader(f, delimiter=',')
                    for row in ttprobe_cvs_reader:
                        # ignore the values when TCP socket state is SYN_SENT (==2)
                        if row[13] == '2':
                            continue
                        if row[0] in io_filter:
                            flow = '%s,%s,%s,%s' % (row[2], row[3], row[4], row[5])
                            if rflow == flow:
                                fout.write(row[1])
                                for field in fields:
                                    # if field is srtt, then convert to second
                                    if int(field) == 9:
                                        fout.write(',%s' % (int(row[int(field) - 1]) / 1000.0))
                                    else:
                                        fout.write(',' + row[int(field) - 1])
                                fout.write('\n')
                fout.close()
        except IOError:
            print('Cannot open file %s' % ttprobe_file)
        return 0


## Extract data from ttprobe files
#  @param test_id Test ID prefix of experiment to analyse
#  @param out_dir Output directory for results
#  @param replot_only Don't extract data again, just redo the plot
#  @param source_filter Filter on specific sources
#  @param attributes Comma-separated list of attributes to extract from ttprobe file,
#                    start index is 1
#                    (refer to ttprobe documentation for column description)
#  @param out_file_ext Extension for the output file containing the extracted data
#  @param post_proc Name of function used for post-processing the extracted data
#  @param ts_correct '0' use timestamps as they are (default)
#                    '1' correct timestamps based on clock offsets estimated
#                        from broadcast pings
#  @param io_filter  'i' only use statistics from incoming packets
#                    'o' only use statistics from outgoing packets
#                    'io' use statistics from incooming and outgoing packets
#  @return Map of flow names to interim data file names and
#          map of file names and group IDs
def extract_ttprobe(test_id='', out_dir='', replot_only='0', source_filter='',
                   attributes='', out_file_ext='', post_proc=None,
                   ts_correct='1', io_filter='i'):

    if io_filter != 'i' and io_filter != 'o' and io_filter != 'io':
        abort('Invalid parameter value for io_filter')

    out_files = {}
    out_groups = {}

    test_id_arr = test_id.split(';')

    # Initialise source filter data structure
    sfil = SourceFilter(source_filter)

    group = 1
    for test_id in test_id_arr:

        # second process ttprobe files
        ttprobe_files = get_testid_file_list('', test_id,
                                            'ttprobe.log.gz', '', no_abort=True)

        for ttprobe_file in ttprobe_files:
            # get ttprobe file format
            #ttprobe_file_format = guess_ttprobe_file_format(ttprobe_file)
            # get input directory name and create result directory if necessary
            out_dirname = get_out_dir(ttprobe_file, out_dir)

            # unique flows
            flows = lookup_flow_cache(ttprobe_file)
            if flows is None:
                flows = get_ttprobe_flows(ttprobe_file)
                append_flow_cache(ttprobe_file, flows)

            for flow in flows:

                src, src_port, dst, dst_port = flow.split(',')

                # get external aNd internal addresses
                src, src_internal = get_address_pair_analysis(test_id, src, do_abort='0')
                dst, dst_internal = get_address_pair_analysis(test_id, dst, do_abort='0')

                if src == '' or dst == '':
                    continue

                flow_name = flow.replace(',', '_')
                # test id plus flow name
                if len(test_id_arr) > 1:
                    long_flow_name = test_id + '_' + flow_name
                else:
                    long_flow_name = flow_name
                out = out_dirname + test_id + '_' + flow_name + '_ttprobe.' + out_file_ext
                if replot_only == '0' or not os.path.isfile(out):
                    extract_ttprobe_fields_data(ttprobe_file, attributes, flow, io_filter, out)

                    if post_proc is not None:
                        post_proc(ttprobe_file, out)

                if sfil.is_in(flow_name):
                    if ts_correct == '1':
                        host = local(
                            'echo %s | sed "s/.*_\([a-z0-9\.]*\)_ttprobe.log.gz/\\1/"' %
                            (ttprobe_file),
                            capture=True)
                        out = adjust_timestamps(test_id, out, host, ',', out_dir)

                    out_files[long_flow_name] = out
                    out_groups[out] = group

        group += 1

    return (out_files, out_groups)




## Extract DASH goodput data from httperf log files
## The extracted files have an extension of .dashgp. The format is CSV with the
## columns:
## 1. Timestamp of request (second.microsecond)
## 2. Size of requested/downloaded block (bytes)
## 3. Byte rate (mbps), equivalent to size devided by response time times 8
## 4. Response time (seconds)
## 5. Nominal/definded cycle length (seconds)
## 6. Nominal/defined rate (kbps)
## 7. Block number
#  @param test_id Test ID prefix of experiment to analyse
#  @param out_dir Output directory for results
#  @param replot_only If '1' don't extract already extracted data
#                     if '0' extract data (default)
#  @param dash_log_list File name with a list of dash logs
#  @param ts_correct If '0' use timestamps as they are (default)
#                    if '1' correct timestamps based on clock offsets estimated
#                    from broadcast pings
#  @return Test ID list, map of flow names to interim data file names, map of files
#          and group ids
def _extract_dash_goodput(test_id='', out_dir='', replot_only='0', dash_log_list='',
                          ts_correct='1'):
    "Extract DASH goodput from httperf logs"

    # extension of input data files
    ifile_ext = '_httperf_dash.log.gz'
    # extension of output data files
    ofile_ext = '.dashgp'

    # files with extracted data
    out_files = {}
    # group ids (map each file to an experiment)
    out_groups = {}
    # input dash log files
    dash_files = []
 
    test_id_arr = test_id.split(';')
    dash_files = get_testid_file_list(dash_log_list, test_id,
				      ifile_ext, '') 

    for dash_file in dash_files:
        # set and create result directory if necessary
        out_dirname = get_out_dir(dash_file, out_dir)

        dash_file = dash_file.strip()
        name = os.path.basename(dash_file.replace(ifile_ext, ''))
        out = out_dirname + name + ofile_ext 

        # this extracts the req time, request size, byte rate, response time,
        # nominal cycle length, nominal rate in kbps and block number
        #(requires modified httperf output)
        # the sed here parses the nominal cycle length, nominal rate in kbps
        # and block number from the file name
        if replot_only == '0' or not os.path.isfile(out):
            local(
                'zcat %s | grep video_files | grep -v NA | '
                'awk \'{ print $1 "," $5 "," $7 "," $10 "," $14 }\' | '
                'sed "s/\/video_files-\([0-9]*\)-\([0-9]*\)\/\([0-9]*\)/\\1,\\2,\\3/" > %s' %
                (dash_file, out))

        host = local(
            'echo %s | sed "s/.*_\([a-z0-9\.]*\)_[0-9]*%s/\\1/"' %
            (dash_file, ifile_ext), capture=True)
        test_id = local(
            'echo %s | sed "s/.*\/\(.*\)_%s_.*/\\1/"' %
            (dash_file, host), capture=True)

        if ts_correct == '1':
            out = adjust_timestamps(test_id, out, host, ',', out_dir)

        if dash_log_list != '':
            # need to build test_id_arr
            if test_id not in test_id_arr:
                test_id_arr.append(test_id) 
        # else test_id_arr has the list of test ids

        # group number is just the index in the list plus one (start with 1)
        group = test_id_arr.index(test_id) + 1

        out_files[name] = out
        out_groups[out] = group

    return (test_id_arr, out_files, out_groups)


## Extract DASH goodput data from httperf log files (TASK)
## SEE _extract_dash_goodput()
@task
def extract_dash_goodput(test_id='', out_dir='', replot_only='0', dash_log_list='',
                         out_name='', ts_correct='1'):
    "Extract DASH goodput from httperf logs"

    _extract_dash_goodput(test_id, out_dir, replot_only, dash_log_list, ts_correct) 

    # done
    puts('\n[MAIN] COMPLETED extracting DASH goodput %s \n' % test_id)


## Plot DASH goodput from httperf log files
#  @param test_id Test IDs of experiments to analyse (ignored if dash_log_list
#                 is specified)
#  @param out_dir Output directory for results
#  @param replot_only Don't extract data again, just redo the plot
#  @param dash_log_list File name with a list of dash logs
#  @param lnames Semicolon-separated list of legend names
#  @param out_name Name prefix for resulting pdf file
#  @param pdf_dir Output directory for pdf files (graphs),
#                 if not specified it is the same as out_dir
#  @param ymin Minimum value on y-axis
#  @param ymax Maximum value on y-axis
#  @param stime Start time of plot window in seconds
#               (by default 0.0 = start of experiment)
#  @param etime End time of plot window in seconds (by default 0.0 = end of
#               experiment)
#  @param ts_correct '0' use timestamps as they are (default)
#                    '1' correct timestamps based on clock offsets estimated
#                        from broadcast pings
#  @param plot_params Parameters passed to plot function via environment variables
#  @param plot_script Specify the script used for plotting, must specify full path
@task
def analyse_dash_goodput(test_id='', out_dir='', replot_only='0', dash_log_list='',
                         lnames='', out_name='', pdf_dir='', ymin=0, ymax=0,
                         stime='0.0', etime='0.0', ts_correct='1', plot_params='',
                         plot_script=''):
    "Plot DASH goodput from httperf logs"

    # get list of test_ids and data files for plot
    (test_id_arr, 
     out_files, 
     out_groups) = _extract_dash_goodput(test_id, out_dir, replot_only, dash_log_list, 
                                         ts_correct) 

    # set output file name and plot title
    out_name = ''
    title = ''
    if dash_log_list != '':
        out_name = get_out_name(dash_log_list, out_name)
        title = dash_log_list
    else:
        out_name = get_out_name(test_id_arr, out_name)
        title = test_id_arr[0]

    # call plot function
    plot_dash_goodput(
        title,
        out_files,
        out_groups,
        'Transferred (MB)',
        'pdf',
        out_name +
        '_dashgp',
        pdf_dir=pdf_dir,
        sep=',',
        ymin=float(ymin),
        ymax=float(ymax),
        lnames=lnames,
        stime=float(stime),
        etime=float(etime),
        plot_params=plot_params,
        plot_script=plot_script)

    # done
    puts('\n[MAIN] COMPLETED plotting DASH goodput %s \n' % out_name)


## Extract RTT for flows using SPP
## The extracted files have an extension of .rtts. The format is CSV with the
## columns:
## 1. Timestamp RTT measured (seconds.microseconds)
## 2. RTT (seconds)
#  @param test_id Test ID prefix of experiment to analyse
#  @param out_dir Output directory for results
#  @param replot_only Don't extract data again that is already extracted
#  @param source_filter Filter on specific sources
#  @param udp_map Map that defines unidirectional UDP flows to combine. Format:
#	          <ip1>,<port1>:<ip2>,<port2>[;<ip3>,<port3>:<ip4>,<port4>]*
#  @param ts_correct '0' use timestamps as they are (default)
#                    '1' correct timestamps based on clock offsets estimated
#                        from broadcast pings
#  @param burst_sep '0' plot seq numbers as they come, relative to 1st seq number
#                 > '0' plot seq numbers relative to 1st seq number after gaps
#                       of more than burst_sep milliseconds (e.g. incast query/response bursts)
#                 < 0,  plot seq numbers relative to 1st seq number after each abs(burst_sep)
#                       seconds since the first burst @ t = 0 (e.g. incast query/response bursts)
#  @param sburst Start plotting with burst N (bursts are numbered from 1)
#  @param eburst End plotting with burst N (bursts are numbered from 1)
#  @return Test ID list, map of flow names to interim data file names and 
#          map of file names and group IDs
def _extract_rtt(test_id='', out_dir='', replot_only='0', source_filter='',
                udp_map='', ts_correct='1', burst_sep='0.0', sburst='1', eburst='0'):
    "Extract RTT of flows with SPP"

    ifile_ext = '.dmp.gz'
    ofile_ext = '.rtts'

    already_done = {}
    out_files = {}
    out_groups = {}
    udp_reverse_map = {}

    test_id_arr = test_id.split(';')
    if len(test_id_arr) == 0 or test_id_arr[0] == '':
        abort('Must specify test_id parameter')

    # Initialise source filter data structure
    sfil = SourceFilter(source_filter)

    #local('which spp')

    if udp_map != '':
        entries = udp_map.split(';')
        for entry in entries:
            # need to add forward and reverse mapping
            k, v = entry.split(':')
            udp_reverse_map[k] = v
            udp_reverse_map[v] = k

    group = 1
    for test_id in test_id_arr:

        # first process tcpdump files (ignore router and ctl interface tcpdumps)
        tcpdump_files = get_testid_file_list('', test_id,
                                ifile_ext, 
                                'grep -v "router.dmp.gz" | grep -v "ctl.dmp.gz"')

        for tcpdump_file in tcpdump_files:
            # get input directory name and create result directory if necessary
            out_dirname = get_out_dir(tcpdump_file, out_dir) 
            dir_name = os.path.dirname(tcpdump_file)

            # get unique flows
            flows = lookup_flow_cache(tcpdump_file)
            if flows == None:
                flows = _list(local('zcat %s | tcpdump -nr - "tcp" | '
                                'awk \'{ if ( $2 == "IP" ) { print $3 " " $5 " tcp" } }\' | '
                                'sed "s/://" | '
                                'sed "s/\.\([0-9]*\) /,\\1 /g" | sed "s/ /,/g" | '
                                'LC_ALL=C sort -u' %
                                tcpdump_file, capture=True))
                flows += _list(local('zcat %s | tcpdump -nr - "udp" | '
                                 'awk \'{ if ( $2 == "IP" ) { print $3 " " $5 " udp" } }\' | '
                                 'sed "s/://" | '
                                 'sed "s/\.\([0-9]*\) /,\\1 /g" | sed "s/ /,/g" | '
                                 'LC_ALL=C sort -u' %
                                 tcpdump_file, capture=True))

                append_flow_cache(tcpdump_file, flows)

            # since client sends first packet to server, client-to-server flows
            # will always be first

            for flow in flows:

                src, src_port, dst, dst_port, proto = flow.split(',')

                # get external and internal addresses
                src, src_internal = get_address_pair_analysis(test_id, src, do_abort='0')
                dst, dst_internal = get_address_pair_analysis(test_id, dst, do_abort='0')

                if src == '' or dst == '':
                    continue

                # flow name
                name = src_internal + '_' + src_port + \
                    '_' + dst_internal + '_' + dst_port
                rev_name = dst_internal + '_' + dst_port + \
                    '_' + src_internal + '_' + src_port
                # test id plus flow name
                if len(test_id_arr) > 1:
                    long_name = test_id + '_' + name
                    long_rev_name = test_id + '_' + rev_name
                else:
                    long_name = name
                    long_rev_name = rev_name

                if long_name not in already_done and long_rev_name not in already_done:

                    # the two dump files
                    dump1 = dir_name + '/' + test_id + '_' + src + ifile_ext 
                    dump2 = dir_name + '/' + test_id + '_' + dst + ifile_ext 

                    # control the fields used by spp for generating the packet
                    # ids (hashes)
                    if proto == 'udp':
                        pid_fields = 2111
                    else:
                        pid_fields = 511

                    if proto == 'tcp':
                        filter1 = '(src host ' + src_internal + ' && src port ' + src_port + \
                                  ') || (' + \
                                  'dst host ' + src_internal + ' && dst port ' + src_port + ')'
                        filter2 = filter1 
                    else:
                        entry = udp_reverse_map.get(
                            src_internal + ',' + src_port, '')
                        if entry != '':
                            src2_internal, src2_port = entry.split(',')
                            name = src_internal + '_' + src_port + \
                                '_' + src2_internal + '_' + src2_port
                            rev_name = src2_internal + '_' + src2_port + \
                                '_' + src_internal + '_' + src_port
                            filter1 = '(src host ' + src_internal + ' && src port ' + src_port + \
                                ') || ( ' + \
                                'src host ' + src2_internal + ' && src port ' + src2_port + ')'
                            filter2 = filter1 
                            if rev_name in out_files:
                                continue
                        else:
                            warn('No entry in udp_map for %s:%s' % (src_internal, src_port)) 
                            continue

                    out1 = out_dirname + test_id + \
                        '_' + src + '_filtered_' + name + '_ref.dmp'
                    out2 = out_dirname + test_id + \
                        '_' + dst + '_filtered_' + name + '_mon.dmp'
                    out_rtt = out_dirname + test_id + '_' + name + ofile_ext 
                    rev_out_rtt = out_dirname + test_id + '_' + rev_name + ofile_ext 

                    if replot_only == '0' or not ( os.path.isfile(out_rtt) and \
                                                   os.path.isfile(rev_out_rtt) ): 
                        # create filtered tcpdumps
                        local(
                            'zcat %s | tcpdump -nr - -w %s "%s"' %
                            (dump1, out1, filter1))
                        local(
                            'zcat %s | tcpdump -nr - -w %s "%s"' %
                            (dump2, out2, filter2))

                        # compute rtts with spp
                        local(
                            'spp -# %s -a %s -f %s -A %s -F %s > %s' %
                            (pid_fields, src_internal, out1, dst_internal, out2, out_rtt))
                        local(
                            'spp -# %s -a %s -f %s -A %s -F %s > %s' %
                            (pid_fields,
                             dst_internal,
                             out2,
                             src_internal,
                             out1,
                             rev_out_rtt))

                        # remove filtered tcpdumps
                        local('rm -f %s %s' % (out1, out2))

                    already_done[long_name] = 1
                    already_done[long_rev_name] = 1

                    if sfil.is_in(name):
                        if ts_correct == '1':
                            out_rtt = adjust_timestamps(test_id, out_rtt, src, ' ', out_dir)

                        (out_files, 
                         out_groups) = select_bursts(long_name, group, out_rtt, burst_sep, sburst, eburst,
                                      out_files, out_groups)

                    if sfil.is_in(rev_name):
                        if ts_correct == '1':
                            rev_out_rtt = adjust_timestamps(test_id, rev_out_rtt, dst, ' ',
                                          out_dir)

                        (out_files, 
                         out_groups) = select_bursts(long_rev_name, group, rev_out_rtt, burst_sep, sburst, 
                                      eburst, out_files, out_groups)

        group += 1

    return (test_id_arr, out_files, out_groups)


## Extract RTT for flows using SPP
## SEE _extract_rtt()
@task
def extract_rtt(test_id='', out_dir='', replot_only='0', source_filter='',
                udp_map='', ts_correct='1', burst_sep='0.0', sburst='1', eburst='0'):
    "Extract RTT of flows with SPP"

    _extract_rtt(test_id, out_dir, replot_only, source_filter,
                udp_map, ts_correct, burst_sep, sburst, eburst)

    # done
    puts('\n[MAIN] COMPLETED extracting RTTs %s \n' % test_id)


## Plot RTT for flows using SPP
#  @param test_id Test ID prefix of experiment to analyse
#  @param out_dir Output directory for results
#  @param replot_only Don't extract data again, just redo the plot
#  @param source_filter Filter on specific sources
#  @param min_values Minimum number of data points in file, if fewer points
#                    the file is ignored
#  @param udp_map Map that defines unidirectional UDP flows to combine. Format:
#                 <ip1>,<port1>:<ip2>,<port2>[;<ip3>,<port3>:<ip4>,<port4>]*
#  @param omit_const '0' don't omit anything,
#                    '1' omit any series that are 100% constant
#                       (e.g. because there was no data flow)
#  @param ymin Minimum value on y-axis
#  @param ymax Maximum value on y-axis
#  @param lnames Semicolon-separated list of legend names
#  @param stime Start time of plot window in seconds
#               (by default 0.0 = start of experiment)
#  @param etime End time of plot window in seconds
#               (by default 0.0 = end of experiment)
#  @param out_name Name prefix for resulting pdf file
#  @param pdf_dir Output directory for pdf files (graphs), if not specified it is
#                 the same as out_dir
#  @param ts_correct '0' use timestamps as they are (default)
#                    '1' correct timestamps based on clock offsets estimated
#                        from broadcast pings
#  @param plot_params Set env parameters for plotting
#  @param plot_script Specify the script used for plotting, must specify full path
#  @param burst_sep '0' plot seq numbers as they come, relative to 1st seq number
#                 > '0' plot seq numbers relative to 1st seq number after gaps
#                    of more than burst_sep milliseconds (e.g. incast query/response bursts)
#                 < 0,  plot seq numbers relative to 1st seq number after each abs(burst_sep)
#                    seconds since the first burst @ t = 0 (e.g. incast query/response bursts)
#   @param sburst Start plotting with burst N (bursts are numbered from 1)
#   @param eburst End plotting with burst N (bursts are numbered from 1)
@task
def analyse_rtt(test_id='', out_dir='', replot_only='0', source_filter='',
                min_values='3', udp_map='', omit_const='0', ymin='0', ymax='0',
                lnames='', stime='0.0', etime='0.0', out_name='', pdf_dir='',
                ts_correct='1', plot_params='', plot_script='', burst_sep='0.0',
                sburst='1', eburst='0'):
    "Plot RTT of flows with SPP"

    (test_id_arr, 
     out_files, 
     out_groups) = _extract_rtt(test_id, out_dir, replot_only, 
                                 source_filter, udp_map, ts_correct,
                                 burst_sep, sburst, eburst)

    (out_files, out_groups) = filter_min_values(out_files, out_groups, min_values)
    out_name = get_out_name(test_id_arr, out_name)
 
    burst_sep = float(burst_sep)
    if burst_sep == 0.0:
        plot_time_series(out_name, out_files, 'SPP RTT (ms)', 2, 1000.0, 'pdf',
                     out_name + '_spprtt', pdf_dir=pdf_dir, omit_const=omit_const,
                     ymin=float(ymin), ymax=float(ymax), lnames=lnames,
                     stime=stime, etime=etime, groups=out_groups, plot_params=plot_params,
                     plot_script=plot_script, source_filter=source_filter)
    else:
        # Each trial has multiple files containing data from separate bursts detected within the trial
        plot_incast_ACK_series(out_name, out_files, 'SPP RTT (ms)', 2, 1000.0, 'pdf',
                        out_name + '_spprtt', pdf_dir=pdf_dir, aggr='',
                        omit_const=omit_const, ymin=float(ymin), ymax=float(ymax),
                        lnames=lnames, stime=stime, etime=etime, groups=out_groups, burst_sep=burst_sep,
                        sburst=int(sburst), plot_params=plot_params, plot_script=plot_script,
                        source_filter=source_filter)


    # done
    puts('\n[MAIN] COMPLETED plotting RTTs %s \n' % out_name)


## Extract data from siftr files
#  @param test_id Test ID prefix of experiment to analyse
#  @param out_dir Output directory for results
#  @param replot_only Don't extract data again, just redo the plot
#  @param source_filter Filter on specific sources
#  @param attributes Comma-separated list of attributes to extract from siftr file,
#                    start index is 1
#                    (refer to siftr documentation for column description)
#  @param out_file_ext Extension for the output file containing the extracted data
#  @param post_proc Name of function used for post-processing the extracted data
#  @param ts_correct '0' use timestamps as they are (default)
#                    '1' correct timestamps based on clock offsets estimated
#                        from broadcast pings
#  @param io_filter  'i' only use statistics from incoming packets
#                    'o' only use statistics from outgoing packets
#                    'io' use statistics from incooming and outgoing packets
#  @return Map of flow names to interim data file names and 
#          map of file names and group IDs
def extract_siftr(test_id='', out_dir='', replot_only='0', source_filter='',
                  attributes='', out_file_ext='', post_proc=None, 
                  ts_correct='1', io_filter='o'):

    out_files = {}
    out_groups = {}

    if io_filter != 'i' and io_filter != 'o' and io_filter != 'io':
        abort('Invalid parameter value for io_filter')
    if io_filter == 'io':
        io_filter = '(i|o)'

    test_id_arr = test_id.split(';')

    # Initialise source filter data structure
    sfil = SourceFilter(source_filter)

    group = 1
    for test_id in test_id_arr:

        # first process siftr files
        siftr_files = get_testid_file_list('', test_id,
                                           'siftr.log.gz', '',  no_abort=True)

        for siftr_file in siftr_files:
            # get input directory name and create result directory if necessary
            out_dirname = get_out_dir(siftr_file, out_dir)

            if replot_only == '0':
                # check that file is complete, i.e. we have the disable line
                with settings(warn_only=True):
                    last_line = local(
                        'zcat %s | tail -1 | grep disable_time_secs' %
                        siftr_file,
                        capture=True)
                if last_line == '':
                    abort('Incomplete siftr file %s' % siftr_file)

                # check that we have patched siftr (27 columns)
                cols = int(
                    local(
                        'zcat %s | head -2 | tail -1 | sed "s/,/ /g" | wc -w' %
                        siftr_file,
                        capture=True))
                if cols < 27:
                    abort('siftr needs to be patched to output ertt estimates')

            # we need to stop reading before the log disable line
            rows = str(int(
                local('zcat %s | wc -l | awk \'{ print $1 }\'' %
                      (siftr_file), capture=True)) - 3)

            # unique flows
            flows = lookup_flow_cache(siftr_file)
            if flows == None:
                flows = _list(
                    local(
                        'zcat %s | grep -v enable | head -%s | '
                        'egrep "^%s" | '
                        'cut -d\',\' -f 4,5,6,7 | LC_ALL=C sort -u' %
                        (siftr_file, rows, io_filter), capture=True))

                append_flow_cache(siftr_file, flows)

            for flow in flows:

                src, src_port, dst, dst_port = flow.split(',')

                # get external and internal addresses
                src, src_internal = get_address_pair_analysis(test_id, src, do_abort='0')
                dst, dst_internal = get_address_pair_analysis(test_id, dst, do_abort='0')

                if src == '' or dst == '':
                    continue

                flow_name = flow.replace(',', '_')
                # test id plus flow name
                if len(test_id_arr) > 1:
                    long_flow_name = test_id + '_' + flow_name
                else:
                    long_flow_name = flow_name
                out = out_dirname + test_id + '_' + flow_name + '_siftr.' + out_file_ext
                if replot_only == '0' or not os.path.isfile(out) :
                    local(
                        'zcat %s | grep -v enable | head -%s | '
                        'egrep "^%s" | '
                        'cut -d\',\' -f 3,4,5,6,7,%s | '
                        'grep "%s" | cut -d\',\' -f 1,6- > %s' %
                        (siftr_file, rows, io_filter, attributes, flow, out))

                    if post_proc is not None:
                        post_proc(siftr_file, out)

                if sfil.is_in(flow_name):
                    if ts_correct == '1':
                        host = local(
                            'echo %s | sed "s/.*_\([a-z0-9\.]*\)_siftr.log.gz/\\1/"' %
                            siftr_file,
                            capture=True)
                        out = adjust_timestamps(test_id, out, host, ',', out_dir)

                    out_files[long_flow_name] = out
                    out_groups[out] = group

        group += 1

    return (out_files, out_groups)


## Guess web10g version (based on first file only!)
#  @param test_id Test ID prefix of experiment to analyse
def guess_version_web10g(test_id=''):

    test_id_arr = test_id.split(';')
    test_id = test_id_arr[0]
    web10g_files = get_testid_file_list('', test_id,
                                        'web10g.log.gz', '', no_abort=True)

    # if there are no web10g files the following will return '2.0.7', but in this
    # case we don't care anyway 
    try:
        web10g_file = web10g_files[0]
        colnum = local('zcat %s | sed -e "s/,/ /g" | head -1 | wc -w' % web10g_file,
		capture=True)

        if int(colnum) == 122:
            return '2.0.7'
        elif int(colnum) == 128:
            return '2.0.9'
        else:
            return '2.0.7'
    except:
        return '2.0.7'


## Extract data from web10g files
#  @param test_id Test ID prefix of experiment to analyse
#  @param out_dir Output directory for results
#  @param replot_only Don't extract data again, just redo the plot
#  @param source_filter Filter on specific sources
#  @param attributes Comma-separated list of attributes to extract from web10g file,
#                    start index is 1
#                    (refer to web10g documentation for column description)
#  @param out_file_ext Extension for the output file containing the extracted data
#  @param post_proc Name of function used for post-processing the extracted data
#  @param ts_correct '0' use timestamps as they are (default)
#                    '1' correct timestamps based on clock offsets estimated
#                        from broadcast pings
#  @return Map of flow names to interim data file names and 
#          map of file names and group IDs
def extract_web10g(test_id='', out_dir='', replot_only='0', source_filter='',
                   attributes='', out_file_ext='', post_proc=None,
                   ts_correct='1'):

    out_files = {}
    out_groups = {}

    test_id_arr = test_id.split(';')

    # Initialise source filter data structure
    sfil = SourceFilter(source_filter)

    group = 1
    for test_id in test_id_arr:

        # second process web10g files
        web10g_files = get_testid_file_list('', test_id,
                                            'web10g.log.gz', '', no_abort=True)

        for web10g_file in web10g_files:
            # get input directory name and create result directory if necessary
            out_dirname = get_out_dir(web10g_file, out_dir)

            # check for errors, unless we replot
            # make sure we have exit status 0 for this, hence the final echo
            if replot_only == '0':
                errors = local(
                    'zcat %s | grep -v "runbg_wrapper.sh" | grep -v "Timestamp" ' 
                    'egrep "[a-z]+" ; echo -n ""' %
                    web10g_file,
                    capture=True)
                if errors != '':
                    warn('Errors in %s:\n%s' % (web10g_file, errors))

            # unique flows
            # the sed command here suppresses the last line, cause that can be
            # incomplete
            flows = lookup_flow_cache(web10g_file)
            if flows == None:
                flows = _list(
                    local(
                        'zcat %s | egrep -v "[a-z]+" | sed -n \'$!p\' | '
                        'cut -d\',\' -f 3,4,5,6 | LC_ALL=C sort -u' %
                        (web10g_file),
                        capture=True))

                append_flow_cache(web10g_file, flows)

            for flow in flows:

                src, src_port, dst, dst_port = flow.split(',')

                # get external aNd internal addresses
                src, src_internal = get_address_pair_analysis(test_id, src, do_abort='0')
                dst, dst_internal = get_address_pair_analysis(test_id, dst, do_abort='0')

                if src == '' or dst == '':
                    continue

                flow_name = flow.replace(',', '_')
                # test id plus flow name
                if len(test_id_arr) > 1:
                    long_flow_name = test_id + '_' + flow_name
                else:
                    long_flow_name = flow_name
                out = out_dirname + test_id + '_' + flow_name + '_web10g.' + out_file_ext
                if replot_only == '0' or not os.path.isfile(out) :
                    # the first grep removes lines with netlink errors printed out
                    # or last incomplete lines (sed '$d')
                    # (not sure how to suppress them in web10g)
                    # the awk command here is a little trick to not print out lines when
                    # no data is flying around; basically it does suppress lines if
                    # there is no change with respect to the fields specified.
                    # this makes the output comparable to siftr where we only
                    # have output if data is flying around.
                    local('zcat %s | egrep -v "[a-z]+" | sed \'$d\' | '
                          'cut -d\',\' -f 1,3,4,5,6,7,8,13,14,%s | grep "%s" | '
                          'awk -F \',\' \'!a[$2$3$4$5$6$7$8$9]++\' | cut -d\',\' -f 1,10- > %s' %
                          (web10g_file, attributes, flow, out))

                    if post_proc is not None:
                        post_proc(web10g_file, out)

                if sfil.is_in(flow_name):
                    if ts_correct == '1':
                        host = local(
                            'echo %s | sed "s/.*_\([a-z0-9\.]*\)_web10g.log.gz/\\1/"' %
                            web10g_file,
                            capture=True)

                        out = adjust_timestamps(test_id, out, host, ',', out_dir) 

                    out_files[long_flow_name] = out
                    out_groups[out] = group

        group += 1

    return (out_files, out_groups)


## SIFTR prints out very high cwnd (max cwnd?) values for some tcp algorithms
## at the start, remove them
#  @param siftr_file Data extracted from siftr log
#  @param out_file File name for post processed data
def post_proc_siftr_cwnd(siftr_file, out_file):
    tmp_file = local('mktemp "/tmp/tmp.XXXXXXXXXX"', capture=True)
    local(
        'cat %s | sed -e "1,2d\" > %s && mv %s %s' %
        (out_file, tmp_file, tmp_file, out_file))


## Extract cwnd over time
## The extracted files have an extension of .cwnd. The format is CSV with the
## columns:
## 1. Timestamp RTT measured (seconds.microseconds)
## 2. CWND 
#  @param test_id Test ID prefix of experiment to analyse
#  @param out_dir Output directory for results
#  @param replot_only Don't extract data again that is extracted already
#  @param source_filter Filter on specific sources
#  @param ts_correct '0' use timestamps as they are (default)
#                    '1' correct timestamps based on clock offsets estimated
#                        from broadcast pings
#  @param io_filter  'i' only use statistics from incoming packets
#                    'o' only use statistics from outgoing packets
#                    'io' use statistics from incooming and outgoing packets
#                    (only effective for SIFTR files)
#  @return Test ID list, map of flow names to interim data file names and 
#          map of file names and group IDs
def _extract_cwnd(test_id='', out_dir='', replot_only='0', source_filter='',
                 ts_correct='1', io_filter='o'):
    "Extract CWND over time"

    test_id_arr = test_id.split(';')
    if len(test_id_arr) == 0 or test_id_arr[0] == '':
        abort('Must specify test_id parameter')

    (files1,
     groups1) = extract_siftr(test_id,
                              out_dir,
                              replot_only,
                              source_filter,
                              '9',
                              'cwnd',
                              post_proc_siftr_cwnd,
                              ts_correct=ts_correct,
                              io_filter=io_filter)
    (files2,
     groups2) = extract_web10g(test_id,
                               out_dir,
                               replot_only,
                               source_filter,
                               '26',
                               'cwnd',
                               ts_correct=ts_correct)

    (files3,
     groups3) = extract_ttprobe(test_id,
                               out_dir,
                               replot_only,
                               source_filter,
                               '10',
                               'cwnd',
                               ts_correct=ts_correct,
                               io_filter=io_filter)

    # to deal with two Linux loggers for same experiments i.e. 'TPCONF_linux_tcp_logger = 'both'
    inters = list(set(files2).intersection(files3))
    if inters is not None:
        try:
            logger = os.environ['LINUX_TCP_LOGGER']
        except:
            logger = ''
        for i in inters:
            if logger == 'ttprobe':
                del files2[i]
            elif logger == 'web10g':
                del files3[i]
            else:
                files2['w' + i] = files2.pop(i)

    all_files = dict(files1.items() + files2.items() + files3.items())
    all_groups = dict(groups1.items() + groups2.items() + groups3.items())

    return (test_id_arr, all_files, all_groups)


## Extract cwnd over time
## SEE _extract_cwnd
@task
def extract_cwnd(test_id='', out_dir='', replot_only='0', source_filter='',
                 ts_correct='1', io_filter='o'):
    "Extract CWND over time"

    _extract_cwnd(test_id, out_dir, replot_only, source_filter, ts_correct,
                  io_filter)

    # done
    puts('\n[MAIN] COMPLETED extracting CWND %s \n' % test_id)


## Analyse cwnd over time
#  @param test_id Test ID prefix of experiment to analyse
#  @param out_dir Output directory for results
#  @param replot_only Don't extract data again, just redo the plot
#  @param source_filter Filter on specific sources
#  @param min_values Minimum number of data points in file, if fewer points
#                    the file is ignored
#  @param omit_const '0' don't omit anything,
#                    '1' omit any series that are 100% constant
#                        (e.g. because there was no data flow)
#  @param ymin Minimum value on y-axis
#  @param ymax Maximum value on y-axis
#  @param lnames Semicolon-separated list of legend names
#  @param stime Start time of plot window in seconds
#               (by default 0.0 = start of experiment)
#  @param etime End time of plot window in seconds
#               (by default 0.0 = end of experiment)
#  @param out_name Name prefix for resulting pdf file
#  @param pdf_dir Output directory for pdf files (graphs), if not specified it is
#                 the same as out_dir
#  @param ts_correct '0' use timestamps as they are (default)
#                    '1' correct timestamps based on clock offsets estimated
#                        from broadcast pings
#  @param io_filter  'i' only use statistics from incoming packets
#                    'o' only use statistics from outgoing packets
#                    'io' use statistics from incooming and outgoing packets
#                    (only effective for SIFTR files)
#  @param plot_params Set env parameters for plotting
#  @param plot_script specify the script used for plotting, must specify full path
@task
def analyse_cwnd(test_id='', out_dir='', replot_only='0', source_filter='',
                 min_values='3', omit_const='0', ymin='0', ymax='0', lnames='',
                 stime='0.0', etime='0.0', out_name='', pdf_dir='', ts_correct='1',
                 io_filter='o', plot_params='', plot_script=''):
    "Plot CWND over time"

    (test_id_arr,
     out_files, 
     out_groups) = _extract_cwnd(test_id, out_dir, replot_only, 
                                 source_filter, ts_correct, io_filter)

    if len(out_files) > 0:
        (out_files, out_groups) = filter_min_values(out_files, out_groups, min_values)
        out_name = get_out_name(test_id_arr, out_name)
        plot_time_series(out_name, out_files, 'CWND (k)', 2, 0.001, 'pdf',
                         out_name + '_cwnd', pdf_dir=pdf_dir, sep=",",
                         omit_const=omit_const, ymin=float(ymin), ymax=float(ymax),
                         lnames=lnames, stime=stime, etime=etime, groups=out_groups,
                         plot_params=plot_params, plot_script=plot_script,
                         source_filter=source_filter)

    # done
    puts('\n[MAIN] COMPLETED plotting CWND %s \n' % out_name)


## SIFTR values are in units of tcp_rtt_scale*hz, so we need to convert to milliseconds
#  @param siftr_file Data extracted from siftr log
#  @param out_file File name for post processed data
def post_proc_siftr_rtt(siftr_file, out_file):

    hz = local(
        'zcat %s | head -1 | awk \'{ print $4 }\' | cut -d\'=\' -f 2' %
        siftr_file,
        capture=True)
    tcp_rtt_scale = local(
        'zcat %s | head -1 | awk \'{ print $5 }\' | cut -d\'=\' -f 2' %
        siftr_file,
        capture=True)
    scaler = str(float(hz) * float(tcp_rtt_scale) / 1000)
    # XXX hmm maybe do the following in python
    tmp_file = local('mktemp "/tmp/tmp.XXXXXXXXXX"', capture=True)
    local('cat %s | awk -v scaler=%s \'BEGIN { FS = "," } ; '
          '{ printf("%%s,%%.0f,%%s\\n", $1, $2/scaler, $3) }\' > %s && mv %s %s' %
          (out_file, scaler, tmp_file, tmp_file, out_file))


## Extract RTT over time estimated by TCP 
## The extracted files have an extension of .tcp_rtt. The format is CSV with the
## columns:
## 1. Timestamp RTT measured (seconds.microseconds)
## 2. Smoothed RTT
## 3. Sample/Unsmoothed RTT 
#  @param test_id Test ID prefix of experiment to analyse
#  @param out_dir Output directory for results
#  @param replot_only Don't extract data again that is extracted already
#  @param source_filter Filter on specific sources
#  @param ts_correct '0' use timestamps as they are (default)
#                    '1' correct timestamps based on clock offsets estimated
#                        from broadcast pings
#  @param io_filter  'i' only use statistics from incoming packets
#                    'o' only use statistics from outgoing packets
#                    'io' use statistics from incooming and outgoing packets
#                    (only effective for SIFTR files)
#  @param web10g_version web10g version string (default is 2.0.9) 
#  @return Test ID list, map of flow names to interim data file names and 
#          map of file names and group IDs
def _extract_tcp_rtt(test_id='', out_dir='', replot_only='0', source_filter='',
                     ts_correct='1', io_filter='o', web10g_version='2.0.9'):
    "Extract RTT as seen by TCP (smoothed RTT)"

    test_id_arr = test_id.split(';')
    if len(test_id_arr) == 0 or test_id_arr[0] == '':
        abort('Must specify test_id parameter')

    # output smoothed rtt and improved sample rtt (patched siftr required),
    # post process to get rtt in milliseconds
    (files1,
     groups1) = extract_siftr(test_id,
                              out_dir,
                              replot_only,
                              source_filter,
                              '17,27',
                              'tcp_rtt',
                              post_proc_siftr_rtt,
                              ts_correct=ts_correct,
                              io_filter=io_filter)

    # output smoothed RTT and sample RTT in milliseconds
    
    if web10g_version == '2.0.9':
        web10g_version = guess_version_web10g(test_id)

    if web10g_version == '2.0.7':
        data_columns = '23,45'
    elif web10g_version == '2.0.9':
        data_columns = '23,47'
    else:
        data_columns = '23,45'

    (files2,
     groups2) = extract_web10g(test_id,
                               out_dir,
                               replot_only,
                               source_filter,
                               data_columns,
                               'tcp_rtt',
                               ts_correct=ts_correct)

    (files3,
     groups3) = extract_ttprobe(test_id,
                               out_dir,
                               replot_only,
                               source_filter,
                               '9',
                               'tcp_rtt',
                               ts_correct=ts_correct,
                               io_filter=io_filter)

    # to deal with two Linux loggers for same experiments i.e. 'TPCONF_linux_tcp_logger = 'both'
    inters = list(set(files2).intersection(files3))
    if inters is not None:
        try:
            logger = os.environ['LINUX_TCP_LOGGER']
        except:
            logger = ''
        for i in inters:
            if logger == 'ttprobe':
                del files2[i]
            elif logger == 'web10g':
                del files3[i]
            else:
                files2['w' + i] = files2.pop(i)

    all_files = dict(files1.items() + files2.items() + files3.items())
    all_groups = dict(groups1.items() + groups2.items() + groups3.items())

    return (test_id_arr, all_files, all_groups)


## Extract RTT over time estimated by TCP 
## SEE _extract_tcp_rtt
@task
def extract_tcp_rtt(test_id='', out_dir='', replot_only='0', source_filter='',
                     ts_correct='1', io_filter='o', web10g_version='2.0.9'):
    "Extract RTT as seen by TCP (smoothed RTT)"

    _extract_tcp_rtt(test_id, out_dir, replot_only, source_filter, 
                     ts_correct, io_filter, web10g_version)

    # done
    puts('\n[MAIN] COMPLETED extracting TCP RTTs %s \n' % test_id)


## Plot RTT estimated by TCP over time 
#  @param test_id Test ID prefix of experiment to analyse
#  @param out_dir Output directory for results
#  @param replot_only Don't extract data again, just redo the plot
#  @param source_filter Filter on specific sources
#  @param min_values Datasets with fewer values won't be plotted
#  @param smoothed '0' plot non-smooth RTT (enhanced RTT in case of FreeBSD),
#                  '1' plot smoothed RTT estimates (non enhanced RTT in case of FreeBSD)
#  @param omit_const '0' don't omit anything,
#                    '1' omit any series that are 100% constant
#                       (e.g. because there was no data flow)
#  @param ymin Minimum value on y-axis
#  @param ymax Maximum value on y-axis
#  @param lnames Semicolon-separated list of legend names
#  @param stime Start time of plot window in seconds
#               (by default 0.0 = start of experiment)
#  @param etime End time of plot window in seconds
#               (by default 0.0 = end of experiment)
#  @param out_name Name prefix for resulting pdf file
#  @param pdf_dir Output directory for pdf files (graphs), if not specified it is
#                 the same as out_dir
#  @param ts_correct '0' use timestamps as they are (default)
#                    '1' correct timestamps based on clock offsets estimated
#                        from broadcast pings
#  @param io_filter 'i' only use statistics from incoming packets
#                   'o' only use statistics from outgoing packets
#                   'io' use statistics from incooming and outgoing packets
#                   (only effective for SIFTR files)
#  @param web10g_version web10g version string (default is 2.0.9) 
#  @param plot_params Set env parameters for plotting
#  @param plot_script Specify the script used for plotting, must specify full path
@task
def analyse_tcp_rtt(test_id='', out_dir='', replot_only='0', source_filter='',
                    min_values='3', smoothed='1', omit_const='0', ymin='0', ymax='0',
                    lnames='', stime='0.0', etime='0.0', out_name='', pdf_dir='',
                    ts_correct='1', io_filter='o', web10g_version='2.0.9',
                    plot_params='', plot_script=''):
    "Plot RTT as seen by TCP (smoothed RTT)"

    (test_id_arr,
     out_files, 
     out_groups) = _extract_tcp_rtt(test_id, out_dir, replot_only, 
                              source_filter, ts_correct, io_filter, web10g_version)
 
    if len(out_files) > 0:
        (out_files, out_groups) = filter_min_values(out_files, out_groups, min_values)
        out_name = get_out_name(test_id_arr, out_name)
        if smoothed == '1':
            plot_time_series(out_name, out_files, 'Smoothed TCP RTT (ms)', 2, 1.0,
                             'pdf', out_name + '_smooth_tcprtt', pdf_dir=pdf_dir,
                             sep=",", omit_const=omit_const,
                             ymin=float(ymin), ymax=float(ymax), lnames=lnames,
                             stime=stime, etime=etime, groups=out_groups,
                             plot_params=plot_params, plot_script=plot_script,
                             source_filter=source_filter)
        else:
            plot_time_series(out_name, out_files, 'TCP RTT (ms)', 3, 1.0, 'pdf',
                             out_name + '_tcprtt', pdf_dir=pdf_dir, sep=",",
                             omit_const=omit_const, ymin=float(ymin),
                             ymax=float(ymax), lnames=lnames, stime=stime,
                             etime=etime, groups=out_groups, 
                             plot_params=plot_params, plot_script=plot_script,
                             source_filter=source_filter)

    # done
    puts('\n[MAIN] COMPLETED plotting TCP RTTs %s \n' % out_name)


## Extract some TCP statistic (based on siftr/web10g/ttprobe output)
## The extracted files have an extension of .tcpstat_<num>, where <num> is the index
## of the statistic. The format is CSV with the columns:
## 1. Timestamp RTT measured (seconds.microseconds)
## 2. TCP statistic chosen 
#  @param test_id Test ID prefix of experiment to analyse
#  @param out_dir Output directory for results
#  @param replot_only Don't extract data again that is already extracted
#  @param source_filter Filter on specific sources
#  @param siftr_index Integer number of the column in siftr log files
#                     (note if you have sitfr and web10g logs, you must also
#                     specify web10g_index) (default = 9, CWND)
#  @param web10g_index Integer number of the column in web10g log files (note if
#                      you have web10g and siftr logs, you must also specify siftr_index)
#                      (default = 26, CWND)
#                      example: analyse_tcp_stat(siftr_index=17,web10_index=23,...)
#                      would plot smoothed RTT estimates.
#  @param ttprobe_index Integer number of the column in ttprobe log files
#                     (note if you have ttprobe, sitfr and web10g logs, you must also
#                     specify sitfr_index and web10g_index) (default = 10, CWND)
#  @param ts_correct '0' use timestamps as they are (default)
#                    '1' correct timestamps based on clock offsets estimated
#                        from broadcast pings
#  @param io_filter  'i' only use statistics from incoming packets
#                    'o' only use statistics from outgoing packets
#                    'io' use statistics from incooming and outgoing packets
#                    (only effective for SIFTR files)
#  @return Test ID list, map of flow names to interim data file names and 
#          map of file names and group IDs
def _extract_tcp_stat(test_id='', out_dir='', replot_only='0', source_filter='',
                     siftr_index='9', web10g_index='26', ttprobe_index='10',
                      ts_correct='1', io_filter='o'):
    "Extract TCP Statistic"

    test_id_arr = test_id.split(';')
    if len(test_id_arr) == 0 or test_id_arr[0] == '':
        abort('Must specify test_id parameter')

    # output smoothed rtt and improved sample rtt (patched siftr required),
    # post process to get rtt in milliseconds
    (files1,
     groups1) = extract_siftr(test_id,
                              out_dir,
                              replot_only,
                              source_filter,
                              siftr_index,
                              'tcpstat_' + siftr_index,
                              ts_correct=ts_correct,
                              io_filter=io_filter)

    # output smoothed RTT and sample RTT in milliseconds
    (files2,
     groups2) = extract_web10g(test_id,
                               out_dir,
                               replot_only,
                               source_filter,
                               web10g_index,
                               'tcpstat_' + web10g_index,
                               ts_correct=ts_correct)

    (files3,
     groups3) = extract_ttprobe(test_id,
                               out_dir,
                               replot_only,
                               source_filter,
                               ttprobe_index,
                               'tcpstat_' + ttprobe_index,
                               ts_correct=ts_correct,
                               io_filter=io_filter)

    # to deal with two Linux loggers for same experiments i.e. 'TPCONF_linux_tcp_logger = 'both'
    inters = list(set(files2).intersection(files3))
    if inters is not None:
        try:
            logger = os.environ['LINUX_TCP_LOGGER']
        except:
            logger = ''
        for i in inters:
            if logger == 'ttprobe':
                del files2[i]
            elif logger == 'web10g':
                del files3[i]
            else:
                files2['w' + i] = files2.pop(i)

    all_files = dict(files1.items() + files2.items() + files3.items())
    all_groups = dict(groups1.items() + groups2.items() + groups3.items())

    return (test_id_arr, all_files, all_groups)


## Extract some TCP statistic (based on siftr/web10g/ttprobe output)
## SEE _extract_tcp_stat
@task
def extract_tcp_stat(test_id='', out_dir='', replot_only='0', source_filter='',
                     siftr_index='9', web10g_index='26', ttprobe_index='10',
                     ts_correct='1', io_filter='o'):
    "Extract TCP Statistic"

    _extract_tcp_stat(test_id, out_dir, replot_only, source_filter,
                      siftr_index, web10g_index, ttprobe_index,
                      ts_correct, io_filter)

    # done
    puts('\n[MAIN] COMPLETED extracting TCP Statistic %s \n' % test_id)


## Plot some TCP statistic (based on siftr/web10g/ttprobe output)
#  @param test_id Test ID prefix of experiment to analyse
#  @param out_dir Output directory for results
#  @param replot_only Don't extract data again, just redo the plot
#  @param source_filter Filter on specific sources
#  @param min_values Minimum number of data points in file, if fewer points
#                    the file is ignored
#  @param omit_const '0' don't omit anything,
#                    '1' omit any Series that are 100% constant
#                        (e.g. because there was no data flow)
#  @param siftr_index Integer number of the column in siftr log files
#                     (note if you have sitfr and web10g logs, you must also
#                     specify web10g_index) (default = 9, CWND)
#  @param web10g_index Integer number of the column in web10g log files (note if
#                      you have web10g and siftr logs, you must also specify siftr_index)
#                      (default = 26, CWND)
#		       example: analyse_tcp_stat(siftr_index=17,web10_index=23,...)
#                      would plot smoothed RTT estimates.
#  @param ttprobe_index Integer number of the column in ttprobe log files
#                     (note if you have ttprobe, sitfr and web10g logs, you must also
#                     specify sitfr_index and web10g_index) (default = 10, CWND)
#  @param ylabel Label for y-axis in plot
#  @param yscaler Scaler for y-axis values (must be a floating point number)
#  @param ymin Minimum value on y-axis
#  @param ymax Maximum value on y-axis
#  @param lnames Semicolon-separated list of legend names
#  @param stime Start time of plot window in seconds (by default 0.0 = start of experiment)
#  @param etime End time of plot window in seconds (by default 0.0 = end of experiment)
#  @param out_name Name prefix for resulting pdf file
#  @param pdf_dir Output directory for pdf files (graphs), if not specified it is
#                 the same as out_dir
#  @param ts_correct '0' use timestamps as they are (default)
#                    '1' correct timestamps based on clock offsets estimated
#                        from broadcast pings
#  @param io_filter  'i' only use statistics from incoming packets
#                    'o' only use statistics from outgoing packets
#                    'io' use statistics from incooming and outgoing packets
#                    (only effective for SIFTR files)
#  @param plot_params Set env parameters for plotting
#  @param plot_script Specify the script used for plotting, must specify full path
@task
def analyse_tcp_stat(test_id='', out_dir='', replot_only='0', source_filter='',
                     min_values='3', omit_const='0', siftr_index='9', web10g_index='26',
                     ttprobe_index='10',
                     ylabel='', yscaler='1.0', ymin='0', ymax='0', lnames='',
                     stime='0.0', etime='0.0', out_name='', pdf_dir='', ts_correct='1',
                     io_filter='o', plot_params='', plot_script=''):
    "Compute TCP Statistic"

    (test_id_arr,
     out_files,
     out_groups) =_extract_tcp_stat(test_id, out_dir, replot_only, source_filter,
                      siftr_index, web10g_index, ttprobe_index, ts_correct, io_filter)

    if len(out_files) > 0:
        (out_files, out_groups) = filter_min_values(out_files, out_groups, min_values)
        out_name = get_out_name(test_id_arr, out_name)
        plot_time_series(out_name, out_files, ylabel, 2, float(yscaler), 'pdf',
                         out_name + '_tcpstat_' +
                         siftr_index + '_' + web10g_index + '_' + ttprobe_index,
                         pdf_dir=pdf_dir, sep=",", omit_const=omit_const,
                         ymin=float(ymin), ymax=float(ymax), lnames=lnames, stime=stime,
                         etime=etime, groups=out_groups, plot_params=plot_params,
                         plot_script=plot_script, source_filter=source_filter)

    # done
    puts('\n[MAIN] COMPLETED plotting TCP Statistic %s \n' % out_name)


## Extract packet sizes. Plot function computes throughput based on the packet sizes.
## The extracted files have an extension of .psiz. The format is CSV with the
## columns:
## 1. Timestamp RTT measured (seconds.microseconds)
## 2. Packet size (bytes) 
#  @param test_id Test ID prefix of experiment to analyse
#  @param out_dir Output directory for results
#  @param replot_only Don't extract data again that is already extracted 
#  @param source_filter Filter on specific sources
#  @param link_len '0' throughput based on IP length (default),
#                  '1' throughput based on link-layer length
#  @param ts_correct '0' use timestamps as they are (default)
#                    '1' correct timestamps based on clock offsets estimated
#                        from broadcast pings
#  @return Test ID list, map of flow names to interim data file names and 
#          map of file names and group IDs
def _extract_pktsizes(test_id='', out_dir='', replot_only='0', source_filter='',
                       link_len='0', ts_correct='1', total_per_experiment='0'):
    "Extract per-flow packet size versus time"

    ifile_ext = '.dmp.gz'
    ofile_ext = '.psiz'

    already_done = {}
    out_files = {}
    out_groups = {}

    test_id_arr = test_id.split(';')
    if len(test_id_arr) == 0 or test_id_arr[0] == '':
        abort('Must specify test_id parameter')

    # Initialise source filter data structure
    sfil = SourceFilter(source_filter)

    group = 1
    for test_id in test_id_arr:

        # first process tcpdump files (ignore router and ctl interface tcpdumps)
        tcpdump_files = get_testid_file_list('', test_id,
                                       ifile_ext,
                                       'grep -v "router.dmp.gz" | grep -v "ctl.dmp.gz"')

        for tcpdump_file in tcpdump_files:
            # get input directory name and create result directory if necessary
            out_dirname = get_out_dir(tcpdump_file, out_dir)
            dir_name = os.path.dirname(tcpdump_file)

            # unique flows
            flows = lookup_flow_cache(tcpdump_file)
            if flows == None:
                flows = _list(local('zcat %s | tcpdump -nr - "tcp" | '
                                'awk \'{ if ( $2 == "IP" ) { print $3 " " $5 " tcp" } }\' | '
                                'sed "s/://" | '
                                'sed "s/\.\([0-9]*\) /,\\1 /g" | sed "s/ /,/g" | '
                                'LC_ALL=C sort -u' %
                                tcpdump_file, capture=True))
                flows += _list(local('zcat %s | tcpdump -nr - "udp" | '
                                 'awk \'{ if ( $2 == "IP" ) { print $3 " " $5 " udp" } }\' | '
                                 'sed "s/://" | '
                                 'sed "s/\.\([0-9]*\) /,\\1 /g" | sed "s/ /,/g" | '
                                 'LC_ALL=C sort -u' %
                                 tcpdump_file, capture=True))
             
                append_flow_cache(tcpdump_file, flows)

            # since client sends first packet to server, client-to-server flows
            # will always be first

            for flow in flows:

                src, src_port, dst, dst_port, proto = flow.split(',')

                # get external and internal addresses
                src, src_internal = get_address_pair_analysis(test_id, src, do_abort='0')
                dst, dst_internal = get_address_pair_analysis(test_id, dst, do_abort='0')

                if src == '' or dst == '':
                    continue

                # flow name
                name = src_internal + '_' + src_port + \
                    '_' + dst_internal + '_' + dst_port
                rev_name = dst_internal + '_' + dst_port + \
                    '_' + src_internal + '_' + src_port 
                # test id plus flow name
                if len(test_id_arr) > 1:
                    long_name = test_id + '_' + name
                    long_rev_name = test_id + '_' + rev_name
                else:
                    long_name = name
                    long_rev_name = rev_name

                # the two dump files
                dump1 = dir_name + '/' + test_id + '_' + src + ifile_ext 
                dump2 = dir_name + '/' + test_id + '_' + dst + ifile_ext 

                # tcpdump filters and output file names
                filter1 = 'src host ' + src_internal + ' && src port ' + src_port + \
                    ' && dst host ' + dst_internal + ' && dst port ' + dst_port
                filter2 = 'src host ' + dst_internal + ' && src port ' + dst_port + \
                    ' && dst host ' + src_internal + ' && dst port ' + src_port
                out_size1 = out_dirname + test_id + '_' + name + ofile_ext 
                out_size2 = out_dirname + test_id + '_' + rev_name + ofile_ext 

                if long_name not in already_done and long_rev_name not in already_done:
                    if replot_only == '0' or not ( os.path.isfile(out_size1) and \
                                               os.path.isfile(out_size2) ):
                        # make sure for each flow we get the packet sizes captured
                        # at the _receiver_, hence we use filter1 with dump2 ...
                        if link_len == '0':
                            local(
                                'zcat %s | tcpdump -v -tt -nr - "%s" | '
                                'awk \'{ print $1 " " $NF }\' | grep ")$" | sed -e "s/)//" > %s' %
                                (dump2, filter1, out_size1))
                            local(
                                'zcat %s | tcpdump -v -tt -nr - "%s" | '
                                'awk \'{ print $1 " " $NF }\' | grep ")$" | sed -e "s/)//" > %s' %
                                (dump1, filter2, out_size2))
                        else:
                            local(
                                'zcat %s | tcpdump -e -tt -nr - "%s" | grep "ethertype IP" | '
                                'awk \'{ print $1 " " $9 }\' | sed -e "s/://" > %s' %
                                (dump2, filter1, out_size1))
                            local(
                                'zcat %s | tcpdump -e -tt -nr - "%s" | grep "ethertype IP" | '
                                'awk \'{ print $1 " " $9 }\' | sed -e "s/://" > %s' %
                                (dump1, filter2, out_size2))
   
                    already_done[long_name] = 1
                    already_done[long_rev_name] = 1

                    if sfil.is_in(name):
                        if ts_correct == '1':
                            out_size1 = adjust_timestamps(test_id, out_size1, dst, ' ', out_dir)
                        out_files[long_name] = out_size1
                        out_groups[out_size1] = group

                    if sfil.is_in(rev_name):
                        if ts_correct == '1':
                            out_size2 = adjust_timestamps(test_id, out_size2, src, ' ', out_dir)
                        out_files[long_rev_name] = out_size2
                        out_groups[out_size2] = group

        # if desired compute aggregate packet kength data for each experiment
        if total_per_experiment == '1':

            files_list = ''
            for name in out_files:
                if out_groups[out_files[name]] == group:
                    files_list += out_files[name] + ' '

            out_size1 = out_dirname + test_id + '_total' + ofile_ext
            # cat everything together and sort by timestamp
            local('cat %s | sort -k 1,1 > %s' % (files_list, out_size1))

            # replace all files for separate flows with total
            delete_list = []
            for name in out_files:
                if out_groups[out_files[name]] == group:
                    delete_list.append(name)
  
            for d in delete_list:
                del out_groups[out_files[d]]
                del out_files[d]

            name = test_id 
            out_files[name] = out_size1
            out_groups[out_size1] = group

        group += 1

    return (test_id_arr, out_files, out_groups)


## Extract packet sizes. The plot function computes throughput based on the packet sizes.
## SEE _extract_pktsizes
@task
def extract_pktsizes(test_id='', out_dir='', replot_only='0', source_filter='',
                       link_len='0', ts_correct='1', total_per_experiment='0'):
    "Extract throughput for generated traffic flows"

    _extract_pktsizes(test_id, out_dir, replot_only, source_filter, link_len,
                        ts_correct, total_per_experiment)
    # done
    puts('\n[MAIN] COMPLETED extracting packet sizes %s \n' % test_id)


## Plot throughput
#  @param test_id Test ID prefix of experiment to analyse
#  @param out_dir Output directory for results
#  @param replot_only Don't extract data again, just redo the plot
#  @param source_filter Filter on specific sources
#  @param min_values Minimum number of data points in file, if fewer points
#                    the file is ignored
#  @param omit_const '0' don't omit anything,
#                    '1' omit any series that are 100% constant
#                        (e.g. because there was no data flow)
#  @param ymin Minimum value on y-axis
#  @param ymax Maximum value on y-axis
#  @param lnames Semicolon-separated list of legend names
#  @param link_len '0' throughput based on IP length (default),
#                  '1' throughput based on link-layer length
#  @param stime Start time of plot window in seconds
#               (by default 0.0 = start of experiment)
#  @param etime End time of plot window in seconds (by default 0.0 = end of experiment)
#  @param out_name Name prefix for resulting pdf file
#  @param pdf_dir Output directory for pdf files (graphs), if not specified it is
#                 the same as out_dir
#  @param ts_correct '0' use timestamps as they are (default)
#                    '1' correct timestamps based on clock offsets estimated
#                        from broadcast pings
#  @param plot_params: set env parameters for plotting
#  @param plot_script: specify the script used for plotting, must specify full path
#  @param total_per_experiment '0' plot per-flow throughput (default)
#                              '1' plot total throughput
@task
def analyse_throughput(test_id='', out_dir='', replot_only='0', source_filter='',
                       min_values='3', omit_const='0', ymin='0', ymax='0', lnames='',
                       link_len='0', stime='0.0', etime='0.0', out_name='',
                       pdf_dir='', ts_correct='1', plot_params='', plot_script='',
                       total_per_experiment='0'):
    "Plot throughput for generated traffic flows"

    (test_id_arr,
     out_files, 
     out_groups) =_extract_pktsizes(test_id, out_dir, replot_only, 
                              source_filter, link_len, ts_correct,
                              total_per_experiment)

    if total_per_experiment == '0':
        sort_flowkey='1'
    else:
        sort_flowkey='0'

    (out_files, out_groups) = filter_min_values(out_files, out_groups, min_values)
    out_name = get_out_name(test_id_arr, out_name)
    plot_time_series(out_name, out_files, 'Throughput (kbps)', 2, 0.008, 'pdf',
                     out_name + '_throughput', pdf_dir=pdf_dir, aggr='1',
                     omit_const=omit_const, ymin=float(ymin), ymax=float(ymax),
                     lnames=lnames, stime=stime, etime=etime, groups=out_groups,
                     sort_flowkey=sort_flowkey,
                     plot_params=plot_params, plot_script=plot_script,
                     source_filter=source_filter)

    # done
    puts('\n[MAIN] COMPLETED plotting throughput %s \n' % out_name)


## Get list of experiment IDs
#  @param exp_list List of all test IDs
#  @param test_id Test ID prefix of experiment to analyse 
def get_experiment_list(exp_list='', test_id=''):

    if test_id != '':
        experiments = [test_id]
    else:
        try:
            with open(exp_list) as f:
                # read lines without newlines
                experiments = f.read().splitlines()
        except IOError:
            abort('Cannot open file %s' % exp_list)

    return experiments


## Do all extraction 
#  @param exp_list List of all test IDs
#  @param test_id Test ID prefix of experiment to analyse
#  @param out_dir Output directory for result files
#  @param replot_only Don't extract data again, just redo the plot
#  @param source_filter Filter on specific sources
#  @param resume_id Resume analysis with this test_id (ignore all test_ids before this),
#                   only effective if test_id is not specified
#  @param link_len '0' throughput based on IP length (default),
#                  '1' throughput based on link-layer length
#  @param ts_correct '0' use timestamps as they are (default)
#                    '1' correct timestamps based on clock offsets estimated
#                        from broadcast pings
#  @param io_filter 'i' only use statistics from incoming packets
#                   'o' only use statistics from outgoing packets
#                   'io' use statistics from incooming and outgoing packets
#                   (only effective for SIFTR files)
#  @param web10g_version web10g version string (default is 2.0.9)
@task
def extract_all(exp_list='experiments_completed.txt', test_id='', out_dir='',
                replot_only='0', source_filter='', resume_id='', 
                link_len='0', ts_correct='1', io_filter='o', web10g_version='2.0.9'):
    "Extract SPP RTT, TCP RTT, CWND and throughput statistics"

    experiments = get_experiment_list(exp_list, test_id)

    do_analyse = True
    if resume_id != '':
        puts('Resuming analysis with test_id %s' % resume_id)
        do_analyse = False

    for test_id in experiments:

        if test_id == resume_id:
            do_analyse = True

        if do_analyse:
            execute(extract_rtt, test_id, out_dir, replot_only, source_filter,
                    ts_correct=ts_correct)
            execute(extract_cwnd, test_id, out_dir, replot_only, source_filter, 
                    ts_correct=ts_correct, io_filter=io_filter)
            execute(extract_tcp_rtt, test_id, out_dir, replot_only, source_filter, 
                    ts_correct=ts_correct, io_filter=io_filter, web10g_version=web10g_version)
            execute(extract_pktsizes, test_id, out_dir, replot_only, source_filter,
                    link_len=link_len, ts_correct=ts_correct)


## Do all analysis
#  @param exp_list List of all test IDs
#  @param test_id Test ID prefix of experiment to analyse
#  @param out_dir Output directory for result files
#  @param replot_only Don't extract data again, just redo the plot
#  @param source_filter Filter on specific sources
#  @param min_values Ignore flows with less output values 
#  @param omit_const '0' don't omit anything, ]
#                    '1' omit any series that are 100% constant
#                    (e.g. because there was no data flow)
#  @param smoothed '0' plot non-smooth RTT (enhanced RTT in case of FreeBSD),
#                  '1' plot smoothed RTT estimates (non enhanced RTT in case of FreeBSD)
#  @param resume_id Resume analysis with this test_id (ignore all test_ids before this),
#                   only effective if test_id is not specified
#  @param lnames Semicolon-separated list of legend names
#  @param link_len '0' throughput based on IP length (default),
#                  '1' throughput based on link-layer length
#  @param stime Start time of plot window in seconds
#               (by default 0.0 = start of experiment)
#  @param etime End time of plot window in seconds
#               (by default 0.0 = end of experiment)
#  @param out_name Name prefix for resulting pdf files
#  @param pdf_dir Output directory for pdf files (graphs), if not specified it is
#                 the same as out_dir
#  @param ts_correct '0' use timestamps as they are (default)
#                    '1' correct timestamps based on clock offsets estimated
#                        from broadcast pings
#  @param io_filter  'i' only use statistics from incoming packets
#                    'o' only use statistics from outgoing packets
#                    'io' use statistics from incooming and outgoing packets
#                    (only effective for SIFTR files)
#  @param web10g_version web10g version string (default is 2.0.9)
#  @param plot_params Parameters passed to plot function via environment variables
#  @param plot_script Specify the script used for plotting, must specify full path
@task
def analyse_all(exp_list='experiments_completed.txt', test_id='', out_dir='',
                replot_only='0', source_filter='', min_values='3', omit_const='0',
                smoothed='1', resume_id='', lnames='', link_len='0', stime='0.0',
                etime='0.0', out_name='', pdf_dir='', ts_correct='1',
                io_filter='o', web10g_version='2.0.9', plot_params='', plot_script=''):
    "Compute SPP RTT, TCP RTT, CWND and throughput statistics"

    experiments = get_experiment_list(exp_list, test_id)

    do_analyse = True
    if resume_id != '':
        puts('Resuming analysis with test_id %s' % resume_id)
        do_analyse = False

    for test_id in experiments:

        if test_id == resume_id:
            do_analyse = True

        if do_analyse:
            execute(analyse_rtt, test_id, out_dir, replot_only, source_filter,
                    min_values, omit_const=omit_const, lnames=lnames, stime=stime,
                    etime=etime, out_name=out_name, pdf_dir=pdf_dir,
                    ts_correct=ts_correct, plot_params=plot_params, plot_script=plot_script)
            execute(analyse_cwnd, test_id, out_dir, replot_only, source_filter, min_values,
                    omit_const=omit_const, lnames=lnames, stime=stime, etime=etime,
                    out_name=out_name, pdf_dir=pdf_dir, ts_correct=ts_correct,
                    io_filter=io_filter, plot_params=plot_params, plot_script=plot_script)
            execute(analyse_tcp_rtt, test_id, out_dir, replot_only, source_filter, min_values,
                    omit_const=omit_const, smoothed=smoothed, lnames=lnames,
                    stime=stime, etime=etime, out_name=out_name, pdf_dir=pdf_dir,
                    ts_correct=ts_correct, io_filter=io_filter, web10g_version=web10g_version,
                    plot_params=plot_params, plot_script=plot_script)
            execute(analyse_throughput, test_id, out_dir, replot_only, source_filter,
                    min_values, omit_const=omit_const, lnames=lnames, link_len=link_len,
                    stime=stime, etime=etime, out_name=out_name, pdf_dir=pdf_dir,
                    ts_correct=ts_correct, plot_params=plot_params, plot_script=plot_script)


## Extract incast response times from httperf files 
## The extracted files have an extension of .rtimes. The format is CSV with the
## columns:
## 1. Request timestamp (seconds.microseconds)
## 2. Burst number
## 3. Response time (seconds)
#  @param test_id Test ID prefix of experiment to analyse
#  @param out_dir Output directory for results
#  @param replot_only Don't extract data again that is already extracted
#  @param source_filter Filter on specific sources
#  @param ts_correct '0' use timestamps as they are (default)
#                    '1' correct timestamps based on clock offsets estimated
#                        from broadcast pings
#  @param sburst Start plotting with burst N (bursts are numbered from 1)
#  @param eburst End plotting with burst N (bursts are numbered from 1)
#  @param slowest_only '0' plot response times for individual responders 
#                      '1' plot slowest response time across all responders
#                      '2' plot time between first request and last response finished
#  @return Experiment ID list, map of flow names to file names, map of file names
#          to group IDs
def _extract_incast(test_id='', out_dir='', replot_only='0', source_filter='',
                    ts_correct='1', sburst='1', eburst='0', slowest_only='0'):
    "Extract incast response times for generated traffic flows"

    ifile_ext = 'httperf_incast.log.gz'
    ofile_ext = '.rtimes'
  
    # abort in case of responder timeout
    abort_extract = False

    out_files = {}
    out_groups = {}

    sburst = int(sburst)
    eburst = int(eburst)

    test_id_arr = test_id.split(';')
    if len(test_id_arr) == 0 or test_id_arr[0] == '':
        abort('Must specify test_id parameter')

    # Initialise source filter data structure
    sfil = SourceFilter(source_filter)

    group = 1
    for test_id in test_id_arr:

        # first find httperf files (ignore router and ctl interface tcpdumps)
        log_files = get_testid_file_list('', test_id,
                                         ifile_ext, '')

        for log_file in log_files:
            # get input directory name and create result directory if necessary
            out_dirname = get_out_dir(log_file, out_dir)

            # get src ip from file name
            src = local(
                'echo %s | sed "s/.*_\([a-z0-9\.]*\)_[0-9]*_httperf_incast.log.gz/\\1/"' %
                log_file,
                capture=True)
            # don't know source port, use it to differentiate experiments
            # must use high port otherwise the later sorting will fail
            src_port = str(50000 + group)

            # get destination ip and port from log file
            responders = _list(
                local(
                    'zcat %s | grep "hash_enter" | grep -v localhost | cut -d" " -f 2,3' %
                    log_file, capture=True))

            cnt = 0
            for _resp in responders:
                dst = _resp.split(' ')[0]
                dst_port = _resp.split(' ')[1]

                # get external and internal addresses
                src, src_internal = get_address_pair_analysis(test_id, src, do_abort='0')
                dst, dst_internal = get_address_pair_analysis(test_id, dst, do_abort='0')

                #print(src, src_port, dst, dst_port)

                if src == '' or dst == '':
                    continue

                # flow name
                name = src_internal + '_' + src_port + \
                    '_' + dst_internal + '_' + dst_port
                # test id plus flow name
                if len(test_id_arr) > 1:
                    long_name = test_id + '_' + name
                else:
                    long_name = name

                if not sfil.is_in(name):
                    continue

                out_fname = out_dirname + test_id + '_' + name + ofile_ext 

                out_files[long_name] = out_fname
                out_groups[out_fname] = group

                if replot_only == '0' or not os.path.isfile(out_fname) :
                    f = open(out_fname, 'w')

                    responses = _list(local('zcat %s | grep "incast_files"' %
                        log_file, capture=True))

                    time = 0.0
                    bursts = {} 
                    for response in responses:
                        request_ts = float(response.split()[0])
                        responder_id = int(response.split()[2])
                        response_time = response.split()[9]
                        interval = float(response.split()[11])
                        timed_out = response.split()[12]

                        if responder_id == cnt:

                            if not responder_id in bursts:
                                bursts[responder_id] = 0                            
                            bursts[responder_id] += 1

                            # do only write the times for burst >= sburst and burst <= eburst
                            # but sburst=0/eburst=0 means no lower/upper limit 
                            if bursts[responder_id] >= sburst and \
                               (eburst == 0 or bursts[responder_id] <= eburst):
                                if timed_out == 'no':
                                    f.write('%f %i %s\n' % (request_ts, bursts[responder_id],
                                                            response_time))
                                else:
                                    f.write('%f NA NA\n' % time)
                                    abort_extract = True

                            time += interval

                    f.close()

                cnt += 1

        # abort but only after we fully processed the problematic experiment
        if abort_extract:
            abort('Responder timed out in experiment %s' % test_id)

        group += 1

    if slowest_only != '0':
        (out_files, out_groups) = get_slowest_response_time(out_files, out_groups,
                                  int(slowest_only) - 1)

    return (test_id_arr, out_files, out_groups)


## Extract incast 
## SEE _extract_incast
@task
def extract_incast(test_id='', out_dir='', replot_only='0', source_filter='',
                   ts_correct='1', sburst='1', eburst='0'):
    "Extract incast response times for generated traffic flows"

    _extract_incast(test_id, out_dir, replot_only, source_filter, ts_correct,
                    sburst, eburst)

    # done
    puts('\n[MAIN] COMPLETED extracting incast response times %s\n' % test_id)


## Get slowest response time per burst
#  @param out_files List of data files
#  @param out_groups Map of files to groups
#  @param mode '0' slowest response time
#              '1' time between first request and last response finished
#  @return Map of flow names to file names, map of file names to group IDs
def get_slowest_response_time(out_files, out_groups, mode=0):

    slowest = {}
    earliest = {}
    latest = {}
    burst_time = {}

    for group in set(out_groups.values()):
        fname = ''
        for name in out_files.keys():
            if out_groups[out_files[name]] == group:

                # read data file and adjust slowest
                f = open(out_files[name], 'r')
                for line in f.readlines():
                    _time = float(line.split()[0])
                    _burst = float(line.split()[1])
                    # response time is in last column, but column number differs
                    # for httperf vs tcpdump extracted data
                    _res_time = float(line.split()[-1])

                    _time_finished = _time + _res_time

                    # use the first time as time burst ocurred
                    if _burst not in burst_time:
                        burst_time[_burst] = _time

                    if _burst not in slowest:
                        slowest[_burst] = _res_time
                    else:
                        if _res_time > slowest[_burst]:
                            slowest[_burst] = _res_time

                    if _burst not in earliest:
                        earliest[_burst] = _time
                    else:
                        if _time < earliest[_burst]:
                            earliest[_burst] = _time

                    if _burst not in latest:
                        latest[_burst] = _time_finished
                    else:
                        if _time_finished > latest[_burst]:
                            latest[_burst] = _time_finished

                f.close()

                if fname == '':
                    fname = out_files[name]

                # delete entries for single responders
                del out_groups[out_files[name]]
                del out_files[name]

        fname = re.sub('_[0-9]*_[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*_[0-9]*\.', '_0_0.0.0.0_0.', fname)
        fname += '.slowest'
        name = 'Experiment ' + str(group) + ' slowest'

        # write file for slowest response times
        f = open(fname, 'w')
        for _burst in sorted(slowest.keys()):
            if mode == 0:
                # slowest response time of all 
                f.write('%f %f\n' % (burst_time[_burst], slowest[_burst]))
            else:
                # time between first request and last response finished
                f.write('%f %f\n' % (burst_time[_burst], latest[_burst] - earliest[_burst]))

        f.close()

        out_files[name] = fname
        out_groups[fname] = group

    return (out_files, out_groups)


## Plot incast response times 
#  @param test_id Test ID prefix of experiment to analyse
#  @param out_dir Output directory for results
#  @param replot_only Don't extract data again, just redo the plot
#  @param source_filter Filter on specific sources
#  @param min_values Ignore flows with equal less output values / packets
#  @param omit_const '0' don't omit anything,
#                    '1' omit any series that are 100% constant
#                        (e.g. because there was no data flow)
#  @param ymin Minimum value on y-axis
#  @param ymax Maximum value on y-axis
#  @param lnames Semicolon-separated list of legend names
#  @param stime Start time of plot window in seconds
#               (by default 0.0 = start of experiment)
#  @param etime End time of plot window in seconds (by default 0.0 = end of experiment)
#  @param out_name Name prefix for resulting pdf file
#  @param tcpdump '0' by default use the response times reported by httperf
#                 '1' plot response times based on tcpdump data (time between GET packet
#                     and last packet of the response)
#  @param query_host If tcpdump=0 we don't need to set this parameter. however, tcpdump=1
#                    query_host needs to be set to the host name that was the querier.
#                    The name of the host as specified in the config file.
#  @param pdf_dir Output directory for pdf files (graphs), if not specified it is
#                 the same as out_dir
#  @param ts_correct '0' use timestamps as they are (default)
#                    '1' correct timestamps based on clock offsets estimated
#                        from broadcast pings
#  @param slowest_only '0' plot response times for individual responders 
#                      '1' plot slowest response time across all responders
#                      '2' plot time between first request and last response finished
#  @param boxplot '0' normal time series (default)
#                 '1' boxplot for each point in time
#  @param sburst Start plotting with burst N (bursts are numbered from 1)
#  @param eburst End plotting with burst N (bursts are numbered from 1)
#  @param plot_params Set env parameters for plotting
#  @param plot_script Specify the script used for plotting, must specify full path
@task
def analyse_incast(test_id='', out_dir='', replot_only='0', source_filter='',
                       min_values='3', omit_const='0', ymin='0', ymax='0', lnames='',
                       stime='0.0', etime='0.0', out_name='', tcpdump='0', query_host='',
                       pdf_dir='', ts_correct='1', slowest_only='0',
                       boxplot='0', sburst='1', eburst='0', plot_params='', plot_script=''):
    "Plot incast response times for generated traffic flows"

    pdf_name_part = '_restime'
    sort_flowkey = '1'

    if tcpdump == '1':
        # XXX no sburst and eburst for tcpdump yet
        if query_host == '':
            abort('Must specify query_host')
        (test_id_arr,
         out_files,
         out_groups) = _extract_incast_restimes(test_id, out_dir, replot_only, 
                             source_filter, ts_correct, query_host, slowest_only)
        yindex = 5
        ofile_ext = '.restimes'
    else:
        (test_id_arr,
         out_files,
         out_groups) = _extract_incast(test_id, out_dir, replot_only, source_filter, 
                                       ts_correct, sburst, eburst, slowest_only) 
        yindex = 3
        ofile_ext = '.rtimes'

    if slowest_only != '0':
        pdf_name_part = '_restime_slowest'
        sort_flowkey = '0'
        # the slowest code produces an output file with only two columns 
        # (time, response time)
        yindex = 2

    out_name = get_out_name(test_id_arr, out_name)
    plot_time_series(out_name, out_files, 'Response time (s)', yindex, 1.0, 'pdf',
                     out_name + pdf_name_part, pdf_dir=pdf_dir,
                     ymin=float(ymin), ymax=float(ymax),
                     lnames=lnames, stime=stime, etime=etime, 
                     groups=out_groups, sort_flowkey=sort_flowkey, 
                     boxplot=boxplot, plot_params=plot_params, plot_script=plot_script,
                     source_filter=source_filter) 

    # done
    puts('\n[MAIN] COMPLETED plotting incast response times %s\n' % out_name)


## Extract_dupACKs_bursts
#  @param acks_file Full path to a specific .acks file which is to be parsed
#                   for dupACKs and (optionally) extract sequence of ACK bursts
#  @param burst_sep =0, Just calculate running total of dupACKs and create acks_file+".0" output file
#                  < 0, extract bursts into acks_file+".N" outputfiles (for burst N),
#                     where burst starts @ t=0 and then burst_sep seconds after start of previous burst
#                  > 0, extract bursts into acks_file+".N" outputfiles (for burst N)
#                     where burst starts @ t=0 and then burst_sep seconds after end of previous burst
#  @return Vector of file names (one for each file generated)
#
# First task is to calculate the number of duplicate ACKs. Define
# them as ACKs whose sequence number is unchanged from the immediately
# preceding ACK.
#
# Generate .acks.0 file with this format:
#
#   <time>  <ack_seq_no>  <cumulative_dupACK_count>
#
#
#If burst_sep != 0 then we try to further subdivide into "bursts"
#
# Output is multiple .acks.N files, containing only the lines for
# burst N:
#
#   <time>  <ack_seq_no>  <cumulative_dupACK_count>
#
# The <ack_seq_no> starts at 0 for burst 1 (since the first
# ACK is assuemd to be the end of the handshake rather than ACK'ing
# a Data packet), but starts at a small non-zero value for the first
# ACK of bursts 2..N.
#
# The <cumulative_dupACK_count> restarts at 0 for each burst.
#
# NOTE: This function relies on there being no re-ordering of ACK packets on
#       the return path.
#
def extract_dupACKs_bursts(acks_file='', burst_sep=0):

    # New filenames (source file + ".0" or ".1,.2,....N" for bursts)
    new_fnames = []

    # Internal variables
    burstN = 1
    firstTS = -1

    try:
        _acks = []
        # First read the entire contents of a .acks file
        with open(acks_file) as f:
            _acks = f.readlines()
            #print _acks

            if burst_sep != 0 :
                # Create the first .acks.N output file
                out_f = open(acks_file+"."+"1","w")
                new_fnames.append(acks_file+"."+"1")
            else:
                out_f = open(acks_file+"."+"0","w")
                new_fnames.append(acks_file+"."+"0")

            # Now walk through every line of the .acks file
            for oneline in _acks:
                # ackdetails[0] is the timestamp, ackdetails[1] is the seq number
                ackdetails = oneline.split()

                if firstTS == -1 :
                    # This is first time through the loop, so set some baseline
                    # values for later offsets
                    firstTS = ackdetails[0]
                    prev_ACKTS = firstTS
                    firstBytes = 0

                # Is this ACK a dupACK ?
                if int(ackdetails[1]) == 0 :
                    # Only the first ACK line has zero seq number. Special case, reset dupACKs count
                    dupACKs = 0
                    prev_seqno = ackdetails[1]
                else:
                    # Define dupACK as an ACK with unchanged seq number wrt preceding ACK
                    if (int(ackdetails[1]) - int(prev_seqno)) == 0 :
                        dupACKs += 1

                # If burst_sep == 0 the only thing we're calculating is a
                # cumulative running total of dupACKs, so we only do burst
                # identification if burst_sep != 0

                if burst_sep != 0 :

                    if burst_sep < 0 :
                        # ack_gap is time since first ACK of this burst
                        # (i.e. relative to firstTS)
                        ack_gap = float(ackdetails[0]) - float(firstTS)
                    else:
                        # ack_gap is time since previous ACK in this burst
                        # (i.e. relative to prev_ACKTS)
                        ack_gap = float(ackdetails[0]) - float(prev_ACKTS)

                    # New burst begins when time between this ACK and previous
                    # exceeds abs(burst_sep)
                    if (ack_gap >= abs(burst_sep)) :
                        # We've found the first ACK of the _next_ burst

                        # Close previous burst output file
                        out_f.close()

                        # Move on to the next burst
                        burstN += 1

                        print ("Burst: %3i, ends at %f sec, data: %i bytes, gap: %3.6f sec, dupACKs: %i" %
                        ( (burstN-1),  float(prev_ACKTS), int(prev_seqno) - int(firstBytes), ack_gap, dupACKs ) )

                        # Reset firstTS to the beginning (first timestamp) of this new burst
                        firstTS = ackdetails[0]

                        # The sequence number of first ACK of bursts 2...N must be considered
                        # relative to LAST seq number of PREVIOUS burst in order to calculate
                        # how many bytes were fully sent in bursts 2...N.
                        firstBytes = prev_seqno

                        # Reset the dupACKs counter
                        dupACKs = 0

                        # Create the next .acks.N output file
                        out_f = open(acks_file+"."+str(burstN),"w")
                        new_fnames.append(acks_file+"."+str(burstN))


                # How many bytes were ACK'ed since beginning? (Of entire file or of burst N)
                # This must be calculated _after_ firstBytes is potentially reset on
                # the boundary between bursts.
                bytes_gap = int(ackdetails[1]) - int(firstBytes)

                #print "Burst: ", burstN, "  Time ", ackdetails[0] ," Bytes ", bytes_gap, "   DupACKS ", dupACKs

                # Write to burst-specific output file
                # <time>  <ACK seq number>  <dupACK count>
                out_f.write(ackdetails[0]+" "+str(bytes_gap)+" "+str(dupACKs)+"\n")

                # Store the seq number for next time around the loop
                prev_seqno = ackdetails[1]
                prev_ACKTS = ackdetails[0]

            # Close the last output file
            out_f.close()

    except IOError:
        print('extract_dupACKs_bursts(): File access problem while working on %s' % acks_file)

    return new_fnames


## Extract cumulative bytes ACKnowledged and cumulative dupACKs
## Intermediate files end in ".acks", ".acks.N", ".acks.tscorr" or ".acks.tscorr.N"
## XXX move sburst and eburst to the plotting task and here extract all?
#  @param test_id Semicolon-separated list of test ID prefixes of experiments to analyse
#  @param out_dir Output directory for results
#  @param replot_only '1' don't extract raw ACK vs time data per test_ID if already done,
#                     but still re-calculate dupACKs and bursts (if any) before plotting results
#                     '0' always extract raw data
#  @param source_filter Filter on specific flows to process
#  @param ts_correct '0' use timestamps as they are (default)
#                    '1' correct timestamps based on clock offsets estimated
#                        from broadcast pings
#  @param burst_sep '0' plot seq numbers as they come, relative to 1st seq number
#                   > '0' plot seq numbers relative to 1st seq number after gaps
#                        of more than burst_sep milliseconds (e.g. incast query/response bursts)
#                   < 0, plot seq numbers relative to 1st seq number after each abs(burst_sep)
#                        seconds since the first burst @ t = 0 (e.g. incast query/response bursts)
#  @param sburst Start plotting with burst N (bursts are numbered from 1)
#  @param eburst End plotting with burst N (bursts are numbered from 1)
#   @param total_per_experiment '0' per-flow data (default)
#                               '1' total data 
#  @return Experiment ID list, map of flow names to file names, map of file names to group IDs
def _extract_ackseq(test_id='', out_dir='', replot_only='0', source_filter='',
                    ts_correct='1', burst_sep='0.0',
                    sburst='1', eburst='0', total_per_experiment='0'):
    "Extract cumulative bytes ACKnowledged vs time / extract incast bursts"

    ifile_ext = '.dmp.gz'
    ofile_ext = '.acks'

    sburst = int(sburst)
    eburst = int(eburst)
    burst_sep = float(burst_sep)

    already_done = {}
    out_files = {}
    out_groups = {}

    test_id_arr = test_id.split(';')
    if len(test_id_arr) == 0 or test_id_arr[0] == '':
        abort('Must specify test_id parameter')

    # Initialise source filter data structure
    sfil = SourceFilter(source_filter)

    group = 1
    for test_id in test_id_arr:

        # first process tcpdump files (ignore router and ctl interface tcpdumps)
        tcpdump_files = get_testid_file_list('', test_id,
                                       ifile_ext,
                                       'grep -v "router.dmp.gz" | grep -v "ctl.dmp.gz"')

        for tcpdump_file in tcpdump_files:
            # get input directory name and create result directory if necessary
            dir_name = os.path.dirname(tcpdump_file)
            out_dirname = get_out_dir(tcpdump_file, out_dir)

            # unique flows
            flows = lookup_flow_cache(tcpdump_file)
            if flows == None:
                flows = _list(local('zcat %s | tcpdump -nr - "tcp" | '
                                'awk \'{ if ( $2 == "IP" ) { print $3 " " $5 " tcp" } }\' | '
                                'sed "s/://" | '
                                'sed "s/\.\([0-9]*\) /,\\1 /g" | sed "s/ /,/g" | '
                                'LC_ALL=C sort -u' %
                                tcpdump_file, capture=True))

                append_flow_cache(tcpdump_file, flows)

            # since client sends first packet to server, client-to-server flows
            # will always be first

            for flow in flows:
	
                src, src_port, dst, dst_port, proto = flow.split(',')

                # get external and internal addresses
                src, src_internal = get_address_pair_analysis(test_id, src, do_abort='0')
                dst, dst_internal = get_address_pair_analysis(test_id, dst, do_abort='0')

                if src == '' or dst == '':
                    continue

                # flow name
                name = src_internal + '_' + src_port + \
                    '_' + dst_internal + '_' + dst_port
                rev_name = dst_internal + '_' + dst_port + \
                    '_' + src_internal + '_' + src_port
                # test id plus flow name
                if len(test_id_arr) > 1:
                    long_name = test_id + '_' + name
                    long_rev_name = test_id + '_' + rev_name
                else:
                    long_name = name
                    long_rev_name = rev_name

                # the two dump files
                dump1 = dir_name + '/' + test_id + '_' + src + ifile_ext 
                dump2 = dir_name + '/' + test_id + '_' + dst + ifile_ext 

                # tcpdump filters and output file names
                # 'tcp[tcpflags] == tcp-ack' rule to extract only ACK packets (eliminate SYN and FIN, even if ACK also set)
                filter1 = 'src host ' + src_internal + ' && src port ' + src_port + \
                    ' && dst host ' + dst_internal + ' && dst port ' + dst_port + \
                    ' && tcp[tcpflags] == tcp-ack'
                filter2 = 'src host ' + dst_internal + ' && src port ' + dst_port + \
                    ' && dst host ' + src_internal + ' && dst port ' + src_port + \
                    ' && tcp[tcpflags] == tcp-ack'

                out_acks1 = out_dirname + test_id + '_' + name + ofile_ext 
                out_acks2 = out_dirname + test_id + '_' + rev_name + ofile_ext 

                if long_name not in already_done and long_rev_name not in already_done:
                    if replot_only == '0' or not ( os.path.isfile(out_acks1) and \
                                               os.path.isfile(out_acks2) ):

                        # make sure for each flow we get the ACKs captured
                        # at the _receiver_, hence we use filter1 with dump2 ...
                        # Use "-S" option to tcpdump so ACK sequence numbers are always absolute

                        # Grab first ACK sequence numbers for later use as a baseline

                        baseACK1 = local(
                            'zcat %s | tcpdump -c 1 -S -tt -nr - "%s" | '
                            'awk \'{ FS=" " ; for(i=2;i<=NF;i++) { if ( $i  == "ack") { print $(i+1) }  } ; }\' | sed \'s/,//\' ' %
                            (dump2, filter1), capture=True)
                        baseACK2 = local(
                            'zcat %s | tcpdump -c 1 -S -tt -nr - "%s" | '
                            'awk \'{ FS=" " ; for(i=2;i<=NF;i++) { if ( $i  == "ack") { print $(i+1) }  } ; }\' | sed \'s/,//\' ' %
                            (dump1, filter2), capture=True)

                        #puts('\n[MAIN] BASEACKs %s %s\n' % (baseACK1, baseACK2))

                        # Now extract all ACK sequence numbers, normalised to baseACK{1,2}

                        local(
                            'zcat %s | tcpdump -S -tt -nr - "%s" | '
                            'awk \'{ FS=" " ; for(i=2;i<=NF;i++) { if ( $i  == "ack") { print $1 " " $(i+1) - %s }  } ; }\' | sed \'s/,//\'  > %s' %
                            (dump2, filter1, baseACK1, out_acks1))
                        local(
                            'zcat %s | tcpdump -S -tt -nr - "%s" | '
                            'awk \'{ FS=" " ; for(i=2;i<=NF;i++) { if ( $i  == "ack") { print $1 " " $(i+1) - %s }  } ; }\' | sed \'s/,//\'  > %s' %
                            (dump1, filter2, baseACK2, out_acks2))

                    already_done[long_name] = 1
                    already_done[long_rev_name] = 1

                    if sfil.is_in(name):
                        if ts_correct == '1':
                            out_acks1 = adjust_timestamps(test_id, out_acks1, dst, ' ', out_dir)

                        # do the dupACK calculations and burst extraction here,
                        # return a new vector of one or more filenames, pointing to file(s) containing
                        # <time> <seq_no> <dupACKs>
                        #
                        out_acks1_dups_bursts = extract_dupACKs_bursts(acks_file = out_acks1, 
                                                          burst_sep = burst_sep)
                        # Incorporate the extracted .N files
                        # as a new, expanded set of filenames to be plotted.
                        # Update the out_files dictionary (key=interim legend name based on flow, value=file)
                        # and out_groups dictionary (key=file name, value=group)
                        if burst_sep == 0.0:
                            # Assume this is a single plot (not broken into bursts)
                            # The plot_time_series() function expects key to have a single string
                            # value rather than a vector. Take the first (and presumably only)
                            # entry in the vector returned by extract_dupACKs_bursts()
                            out_files[long_name] = out_acks1_dups_bursts[0]
                            out_groups[out_acks1_dups_bursts[0]] = group
                        else:
                            # This trial has been broken into one or more bursts.
                            # plot_incast_ACK_series() knows how to parse a key having a
                            # 'vector of strings' value.
                            # Also filter the selection based on sburst/eburst nominated by user
                            if eburst == 0 :
                                eburst = len(out_acks1_dups_bursts)
                            # Catch case when eburst was set non-zero but also > number of actual bursts
                            eburst = min(eburst,len(out_acks1_dups_bursts))
                            if sburst <= 0 :
                                sburst = 1
                            # Catch case where sburst set greater than eburst
                            if sburst > eburst :
                                sburst = eburst

                            out_files[long_name] = out_acks1_dups_bursts[sburst-1:eburst]
                            for tmp_f in out_acks1_dups_bursts[sburst-1:eburst] :
                                out_groups[tmp_f] = group

                    if sfil.is_in(rev_name):
                        if ts_correct == '1':
                            out_acks2 = adjust_timestamps(test_id, out_acks2, src, ' ', out_dir)

                        # do the dupACK calculations burst extraction here
                        # return a new vector of one or more filenames, pointing to file(s) containing
                        # <time> <seq_no> <dupACKs>
                        #
                        out_acks2_dups_bursts = extract_dupACKs_bursts(acks_file = out_acks2, 
                                                          burst_sep = burst_sep)

                        # Incorporate the extracted .N files
                        # as a new, expanded set of filenames to be plotted.
                        # Update the out_files dictionary (key=interim legend name based on flow, value=file)
                        # and out_groups dictionary (key=file name, value=group)
                        if burst_sep == 0.0:
                            # Assume this is a single plot (not broken into bursts)
                            # The plot_time_series() function expects key to have a single string
                            # value rather than a vector. Take the first (and presumably only)
                            # entry in the vector returned by extract_dupACKs_bursts()
                            out_files[long_rev_name] = out_acks2_dups_bursts[0]
                            out_groups[out_acks2_dups_bursts[0]] = group
                        else:
                            # This trial has been broken into bursts.
                            # plot_incast_ACK_series() knows how to parse a key having a
                            # 'vector of strings' value.
                            # Also filter the selection based on sburst/eburst nominated by user
                            if eburst == 0 :
                                eburst = len(out_acks2_dups_bursts)
                            # Catch case when eburst was set non-zero but also > number of actual bursts
                            eburst = min(eburst,len(out_acks2_dups_bursts))
                            if sburst <= 0 :
                                sburst = 1
                            # Catch case where sburst set greater than eburst
                            if sburst > eburst :
                                sburst = eburst

                            out_files[long_rev_name] = out_acks2_dups_bursts[sburst-1:eburst]
                            for tmp_f in out_acks2_dups_bursts[sburst-1:eburst] :
                                out_groups[tmp_f] = group

        # if desired compute aggregate acked bytes for each experiment
        # XXX only do this for burst_sep=0 now
        if burst_sep == 0.0 and total_per_experiment == '1':

            aggregated = {}

            # first read everything in one dictionary indexed by time
            flow = 0
            for name in out_files:
                if out_groups[out_files[name]] == group:
                    with open(out_files[name], 'r') as f:
                        lines = f.readlines()
                        for line in lines:
                            fields = line.split()
                            curr_time = float(fields[0])
                            if curr_time not in aggregated:
                                aggregated[curr_time] = [] 
                            aggregated[curr_time].append((flow, int(fields[1]), int(fields[2])))

                    flow += 1

            total = {} # total cumulative values 
            last_flow_val = {} # last values per flow (ackbyte, dupack) tuples
            last_val = (0, 0)  # value from last time

            # second go through by time and total 
            for t in sorted(aggregated.keys()):

                # if there is no entry for time t, then create one
                if t not in total:
                    total[t] = last_val # start with the last value (cumulative total) 
 
                # get delta values for ackbytes and dupacks for each value and add
                for (flow, cum_byte, cum_ack) in aggregated[t]:

                    #print(t, flow, cum_byte, cum_ack)

                    if flow in last_flow_val:
                        byte = cum_byte - last_flow_val[flow][0]
                        ack = cum_ack - last_flow_val[flow][1]
                    else:
                        byte = cum_byte
                        ack = cum_ack

                    #if flow in last_flow_val:
                    #    print(cum_byte, last_flow_val[flow][0], byte)

                    # add delta values to value at current time t
                    total[t] = (total[t][0] + byte, total[t][1] + ack) 
 
                    # memorise last value
                    last_flow_val[flow] = (cum_byte, cum_ack)

                last_val = total[t]

            # write output file
            out_acks1 = out_dirname + test_id + '_total' + ofile_ext
            with open(out_acks1, 'w') as f:
                for t in sorted(total.keys()):
                    f.write('%f %i %i\n' % (t, total[t][0], total[t][1]))

            # replace all files for separate flows with total
            delete_list = []
            for name in out_files:
                if out_groups[out_files[name]] == group:
                    delete_list.append(name)

            #print(delete_list)
            #print(out_files)
            #print(out_groups)
            for d in delete_list:
                try:
                    del out_groups[out_files[d]]
                except KeyError:
                    # forward and backward name match to same data file 
                    # XXX investigate
                    pass
                del out_files[d]

            name = test_id
            out_files[name] = out_acks1
            out_groups[out_acks1] = group


        group += 1

    return (test_id_arr, out_files, out_groups)


## Extract cumulative bytes ACKnowledged and cumulative dupACKs
## SEE _extract_ackseq
@task
def extract_ackseq(test_id='', out_dir='', replot_only='0', source_filter='',
                    ts_correct='1', burst_sep='0.0',
                    sburst='1', eburst='0', total_per_experiment='0'):
    "Extract cumulative bytes ACKnowledged vs time / extract incast bursts"

    _extract_ackseq(test_id, out_dir, replot_only, source_filter, ts_correct,
                    burst_sep, sburst, eburst, total_per_experiment)

    # done
    puts('\n[MAIN] COMPLETED extracting ackseq %s \n' % test_id)


## Plot cumulative bytes ACKnowledged or cumulative dupACKs vs time
#  @param test_id Semicolon-separated list of test ID prefixes of experiments to analyse
#  @param out_dir Output directory for results
#  @param replot_only '1' don't extract raw ACK vs time data per test_ID if already done,
#                     but still re-calculate dupACKs and bursts (if any) before plotting results
#  @param source_filter Filter on specific flows to process
#  @param min_values Ignore flows with equal less output values / packets
#  @param omit_const '0' don't omit anything,
#                    '1' omit any series that are 100% constant
#                    (e.g. because there was no data flow)
#  @param ymin Minimum value on y-axis
#  @param ymax Maximum value on y-axis
#  @param lnames Semicolon-separated list of legend names per flow
#                (each name will have burst numbers appended if burst_sep is set)
#  @param stime Start time of plot window in seconds
#               (by default 0.0 = start of experiment)
#  @param etime End time of plot window in seconds (by default 0.0 = end of experiment)
#  @param out_name Prefix for filenames of resulting pdf files
#  @param pdf_dir Output directory for pdf files (graphs), if not specified it is
#                the same as out_dir
#  @param ts_correct '0' use timestamps as they are (default)
#                    '1' correct timestamps based on clock offsets estimated
#                        from broadcast pings
#  @param burst_sep '0' plot seq numbers as they come, relative to 1st seq number
#                   > '0' plot seq numbers relative to 1st seq number after gaps
#                   of more than burst_sep milliseconds (e.g. incast query/response bursts)
#                   < 0,  plot seq numbers relative to 1st seq number after each abs(burst_sep)
#                   seconds since the first burst @ t = 0 (e.g. incast query/response bursts)
#   @param sburst Start plotting with burst N (bursts are numbered from 1)
#   @param eburst End plotting with burst N (bursts are numbered from 1)
#   @param dupacks '0' to plot ACKed bytes vs time
#                  '1' to plot cumulative dupACKs vs time
#   @param plot_params Parameters passed to plot function via environment variables
#   @param plot_script Specify the script used for plotting, must specify full path
#
# Intermediate files end in ".acks", ".acks.N", ".acks.tscorr" or ".acks.tscorr.N"
# Output pdf files end in:
#   "_ackseqno_time_series.pdf",
#   "_ackseqno_bursts_time_series.pdf",
#   "_comparison_ackseqno_time_series.pdf"
#   "_comparison_ackseqno_bursts_time_series.pdf"
#   (if dupacks=1, then as above with "dupacks" instead of "ackseqno")
@task
def analyse_ackseq(test_id='', out_dir='', replot_only='0', source_filter='',
                       min_values='3', omit_const='0', ymin='0', ymax='0', lnames='',
                       stime='0.0', etime='0.0', out_name='',
                       pdf_dir='', ts_correct='1', burst_sep='0.0',
                       sburst='1', eburst='0', dupacks='0',
                       plot_params='', plot_script=''):
    "Plot cumulative bytes ACKnowledged vs time / extract incast bursts"

    (test_id_arr,
     out_files,
     out_groups) =  _extract_ackseq(test_id, out_dir, replot_only, source_filter, 
                    ts_correct, burst_sep, sburst, eburst)
   
    (out_files, out_groups) = filter_min_values(out_files, out_groups, min_values)
    out_name = get_out_name(test_id_arr, out_name)

    # Set plot conditions based on whether user wants dupacks or acked bytes vs time
    if dupacks == '0' :
        yaxistitle = 'Bytes acknowledged (Kbytes)'
        ycolumn = 2
        yaxisscale =  (1.0/1024.0)
        oname = '_ackseqno'
    else :
        yaxistitle = 'Cumulative dupACKs'
        ycolumn = 3
        yaxisscale = 1.0
        oname = '_dupacks'

    # NOTE: Turn off aggregation with aggr=''
    if float(burst_sep) == 0.0:
        # Regular plots, each trial has one file containing data
        plot_time_series(out_name, out_files, yaxistitle, ycolumn, yaxisscale, 'pdf',
                        out_name + oname, pdf_dir=pdf_dir, aggr='',
                        omit_const=omit_const, ymin=float(ymin), ymax=float(ymax),
                        lnames=lnames, stime=stime, etime=etime, groups=out_groups,
                        plot_params=plot_params, plot_script=plot_script,
                        source_filter=source_filter)
    else:
        # Each trial has multiple files containing data from separate ACK bursts detected within the trial
        plot_incast_ACK_series(out_name, out_files, yaxistitle, ycolumn, yaxisscale, 'pdf',
                        out_name + oname, pdf_dir=pdf_dir, aggr='',
                        omit_const=omit_const, ymin=float(ymin), ymax=float(ymax),
                        lnames=lnames, stime=stime, etime=etime, groups=out_groups, burst_sep=burst_sep, 
                        sburst=int(sburst), plot_params=plot_params, plot_script=plot_script,
                        source_filter=source_filter)

    # done
    puts('\n[MAIN] COMPLETED plotting ackseq %s \n' % out_name)


## Plot goodput based on extracted ACKseq data
#  @param test_id Semicolon-separated list of test ID prefixes of experiments to analyse
#  @param out_dir Output directory for results
#  @param replot_only '1' don't extract raw ACK vs time data per test_ID if already done,
#                     but still re-calculate dupACKs and bursts (if any) before plotting results
#  @param source_filter Filter on specific flows to process
#  @param min_values Ignore flows with equal less output values / packets
#  @param omit_const '0' don't omit anything,
#                    '1' omit any series that are 100% constant
#                    (e.g. because there was no data flow)
#  @param ymin Minimum value on y-axis
#  @param ymax Maximum value on y-axis
#  @param lnames Semicolon-separated list of legend names per flow
#                (each name will have burst numbers appended if burst_sep is set)
#  @param stime Start time of plot window in seconds
#               (by default 0.0 = start of experiment)
#  @param etime End time of plot window in seconds (by default 0.0 = end of experiment)
#  @param out_name Prefix for filenames of resulting pdf files
#  @param pdf_dir Output directory for pdf files (graphs), if not specified it is
#                the same as out_dir
#  @param ts_correct '0' use timestamps as they are (default)
#                    '1' correct timestamps based on clock offsets estimated
#                        from broadcast pings
#   @param plot_params Parameters passed to plot function via environment variables
#   @param plot_script Specify the script used for plotting, must specify full path
#   @param total_per_experiment '0' plot per-flow goodput (default)
#                               '1' plot total goodput
@task
def analyse_goodput(test_id='', out_dir='', replot_only='0', source_filter='',
                       min_values='3', omit_const='0', ymin='0', ymax='0', lnames='',
                       stime='0.0', etime='0.0', out_name='',
                       pdf_dir='', ts_correct='1', 
                       plot_params='', plot_script='', total_per_experiment='0'):
    "Plot goodput vs time"

    (test_id_arr,
     out_files,
     out_groups) =  _extract_ackseq(test_id, out_dir, replot_only, source_filter,
                    ts_correct, 0, 0, 0, total_per_experiment)

    (out_files, out_groups) = filter_min_values(out_files, out_groups, min_values)
    out_name = get_out_name(test_id_arr, out_name)

    yaxistitle = 'Goodput [kbps]'
    ycolumn = 2
    yaxisscale = 0.008 
    oname = '_goodput'

    # ackseq always delivers cumulative values, instruct plot code to use the
    # differences
    plot_params = plot_params + 'DIFF=1'

    if total_per_experiment == '0':
        sort_flowkey='1'
    else:
        sort_flowkey='0'

    # Regular plots, each trial has one file containing data
    plot_time_series(out_name, out_files, yaxistitle, ycolumn, yaxisscale, 'pdf',
                     out_name + oname, pdf_dir=pdf_dir, aggr='1',
                     omit_const=omit_const, ymin=float(ymin), ymax=float(ymax),
                     lnames=lnames, stime=stime, etime=etime, groups=out_groups,
                     sort_flowkey=sort_flowkey,
                     plot_params=plot_params, plot_script=plot_script,
                     source_filter=source_filter)

    # done
    puts('\n[MAIN] COMPLETED plotting ackseq %s \n' % out_name)


## Extract inter-query times for each query burst
#  @param test_id Semicolon-separated list of test ID prefixes of experiments to analyse
#  @param out_dir Output directory for results
#  @param replot_only '1' don't extract raw ACK vs time data per test_ID if already done,
#                     but still re-calculate dupACKs and bursts (if any) before plotting results
#                     '0' always extract raw data
#  @param source_filter Filter on specific flows to process
#  @param ts_correct '0' use timestamps as they are (default)
#                    '1' correct timestamps based on clock offsets estimated
#                        from broadcast pings
#  @param query_host Name of the host that sent the queries
#  @param by_responder '1' plot times for each responder separately
#                      Limitation: if by_responder=1, then this function only supports one test id
#                      '0' times for all responders
#  @param cummulative '0' raw inter-query time for each burst 
#                     '1' accumulated inter-query time over all bursts
#  @param burst_sep 'time between burst (default 1.0), must be > 0 
#  @return Experiment ID list, map of flow names and file names, map of file names to group IDs
#
# Intermediate files end in ".iqtime.all ".iqtime.<responder>", ".iqtime.<responder>.tscorr" 
# The files contain the following columns:
# 1. Timestamp
# 2. IP of responder
# 3. port number of responder
# 4. inter-query time, time between request and first request in burst 
# 5. inter-query time, time between request and previous request  
# Note 4,5 can be cumulative or non-cumulative
def _extract_incast_iqtimes(test_id='', out_dir='', replot_only='0', source_filter='',
                           ts_correct='1', query_host='', by_responder='1', cumulative='0',
                           burst_sep='1.0'):
    "Extract incast inter-query times"

    ifile_ext = '.dmp.gz'
    ofile_ext = '.iqtimes' # inter-query times

    already_done = {}
    out_files = {}
    out_groups = {}

    burst_sep = float(burst_sep)

    if query_host == '':
        abort('Must specify query_host parameter')

    test_id_arr = test_id.split(';')
    if len(test_id_arr) == 0 or test_id_arr[0] == '':
        abort('Must specify test_id parameter')

    # Initialise source filter data structure
    sfil = SourceFilter(source_filter)

    group = 1
    for test_id in test_id_arr:

        # first process tcpdump files (ignore router and ctl interface tcpdumps)
        tcpdump_files = get_testid_file_list('', test_id,
                                       ifile_ext,
                                       'grep -v "router.dmp.gz" | grep -v "ctl.dmp.gz"')

        for tcpdump_file in tcpdump_files:
            # get input directory name and create result directory if necessary
            out_dirname = get_out_dir(tcpdump_file, out_dir)

            if tcpdump_file.find(query_host) == -1:
                # ignore all dump files not taken at query host
                continue

            # tcpdump filters and output file names
            # 'tcp[tcpflags] & tcp-push != 0' rule to extract only packets with push flag set (eliminate SYN, FIN, or ACKs
            # without data)
            filter1 = 'tcp[tcpflags] & tcp-push != 0'

            (dummy, query_host_internal) = get_address_pair_analysis(test_id, query_host, do_abort='0') 
            flow_name = query_host_internal + '_0_0.0.0.0_0'
            name = test_id + '_' + flow_name 
            out1 = out_dirname + name + ofile_ext

            if name not in already_done:
                if replot_only == '0' or not (os.path.isfile(out1)):

                    # Use "-A" option to tcpdump so we get the payload bytes and can check for GET 
                    # XXX this command fails if default snap length is changed because of the magic -B 4
                    local(
                       'zcat %s | tcpdump -A -tt -nr - "%s" | grep -B 5 "GET" | egrep "IP" | '
                       'awk \'{ print $1 " " $5; }\' | sed \'s/\.\([0-9]*\):/ \\1/\'  > %s' %
                       (tcpdump_file, filter1, out1))

                already_done[name] = 1

                if sfil.is_in(flow_name):
                    if ts_correct == '1':
                        out1 = adjust_timestamps(test_id, out1, query_host, ' ', out_dir)

                    if by_responder == '0':
                        # all responders in in one output file
                        out_name = out1 + '.all'

                        if replot_only == '0' or not (os.path.isfile(out_name)):
                            last_time = 0.0
                            burst_start = 0.0
                            cum_time = 0.0 

                            out_f = open(out_name, 'w')

                            with open(out1) as f:
                                lines = f.readlines()
                                for line in lines:
                                    fields = line.split()
                                    time = float(fields[0])

                                    if burst_start == 0.0:
                                        burst_start = time
                                    if line != lines[:-1] and last_time != 0.0 and time - last_time >= burst_sep:
                                        cum_time += (last_time - burst_start)
                                        burst_start = time
                                        last_req_time = time
                                    else:
                                        last_req_time = last_time
                                        if last_req_time == 0.0:
                                            last_req_time = time

                                    if cumulative == '0':
                                        out_f.write('%s %f %f\n' % (' '.join(fields), (time - burst_start), (time - last_req_time)))
                                    else:
                                        out_f.write('%s %f %f\n' % (' '.join(fields), cum_time + (time - burst_start),
                                                    cum_time + (time - last_req_time)))
                                    last_time = float(time)

                            out_f.close()

                        out_files[name] = out_name
                        out_groups[out_name] = group

                    else:
                        # split inter-query times into multiple files by responder
                        # XXX ignore replot_only here, cause too difficult to check
                        last_time = 0.0
                        burst_start = 0.0
                        responders = {}
                        cum_time = {} 
                        with open(out1) as f:
                            lines = f.readlines()
                            for line in lines:
                                fields = line.split()
                                time = float(fields[0])
                                responder = fields[1] + '.' + fields[2]
                                if responder not in responders:
                                    out_name = out1 + '.' + responder 
                                    responders[responder] = open(out_name, 'w')
                                    out_files[responder] = out_name 
                                    cum_time[responder] = 0

                                out_f = responders[responder]

                                if burst_start == 0.0:
                                    burst_start = time
                                if line != lines[:-1] and last_time != 0.0 and time - last_time >= burst_sep:
                                    #cum_time[responder] += (last_time - burst_start)
                                    burst_start = time
                                    last_req_time = time
                                else:
                                    last_req_time = last_time
                                    if last_req_time == 0.0:
                                        last_req_time = time

                                if cumulative == '0':
                                    out_f.write('%s %f %f\n' % (' '.join(fields), (time - burst_start), (time - last_req_time)))
                                else:
                                    out_f.write('%s %f %f\n' % (' '.join(fields), cum_time[responder] + (time - burst_start),
                                                cum_time[responder] + (time - last_req_time)))

                                cum_time[responder] += time - burst_start
                                last_time = float(time)

                        for out_f in responders.values():
                            out_f.close()

                        # sort by responder name and set groups (ip+port)
                        for responder in sorted(responders.keys()):
                            out_name = out1 + '.' + responder
                            out_groups[out_name] = group
                            group += 1

        if by_responder == '0':
            group += 1
        else:
            group = 1


    return (test_id_arr, out_files, out_groups)


## Extract inter-query times for each query burst
## SEE _extract_incast_iqtimes()
@task
def extract_incast_iqtimes(test_id='', out_dir='', replot_only='0', source_filter='',
                           ts_correct='1', query_host='', by_responder='1', cumulative='0',
                           burst_sep='1.0'):
    "Extract incast inter-query times"
   
    _extract_incast_iqtimes(test_id, out_dir, replot_only, source_filter, ts_correct,
                            query_host, by_responder, cumulative, burst_sep)

    # done
    puts('\n[MAIN] COMPLETED extracting incast inter-query times %s \n' % test_id)


## Plot inter-query times
#  @param test_id Semicolon-separated list of test ID prefixes of experiments to analyse
#  @param out_dir Output directory for results
#  @param replot_only '1' don't extract raw data per test_ID if already done,
#                     '0' always extract raw data
#  @param source_filter Filter on specific flows to process
#  @param ts_correct '0' use timestamps as they are (default)
#                    '1' correct timestamps based on clock offsets estimated
#                        from broadcast pings
#  @param query_host Name of the host that sent the queries
#  @param by_responder '1' plot times for each responder separately
#                      '0' times for all responders
#  @param cumulative '0' raw inter-query time for each burst 
#                     '1' accumulated inter-query time over all bursts
#  @param burst_sep Time between burst (default 1.0), must be > 0 
#  @param min_values Ignore flows with equal less output values / packets
#  @param omit_const '0' don't omit anything,
#                    '1' omit any series that are 100% constant
#                       (e.g. because there was no data flow)
#  @param out_name File name prefix for resulting pdf file
#  @param diff_to_burst_start '0' print time diferences between requests, i.e.
#                       the times are the differences between request and previous
#                       request
#                       '1' print time differences between requests and first requests in
#                       burst (default) 
#   @param ymin Minimum value on y-axis
#   @param ymax Maximum value on y-axis
#   @param lnames Semicolon-separated list of legend names
#   @param stime Start time of plot window in seconds
#                (by default 0.0 = start of experiment)
#   @param etime End time of plot window in seconds (by default 0.0 = end of experiment)
#   @param pdf_dir Output directory for pdf files (graphs), if not specified it
#                  is the same as out_dir
#   @param ts_correct '0' use timestamps as they are (default)
#                     '1' correct timestamps based on clock offsets estimated
#                         from broadcast pings
#   @param plot_params Parameters passed to plot function via environment variables
#   @param plot_script Specify the script used for plotting, must specify full path
#                      (default is config.TPCONF_script_path/plot_contour.R)
#
# Note setting cumulative=1 and diff_to_burst_start=0 does produce a graph, but the
# graph does not make any sense. 
@task
def analyse_incast_iqtimes(test_id='', out_dir='', replot_only='0', source_filter='',
                    ts_correct='1', query_host='', by_responder='1', cumulative='0',
                    burst_sep='1.0', min_values='3', omit_const='0', ymin='0', ymax='0', lnames='',
                    stime='0.0', etime='0.0', out_name='', diff_to_burst_start='1',
                    pdf_dir='',  plot_params='', plot_script=''):
    "Plot incast inter-query times"

    if query_host == '':
        abort('Must specify query_host parameter')

    (test_id_arr,
     out_files,
     out_groups) = _extract_incast_iqtimes(test_id, out_dir, replot_only, source_filter, 
                            ts_correct, query_host, by_responder, cumulative, burst_sep) 

    (out_files, out_groups) = filter_min_values(out_files, out_groups, min_values)
    out_name = get_out_name(test_id_arr, out_name)

    if cumulative == '0':
        ylabel = 'Inter-query time (ms)'
    else:
        ylabel = 'Cumulative Inter-query time (ms)'

    if diff_to_burst_start == '1':
        ycolumn = 4
    else:
        ycolumn = 5

    if by_responder == '0' and cumulative == '0':
        out_name_add = '_iqtimes'
    elif by_responder == '0' and cumulative == '1':
        out_name_add = '_cum_iqtimes' 
    elif by_responder == '1' and cumulative == '0':
        out_name_add = '_iqtimes_responders'
    else:
        out_name_add = '_cum_iqtimes_responders'

    plot_time_series(out_name, out_files, ylabel, ycolumn, 1000, 'pdf',
                     out_name + out_name_add, pdf_dir=pdf_dir, aggr='', 
                     sort_flowkey='0', omit_const=omit_const, ymin=float(ymin), ymax=float(ymax), 
                     lnames=lnames, stime=stime, etime=etime, groups=out_groups,
                     plot_params=plot_params, plot_script=plot_script,
                     source_filter=source_filter)

    # done
    puts('\n[MAIN] COMPLETED plotting incast inter-query times %s\n' % out_name)


## Extract response times for each responder for incast experiments from tcpdump data 
#  @param test_id Semicolon-separated list of test ID prefixes of experiments to analyse
#  @param out_dir Output directory for results
#  @param replot_only '1' don't extract raw data per test_ID if already done,
#                     '0' always extract raw data 
#  @param source_filter Filter on specific flows to process
#  @param ts_correct '0' use timestamps as they are (default)
#                    '1' correct timestamps based on clock offsets estimated
#                        from broadcast pings
#  @param query_host Name of the host that sent the queries (s specified in config)
#  @param slowest_only '0' plot response times for individual responders 
#                      '1' plot slowest response time across all responders
#                      '2' plot time between first request and last response finished
#
# Intermediate files end in ".restimes", ".restimes.tscorr" 
# The files contain the following columns:
# 1. Timestamp the GET was sent
# 2. Burst number
# 3. Querier IP.port
# 4. Responder IP.port
# 5. Response time [seconds]
def _extract_incast_restimes(test_id='', out_dir='', replot_only='0', source_filter='',
                             ts_correct='1', query_host='', slowest_only='0'):
    "Extract incast response times"

    ifile_ext = '.dmp.gz'
    ofile_ext = '.restimes'

    already_done = {}
    out_files = {}
    out_groups = {}

    if query_host == '':
        abort('Must specify query_host parameter')

    test_id_arr = test_id.split(';')
    if len(test_id_arr) == 0 or test_id_arr[0] == '':
        abort('Must specify test_id parameter')

    # Initialise source filter data structure
    sfil = SourceFilter(source_filter)

    group = 1
    for test_id in test_id_arr:

        # first process tcpdump files (ignore router and ctl interface tcpdumps)
        tcpdump_files = get_testid_file_list('', test_id,
                                       ifile_ext,
                                       'grep -v "router.dmp.gz" | grep -v "ctl.dmp.gz"')

        for tcpdump_file in tcpdump_files:
            # get input directory name and create result directory if necessary
            out_dirname = get_out_dir(tcpdump_file, out_dir)
            dir_name = os.path.dirname(tcpdump_file)

            if tcpdump_file.find(query_host) == -1:
                # ignore all dump files not taken at query host
                continue

            # unique flows
            flows = lookup_flow_cache(tcpdump_file)
            if flows == None:
                flows = _list(local('zcat %s | tcpdump -nr - "tcp" | '
                                'awk \'{ if ( $2 == "IP" ) { print $3 " " $5 " tcp" } }\' | '
                                'sed "s/://" | '
                                'sed "s/\.\([0-9]*\) /,\\1 /g" | sed "s/ /,/g" | '
                                'LC_ALL=C sort -u' %
                                tcpdump_file, capture=True))

                append_flow_cache(tcpdump_file, flows)

            # since client sends first packet to server, client-to-server flows
            # will always be first

            for flow in flows:

                src, src_port, dst, dst_port, proto = flow.split(',')

                # get external and internal addresses
                src, src_internal = get_address_pair_analysis(test_id, src, do_abort='0')
                dst, dst_internal = get_address_pair_analysis(test_id, dst, do_abort='0')

                if src == '' or dst == '':
                    continue

                # ignore flows with querier as destination
                if dst == query_host:
                    continue

                # flow name
                name = src_internal + '_' + src_port + \
                    '_' + dst_internal + '_' + dst_port
                # test id plus flow name
                if len(test_id_arr) > 1:
                    long_name = test_id + '_' + name
                else:
                    long_name = name

                # the two dump files
                dump1 = dir_name + '/' + test_id + '_' + src + ifile_ext

                # tcpdump filters and output file names
                # 'tcp[tcpflags] & tcp-push != 0' rule to extract only packets with push flag set 
                # (eliminate SYN, FIN, or ACKs without data)
                filter1 = 'host ' + dst_internal + ' && port ' + dst_port + \
                    ' && tcp[tcpflags] & tcp-push != 0'

                out1_tmp = out_dirname + test_id + '_' + name + ofile_ext + '.tmp'
                out1 = out_dirname + test_id + '_' + name + ofile_ext
                
                if long_name not in already_done:
                    if replot_only == '0' or not ( os.path.isfile(out1) ):
 
                        # Use "-A" option to tcpdump so we get the payload bytes 
                        # XXX this falls apart if snap size is not the default because of the magic -B 8
                        local(
                            'zcat %s | tcpdump -A -tt -nr - "%s" | grep -B 10 "GET" | egrep "IP" | '
                            'awk \'{ print $1 " " $3 " " $5; }\' | sed \'s/://\' > %s' %
                            (dump1, filter1, out1_tmp))
                        # get the last line, assume this is last packet of last request
                        local('zcat %s | tcpdump -tt -nr - "%s" | tail -1 | '
                              'awk \'{ print $1 " " $3 " " $5; }\' | sed \'s/://\' >> %s' % 
                            (dump1, filter1, out1_tmp))

                        # compute response times from each GET packet and corresponding final data packet
                        out_f = open(out1, 'w')
                        with open(out1_tmp) as f:
                            lines = f.readlines()
                            cnt = 0
                            last_src = ''
                            for line in lines:
                                fields = line.split()
                                if cnt % 2 == 0:
                                    # request
                                    req_time = float(line.split()[0])
                                elif fields[1] != last_src:
                                    # response, unless the source is the same as for the last packet
                                    # (then we possibly have no response)
                                    res_time = float(fields[0]) - req_time
                                    out_f.write('%f %i %s %s %s\n' %  (req_time, int(cnt/2) + 1, fields[2], 
                                                                       fields[1], res_time))

                                last_src = fields[1] 
                                cnt += 1

                        out_f.close()
                        os.remove(out1_tmp)

                    already_done[long_name] = 1

                    if sfil.is_in(name):
                        if ts_correct == '1':
                            out1 = adjust_timestamps(test_id, out1, dst, ' ', out_dir)

                        out_files[long_name] = out1 
                        out_groups[out1] = group

        # check for consistency and abort if we see less response times for one responder
        max_cnt = 0
        for name in out_files:
            if out_groups[out_files[name]] == group:
                cnt = int(local('wc -l %s | awk \'{ print $1 }\'' %
                                out_files[name], capture=True)) 
                if max_cnt > 0 and cnt < max_cnt:
                    abort('Responder timed out in experiment %s' % test_id)
                if cnt > max_cnt:
                    max_cnt = cnt

        group += 1

    if slowest_only != '0':
        (out_files, out_groups) = get_slowest_response_time(out_files, out_groups,
                                  int(slowest_only) - 1)


    return (test_id_arr, out_files, out_groups)


## Extract response times for each responder for incast experiments 
## SEE _extract_restimes()
@task
def extract_incast_restimes(test_id='', out_dir='', replot_only='0', source_filter='',
                             ts_correct='1', query_host=''):
    "Extract incast response times"

    _extract_incast_restimes(test_id, out_dir, replot_only, source_filter, ts_correct,
                             query_host)

    # done
    puts('\n[MAIN] COMPLETED extracting incast response times %s \n' % test_id)


