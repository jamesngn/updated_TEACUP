# Copyright (c) 2013-2017 Centre for Advanced Internet Architectures,
# Swinburne University of Technology. All rights reserved.
#
# Author: Grenville Armitage (garmitage@swin.edu.au)
#         Sebastian Zander (sebastian.zander@gmx.de)
#         
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
# $Id: analyse_owd.py,v 1920bf13a9bf 2018/02/07 09:03:39 garmitage $

import os
import errno
import datetime
import re
import imp

import dpkt     # For direct pcap file parsing
import zlib     # For calculating crc32 hash


import tempfile

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


## Extract OWD for flows
## SEE _extract_owd_pktloss()
@task
def extract_owd(test_id='', out_dir='', replot_only='0', source_filter='',
                ts_correct='1', burst_sep='0.0', sburst='1', eburst='0',
                seek_window='', anchor_map='', owd_midpoint='0'):
    "Extract OWD of flows"

    _extract_owd_pktloss(test_id, out_dir, replot_only, source_filter,
                    ts_correct, burst_sep, sburst, eburst,
                    seek_window, log_loss='0',
                    anchor_map=anchor_map,
                    owd_midpoint = owd_midpoint)
    # done
    puts('\n[MAIN] COMPLETED extracting OWDs %s \n' % test_id)



## Extract PKTLOSS for flows
## SEE _extract_owd_pktloss()
@task
def extract_pktloss(test_id='', out_dir='', replot_only='0', source_filter='',
                ts_correct='1', burst_sep='0.0', sburst='1', eburst='0',
                seek_window='', log_loss='2'):
    "Extract per-flow packet loss events vs time (or cumlative over time)"

    _extract_owd_pktloss(test_id, out_dir, replot_only, source_filter,
                    ts_correct, burst_sep, sburst, eburst,
                    seek_window, log_loss)

    # done
    puts('\n[MAIN] COMPLETED extracting pktloss %s \n' % test_id)



## Plot OWD for flows
#  @param test_id Test ID prefix of experiment to analyse
#  @param out_dir Output directory for results
#  @param replot_only Don't extract data again, just redo the plot
#  @param source_filter Filter on specific sources
#  @param min_values Minimum number of data points in file, if fewer points
#                    the file is ignored
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
#  @param plot_params Set env parameters for plotting
#  @param plot_script Specify the script used for plotting, must specify full path
#  @param burst_sep '0' plot OWD values as they come, relative to 1st OWD value
#                 > '0' plot OWD values relative to 1st OWD value after gaps
#                       of more than burst_sep milliseconds (e.g. incast query/response bursts)
#                 < 0,  plot OWD values relative to 1st OWD value after each abs(burst_sep)
#                       seconds since the first burst @ t = 0 (e.g. incast query/response bursts)
#  @param sburst Start plotting with burst N (bursts are numbered from 1)
#  @param eburst End plotting with burst N (bursts are numbered from 1)
#  @param seek_window Assume you'll find next matching packet within seek_window of most recent match
#               in the 'destination' capture file
@task
def analyse_owd(test_id='', out_dir='', replot_only='0', source_filter='',
                min_values='3', omit_const='0', ymin='0', ymax='0',
                lnames='', stime='0.0', etime='0.0', out_name='', pdf_dir='',
                ts_correct='1',plot_params='', plot_script='', burst_sep='0.0',
                sburst='1', eburst='0', seek_window='', anchor_map='', owd_midpoint='0'):
    "Plot OWD of flows"
    
    # Note we allow ts_correct as a parameter for syntactic similarity to other
    # analyse_* tasks, but abort with warning if user tries explicitly to
    # make it 0 (which is unacceptable for OWD calculations)
    
    if ts_correct == '0':
        abort("Warning: Cannot do OWD calculations with ts_correct=0")

    (test_id_arr, 
    out_files, 
    out_groups) = _extract_owd_pktloss(test_id, out_dir, replot_only, 
                                    source_filter, ts_correct,
                                    burst_sep, sburst, eburst,
                                    seek_window, log_loss='0',
                                    anchor_map=anchor_map,
                                    owd_midpoint = owd_midpoint)
        
    (out_files, out_groups) = filter_min_values(out_files, out_groups, min_values)
    out_name = get_out_name(test_id_arr, out_name)
 
    burst_sep = float(burst_sep)
    if burst_sep == 0.0:
        plot_time_series(out_name, out_files, 'OWD (ms)', 2, 1000.0, 'pdf',
                     out_name + '_owd', pdf_dir=pdf_dir, omit_const=omit_const,
                     ymin=float(ymin), ymax=float(ymax), lnames=lnames,
                     stime=stime, etime=etime, groups=out_groups, plot_params=plot_params,
                     plot_script=plot_script, source_filter=source_filter)
    else:
        # Each trial has multiple files containing data from separate bursts detected within the trial
        plot_incast_ACK_series(out_name, out_files, 'OWD (ms)', 2, 1000.0, 'pdf',
                        out_name + '_owd', pdf_dir=pdf_dir, aggr='',
                        omit_const=omit_const, ymin=float(ymin), ymax=float(ymax),
                        lnames=lnames, stime=stime, etime=etime, groups=out_groups, burst_sep=burst_sep,
                        sburst=int(sburst), plot_params=plot_params, plot_script=plot_script,
                        source_filter=source_filter)


    # done
    puts('\n[MAIN] COMPLETED plotting OWDs %s \n' % out_name)
    

## Plot PKTLOSS (individual or cumulative) for flows using _extract_owd_pktloss()
##
#  @param test_id Test ID prefix of experiment to analyse
#  @param out_dir Output directory for results
#  @param replot_only Don't extract data again, just redo the plot
#  @param source_filter Filter on specific sources
#  @param min_values Minimum number of data points in file, if fewer points
#                    the file is ignored
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
#  @param ts_correct '0' use timestamps as they are (Allowed but not preferred for PKTLOSS)
#                    '1' correct timestamps based on clock offsets estimated
#                        from broadcast pings (default)
#  @param plot_params Set env parameters for plotting
#  @param plot_script Specify the script used for plotting, must specify full path
#  @param burst_sep '0' plot pktloss values as they come, relative to 1st pktloss value
#                 > '0' plot pktloss values relative to 1st pktloss value after gaps
#                       of more than burst_sep milliseconds (e.g. incast query/response bursts)
#                 < 0,  plot pktloss values relative to 1st pktloss value after each abs(burst_sep)
#                       seconds since the first burst @ t = 0 (e.g. incast query/response bursts)
#  @param sburst Start plotting with burst N (bursts are numbered from 1)
#  @param eburst End plotting with burst N (bursts are numbered from 1)
#  @param seek_window Assume you'll find next matching packet within seek_window of
#                   most recent match in the destination's capture file
#  @param log_loss '1': Plot individual loss events
#                  '2': Plot cumulative loss events (default)
#
#
@task
def analyse_pktloss(test_id='', out_dir='', replot_only='0', source_filter='',
                min_values='3', omit_const='0', ymin='0', ymax='0',
                lnames='', stime='0.0', etime='0.0', out_name='', pdf_dir='',
                ts_correct='1', plot_params='', plot_script='', burst_sep='0.0',
                sburst='1', eburst='0', seek_window='', log_loss='2'):
    "Plot per-flow packet loss events vs time (or cumlative over time)"
    
    if log_loss != '1' and log_loss !='2':
        abort("Must set log_loss=1 (pkt loss events) or log_loss=2 (cumulative pkt loss)")
        
    (test_id_arr, 
    out_files, 
    out_groups) = _extract_owd_pktloss(test_id, out_dir, replot_only, 
                                    source_filter, ts_correct,
                                    burst_sep, sburst, eburst,
                                    seek_window, log_loss)
        
    (out_files, out_groups) = filter_min_values(out_files, out_groups, min_values)
    out_name = get_out_name(test_id_arr, out_name)
 
    burst_sep = float(burst_sep)
    if burst_sep == 0.0:
        plot_time_series(out_name, out_files, 'Lost packets', 2, 1, 'pdf',
                     out_name + '_loss2', pdf_dir=pdf_dir, omit_const=omit_const,
                     ymin=float(ymin), ymax=float(ymax), lnames=lnames,
                     stime=stime, etime=etime, groups=out_groups, plot_params=plot_params,
                     plot_script=plot_script, source_filter=source_filter)
    else:
        # Each trial has multiple files containing data from separate bursts detected within the trial
        plot_incast_ACK_series(out_name, out_files, 'Lost packets', 2, 1, 'pdf',
                        out_name + '_loss2', pdf_dir=pdf_dir, aggr='',
                        omit_const=omit_const, ymin=float(ymin), ymax=float(ymax),
                        lnames=lnames, stime=stime, etime=etime, groups=out_groups, burst_sep=burst_sep,
                        sburst=int(sburst), plot_params=plot_params, plot_script=plot_script,
                        source_filter=source_filter)


    # done
    puts('\n[MAIN] COMPLETED plotting pktloss %s \n' % out_name)


## Extract OWD or LOSS for flows using DPKT/TCPDUMP
# The extracted files have an extension of .owds or .loss
#
# For OWD the output file format is space-separated <timestamp> <OWD> pairs:
# 1. <timestamp> = Timestamp of packet emitted by source (seconds.microseconds)
# 2. OWD (seconds)(time taken to reach destination)
#
# For Loss the output file format is space-separated <timestamp> <X> pairs:
# 1. <timestamp> = Timestamp of packet emitted by source (seconds.microseconds)
# 2. X = ('0'/'1' for successful/lost packet,
#         or cumulative pkts lost since start of flow)
#
#  @param test_id Test ID prefix of experiment to analyse
#  @param out_dir Output directory for results
#  @param replot_only Don't extract data again that is already extracted
#  @param source_filter Filter on specific sources
#  @param ts_correct '0' use timestamps as they are (not allowed)
#                    '1' correct timestamps based on clock offsets estimated
#                        from broadcast pings  (default and mandatory)
#  @param burst_sep '0' plot OWD/pktloss values as they come, relative to 1st OWD/pktloss value
#                 > '0' plot OWD/pktloss values relative to 1st OWD/pktloss value after gaps
#                       of more than burst_sep milliseconds (e.g. incast query/response bursts)
#                 < 0,  plot OWD/pktloss values relative to 1st OWD/pktloss value after each abs(burst_sep)
#                       seconds since the first burst @ t = 0 (e.g. incast query/response bursts)
#  @param sburst Start plotting with burst N (bursts are numbered from 1)
#  @param eburst End plotting with burst N (bursts are numbered from 1)
#  @param seek_window Assume you'll find next matching packet within seek_window of most recent match
#               in the 'destination' capture file (default=16000 in case we're checking UDP packets,
#               and want to avoid duplicate matching due to wrap-around of ip.id field)
#  @param log_loss '0': Extract OWD (<timestamps> <OWD>)    (default '0')
#                  '1': Extract loss events, log output to <test_id><flow>.loss file in the form
#                       "<timestamp> 0" (no loss) or "<timestamp> 1" (loss), timestamp of packet @ source
#                  '2': Extract cumulative loss events, log output to <test_id><flow>.loss file in the form
#                       "<timestamp> N", where N is number of packets lost up to <timestamp>)
#  @param anchor_map "<srcip1>:<dstip1>;<srcip2>:<dstip2>;..." Indicate if OWD for pkts from
#                   <srcip> should be logged with timestamp of when seen closer to <dstip>
#  @param owd_midpoint  '0': OWD is logged at timestamp when packet seen at origin
#                       '1': OWD is logged as occuring halfway between origin and destination
#                       (i.e. time_at_src + 0.5*OWD)
#  @return Test ID list, map of flow names to interim data file names and 
#          map of file names and group IDs
def _extract_owd_pktloss(test_id='', out_dir='', replot_only='0', source_filter='',
                ts_correct='1', burst_sep='0.0', sburst='1', eburst='0',
                seek_window='16000', log_loss='0', anchor_map='', owd_midpoint='0'):
    "Extract OWD or PKTLOSS of flows"

    ifile_ext = '.dmp.gz'
    
    if log_loss == '0':
        ofile_ext = '.owds2.gz'
    else:
        ofile_ext = '.loss2.gz'

    already_done = {}
    out_files = {}
    out_groups = {}

    test_id_arr = test_id.split(';')
    if len(test_id_arr) == 0 or test_id_arr[0] == '':
        abort('Must specify test_id parameter')

    if ts_correct == '0' and log_loss == '0':
        abort('Must use ts_correct=1 when calculating OWD')

    # Initialise source filter data structure
    sfil = SourceFilter(source_filter)
    
    # EXPERIMENTAL: anchor_map="<srcip1>:<dstip1>;<srcip2>:<dstip2>;..."
    # Normally a packet's OWD is logged as having occurred at the time the
    # packet is seen in pcap file associated with <srcip> (src_extname)
    # An 'anchor_map' entry allows you to specify that a packet's OWD be
    # logged as having occurred at the time the packet from <srcip> was
    # seen in the pcap file associated with <dstip> (dst_extname)
    # This is only operates on packets between <srcip>:<dstip>, other
    # flows in the same testID are unaffected.

    anchor_map_list = {}
    if anchor_map != '':
        if replot_only == '1':
            abort("Must specify replot_only=0 in conjunction with anchor_map")
        entries = anchor_map.split(';')
        for entry in entries:
            k, v = entry.split(':')
            anchor_map_list[k] = v

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
                # If not previously found in flow_cache,
                # extract and identify the tcp and udp flows contained in tcpdump_file
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

                # Add them to the flow cache
                append_flow_cache(tcpdump_file, flows)

            # Walk through and process the flows identified in this current tcpdump_file
            
            for flow in flows:
                
                # First extract src & dst as IP addr on experiment networks
                src, src_port, dst, dst_port, proto = flow.split(',')
                
                # Map src & dst (IP addr) to testbed-specific external (control network)
                # host names from config.py ({src,dst}_extname) and internal (experiment network)
                # hostnames/addresses from config.py ({src,dst}_internal)
                src_extname, src_internal = get_address_pair_analysis(test_id, src, do_abort='0')
                dst_extname, dst_internal = get_address_pair_analysis(test_id, dst, do_abort='0')
                
                # Skip cases of random (broadcast) traffic involving an IP address for
                # which no experimental network NIC (and hence control network hostname)
                # is directly related
                if src_extname == '' or dst_extname == '':
                    continue

                # flow name
                name = src_internal + '_' + src_port + '_' + dst_internal + '_' + dst_port
                
                # test id plus flow name
                if len(test_id_arr) > 1:
                    long_name = test_id + '_' + name
                else:
                    long_name = name
                    
                if long_name not in already_done:

                    # Construct filenames for files containing final <time> <owd|loss> pairs
                    out_final = out_dirname + test_id + '_' + name + ofile_ext
                    
                    # Only embark on actual filtering/extraction if we're asked to regenerate
                    # the intermediate OWD values, or for some reason the intermediate OWD
                    # file is missing...
                    if replot_only == '0' or not os.path.isfile(out_final):
                                                
                        # Per flow/host:
                        #   Create intermediate file of timestamps + uniqString from pcap files,
                        #   THEN call adjust_timestamps to construct a version with timestamps adjusted
                        #   relative to a single reference host in the testbed
                        #   THEN use the adjusted timestamps in the subsequent owd/loss calculations.
                        
                        # To extract packets in in FORWARD direction from both src and dst pcap files,
                        # construct dpkt flow filter in form <src_ip>:<src_port>:<dst_ip>:<dst_port>
                        # (and more specifically, from src_internal:src_port to dst_internal:dst_port).

                        filter_dpkt = src_internal + ':' + src_port + ':' + dst_internal + ':' + dst_port
                        src_port_int = int(src_port)
                        dst_port_int = int(dst_port)
                        
                        # Loop across the src and dst dmp files
                        
                        tmp_fwd_out_adj = {}
                        for dmpfile_host, dirsuffix in ([src_extname,"src"],[dst_extname,"dst"]):
                            
                            # Construct the file name of the dump file that contains this
                            # flow's packets. 'src' captured at (near) the flow's source, and 'dst'
                            # captured at (near) the flow's destination.
                            dmp_file = dir_name + '/' + test_id + '_' + dmpfile_host + ifile_ext
                            print("Extracting packets for " + name + " from:" + dmp_file)
                            
                            # Construct filename for intermediate "<time> <uniqueString>" output files
                            # whose timestamps will be adjusted by adjust_timestamps()
                            # before being used for owd calculations
                            # (NOTE: Due to adjust_timestamps making assumptions about out_dir parameter,
                            # we currently can't place these tmp files under /tmp)
                            tmp_fwd_out = tempfile.mktemp(suffix=test_id + '_' + name +'_fwd_out_' + dirsuffix+".gz", dir=out_dirname)
                            
                            # Extract packet id info
                            if dmp_file.endswith('.gz'):
                                f_dmp_file = gzip.open(dmp_file)
                            else:
                                f_dmp_file = open(dmp_file)
                            pcap_reader = dpkt.pcap.Reader(f_dmp_file)
                            pcap_reader.setfilter(filter_dpkt)
                            #pcap_reader.setfilter('')
                            
                            # Create a compressed temporary intermediate file
                            f_tmp_fwd_out = gzip.open(tmp_fwd_out,'wb',1)
                            
                            # Walk across every packet in this pcap file
                            for ts, pkt in pcap_reader:
                                # get pointer to ethernet layer and check that we have IP
                                eth = dpkt.ethernet.Ethernet(pkt)
                                if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                                    continue

                                # get pointer to IP layer
                                ip_pkt = eth.data

                                # ignore if src or dst IP not the ones specified in filter
                                if socket.inet_ntoa(ip_pkt.src) != src_internal or \
                                    socket.inet_ntoa(ip_pkt.dst) != dst_internal:
                                        continue

                                # ignore if UDP/TCP src or dst ports not the ones specified in filter
                                # get pointer to payload
                                if type(ip_pkt.data) == dpkt.udp.UDP:
                                    udp_frame = ip_pkt.data
                                    if udp_frame.sport != src_port_int or udp_frame.dport != dst_port_int:
                                        continue
                                    # Add IP ID field to the payload to ensure
                                    # at least something semi-unique is hashed
                                    # if UDP payload is invariant
                                    payload = str(ip_pkt.id) +udp_frame.data
                                    
                                elif type(ip_pkt.data) == dpkt.tcp.TCP:
                                    tcp_frame = ip_pkt.data
                                    if tcp_frame.sport != src_port_int or tcp_frame.dport != dst_port_int:
                                        continue
                                    # Use IP ID field, TCP Sequence number and ACK number to
                                    # construct a mostly unique string within context of this flow
                                    payload = str(ip_pkt.id) + str(tcp_frame.seq) + str(tcp_frame.ack)
                                else:
                                    continue
                                
                                # Write <timestamp> <crc32 hash of uniqueString bytes>
                                # (hashing here eliminates any later problems parsing payloads
                                # containing null bytes)

                                f_tmp_fwd_out.write("%f %s\n" % (ts,zlib.crc32(payload)))

                            f_tmp_fwd_out.close()
                            f_dmp_file.close()
                            
                            # Apply timestamp corrections to the data thus extracted, prior to
                            # calculating OWDs. Correction is MANDATORY otherwise the
                            # 'calculated' OWDs are essentially useless.
                            tmp_fwd_out_adj[dirsuffix] = adjust_timestamps(test_id, tmp_fwd_out, dmpfile_host, ' ', out_dir)
                            
                            # Remove pre-adjustment files.
                            os.remove(tmp_fwd_out)
                            
                        # Now we have unique packet hashes seen at both src and dst locations,
                        # and timestamps have been adjusted for clockoffsets.
                        
                        # Begin calculating OWD or identifying when packet losses occurred
                        
                        # Read into memory the <adjusted_timestamp> <uniqString> datasets captured
                        # at dst (2nd place packet seen, "destination"). The src is (1st place packet
                        # seen, "source")
                        
                        dst_data_time=list()
                        dst_data_uniqString=list()
                        for line in gzip.open(tmp_fwd_out_adj["dst"]).read().splitlines():
                            sline = line.split(" ")
                            dst_data_time.append(float(sline[0]))
                            dst_data_uniqString.append(sline[1])

                        # Walk through tmp_fwd_out_adj["src"] looking for matches to packets
                        # in dst_data_uniqString, and write <time> <owd|loss> pairs in plain
                        # ASCII to out_final
                        
                        # To limit potential duplicate matches to packets received forward
                        # in time from previous match in dst_data_uniqString, maintain
                        # index next_j pointing to next row in dst_data_uniqString to start
                        # matching next packet from tmp_fwd_out_adj["src"]
                        next_j = 0
                        last_j = len(dst_data_uniqString)-1

                        # As a speed-up hack, assume match in dst_data_uniqString is
                        # within sk_window entries of next_j (saves searching all the
                        # way to the end of dst_data_uniqString when seeking a lost packet)
                        # Keeping seek_window in the low 1000s also minimises chances of
                        # duplicate matches.
                        if seek_window != '':
                            sk_window = int(seek_window)
                        else:
                            sk_window = last_j
                        
                        # Create gzipped output file (rough experiments showed over reduction
                        # in on-disk file size easily 100s of K down to 10s of K).
                        # R automagically reads gzipped data files, so no changes required
                        # to subsequent analyse_* plotting scripts.
                        f = gzip.open(out_final, 'w')
                        
                        cumulative_loss = 0
                        
                        # Decide whether to use timestamp at src or dst for OWD
                        # (Default to src, unless anchor_map indicates using dst for
                        # this particular traffic pattern)
                        anchor = 0 # Default print timestamp at src
                        if log_loss == '0': # Only relevant for OWD calculations
                            if src_internal in anchor_map_list.keys():
                                #print "*** Found " + src_internal + " in anchor_map"
                                if anchor_map_list[src_internal] == dst_internal:
                                    # Only relevant if the map relates to both src_internal and dst_internal
                                    #print "*** " + src_internal + " points to " + anchor_map_list[src_internal] + " in anchor_map"
                                    anchor = 1 # Print timestamp at dst
                                        
                        for line in gzip.open(tmp_fwd_out_adj["src"]).read().splitlines():
                            i = line.split(" ")
                            try:
                                # The following search will raise a 'ValueError' exception if i[1] does not occur in dst_data_uniqString[next_j:]
                                j = dst_data_uniqString[next_j:min((next_j+sk_window),last_j+1)].index(i[1])
                                
                                if log_loss == '0':
                                    # OWD is diff between i[0] and dst_data_time[next_j+j]
                                    ts = float(i[0])
                                    owd = dst_data_time[next_j+j]-float(i[0])
                                    # If required, print event as occuring at dst timestamp rather than src timestamp
                                    if anchor:
                                        ts = dst_data_time[next_j+j]
                                    # If we want to imply the OWD "existed" at some mid-point
                                    # between pkt seen at src and seen at dst
                                    if owd_midpoint == '1':
                                        ts += owd/2                                    
                                    f.write('%f %f\n' % (ts, owd))
                                    
                                if log_loss == '1':
                                    # No lost packet, emit "0"
                                    f.write('%s 0\n' % (i[0]))
                                if log_loss == '2':
                                    # No lost packet, emit previous cumulative count
                                    f.write('%s %i\n' % (i[0], cumulative_loss))
                                    
                                next_j = min(next_j+j+1,last_j)
                                
                            except ValueError:
                                # No match means a packet loss
                                if log_loss == '1':
                                    # Single loss event, emit "1"
                                    f.write('%s 1\n' % (i[0]))
                                if log_loss == '2':
                                    # Single loss event, increment cumulative count, emit cumulative count
                                    cumulative_loss += 1
                                    f.write('%s %i\n' % (i[0], cumulative_loss))
                                pass
                                                    
                        f.close()
                        dst_data_time=[]
                        dst_data_uniqString=[]
                        
                        # Clean up temporary post-adjustment files
                        os.remove(tmp_fwd_out_adj["src"])
                        os.remove(tmp_fwd_out_adj["dst"])
                        
                    already_done[long_name] = 1
                    
                    if sfil.is_in(name):
                        (out_files, 
                        out_groups) = select_bursts(long_name, group, out_final, burst_sep, sburst, eburst,
                                    out_files, out_groups)
                         
        group += 1

    return (test_id_arr, out_files, out_groups)


