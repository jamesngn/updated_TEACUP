# -*- coding: utf-8 -*-
#
# Copyright (c) 2015 Centre for Advanced Internet Architectures,
# Swinburne University of Technology. All rights reserved.
#
# Author: Isaac True (itrue@swin.edu.au)
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

from ast import literal_eval
import logging
import numpy as np
import os
from scipy.interpolate.fitpack2 import InterpolatedUnivariateSpline
import sys
from threading import Lock
import traceback


TEACUP_DIR = os.environ['TEACUP_DIR']
CWD = os.environ['TEACUP_CWD']
EXP_COMPLETED = os.path.join(CWD, os.environ['TEACUP_EXP_LIST'])
EXP_DIR = os.path.join(CWD, os.environ['TEACUP_EXP_DIR'])
OUT_DIR = os.environ['TEACUP_OUT_DIR']

os.chdir(CWD)
sys.path.append(TEACUP_DIR)
from analysecmpexp import get_extract_function, read_experiment_ids
from analyse import _extract_tcp_stat

def init_log():
    """
    Initialises a file-based logger
    """
    log = logging.getLogger('teaplot')
    handler = logging.FileHandler(os.path.join(CWD, 'teaplot.log'))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(formatter)
    log.addHandler(handler)
    return log

LOG = init_log()


# Change me to logging.WARNING to hide info messages
LOG.setLevel(logging.INFO)
#LOG.setLevel(logging.WARNING)

def cumulative_window(data, window_size=1, skip_factor=0.1):
    """
    Calculates a moving window sum over the provided data, with a window size measured in seconds.
    Functions by iterating through the data according to skip_factor*window_size, and summing all
    data points within the window_size of the current point.
    """

    time_skip = window_size * skip_factor

    # Hard to figure out how many are required without actually processing the data.
    # Therefore, allocate an empty array that is equal in size to the source data,
    # and keep track of how many points are added, then return the array up to that
    # index.
    result = np.empty(data.shape)
    index = 0
    result_index = 0
    data_length = len(data)
    LOG.info('Calculating cumulative window for %s data points \
             with window size %s, skip factor %s…', data_length, window_size, skip_factor)
    while index < data_length:
        # Window start time
        time = data[index][0]
        max_time = time + window_size
        points = []
        seek_index = index
        point = [0, 0]
        # Collect all future data points within the window
        while (seek_index + 1) < data_length and point[0] <= max_time:
            seek_index = seek_index + 1
            point = data[seek_index]
            points = points + [point, ]
        # Calculate sum of the value of all points found
        total = 0
        for point in points:
            total = total + point[1]
        # Normalise to per second
        total = total / window_size
        # Add resulting sum to result array, timestamp is centred in the window
        timestamp = time + window_size / 2

        result[result_index][0] = timestamp
        result[result_index][1] = total

        result_index = result_index + 1
        # Find next window index
        while index < data_length and data[index][0] <= (time + time_skip):
            index = index + 1
    LOG.info('Done. Calculated %s data points', result_index)
    return result[:result_index]

def calculate_throughput(data):
    """
    Moving window sum over packet sizes
    """
    # Sort array by time
    data = data[data[:, 0].argsort()]
    data = cumulative_window(data)
    # bytes to bits
    data[:, 1] = data[:, 1] * 8.0
    return data

def extract_goodput(test_id='',
                    source_filter='',
                    ts_correct='1',
                    replot_only='1',
                    ** kwargs):
    """
    Uses the changes in the ackseq metric to produce an application-layer bit rate
    """
    ex_function, kwargs = get_extract_function(metric='ackseq')
    return ex_function(test_id=test_id,
                       source_filter=source_filter,
                       ts_correct=ts_correct,
                       replot_only=replot_only,
                       out_dir=OUT_DIR,
                       ** kwargs)


def calculate_goodput(data):
    """
    Moving window sum over the bytes received column (2nd column) in the ACKSEQ data.
    ACKSEQ is cumulative bytes received, so calculate differences between ACKs.
    """
    # Sort array by time
    data = data[data[:, 0].argsort()]
    data[:, 1] = np.append(np.zeros(1), np.diff(data[:, 1]))
    data = cumulative_window(data)
    # bytes to bits
    data[:, 1] = data[:, 1] * 8.0
    return data

def extract_siftr(test_id='',
                  source_filter='',
                  ts_correct='1',
                  replot_only='1',
                  ** kwargs):
    """
    Utilise TEACUP's _extract_tcp_stat task to extract siftr metric data for FreeBSD clients
    """
    metric = kwargs['metric']
    siftr_index = METRIC_LIST[metric]['siftr']
    io_filter = METRIC_LIST[metric]['io_filter'] if 'io_filter' in METRIC_LIST[metric] else 'o'
    LOG.info('Extract siftr statistics for "%s" (column %s, io filter "%s")…',
             metric, siftr_index, io_filter)
    return _extract_tcp_stat(test_id=test_id,
                             source_filter=source_filter,
                             ts_correct=ts_correct,
                             replot_only=replot_only,
                             siftr_index=siftr_index,
                             out_dir=OUT_DIR,
                             io_filter=io_filter)

def extract_web10g(test_id='',
                   source_filter='',
                   ts_correct='1',
                   replot_only='1',
                   ** kwargs):
    """
    Utilise TEACUP's _extract_tcp_stat task to extract web10g metric data for Linux clients
    """
    metric = kwargs['metric']
    web10g_index = METRIC_LIST[metric]['web10g']
    LOG.info('Extract web10g statistics for "%s" (column %s)…', metric, web10g_index)
    return _extract_tcp_stat(test_id=test_id,
                             source_filter=source_filter,
                             ts_correct=ts_correct,
                             replot_only=replot_only,
                             out_dir=OUT_DIR,
                             web10g_index=web10g_index)


# METRIC_LIST is dictionary of metrics that are available to be plotted. The value of the dictionary
# corresponds to a function which is used to calculate the actual values from the raw data, if
# needed. Set the value to None if not required.

SIFTR_LIST = {
    'SIFTR ssthresh': {
        'calculate': None,
        'extract': extract_siftr,
        'siftr': '8',
        'io_filter': 'i'
    },
    'SIFTR bwcontrolledwin': {
        'calculate': None,
        'extract': extract_siftr,
        'siftr': '10'
    },
    'SIFTR sndwin': {
        'calculate': None,
        'extract': extract_siftr,
        'siftr': '11',
        'io_filter': 'o'
    },
    'SIFTR recvwin': {
        'calculate': None,
        'extract': extract_siftr,
        'siftr': '12',
        'io_filter': 'i'
    },
    'SIFTR sndwinscalfac': {
        'calculate': None,
        'extract': extract_siftr,
        'siftr':'13',
        'io_filter': 'o'
    },
    'SIFTR recvwinscalfac': {
        'calculate': None,
        'extract': extract_siftr,
        'siftr':'14',
        'io_filter': 'i'
    },
    'SIFTR tcpfsm': {
        'calculate': None,
        'extract': extract_siftr,
        'siftr': '15',
        'io_filter': 'io'
    },
    'SIFTR maxsegsize': {
        'calculate': None,
        'extract': extract_siftr,
        'siftr': '16',
        'io_filter': 'io'
    },
    'SIFTR tcpflags': {
        'calculate': None,
        'extract': extract_siftr,
        'siftr': '19',
        'io_filter': 'io'
    },
    'SIFTR rto': {
        'calculate': None,
        'extract': extract_siftr,
        'siftr': '20',
        'io_filter': 'o'
    },
    'SIFTR sndbufsize': {
        'calculate': None,
        'extract': extract_siftr,
        'siftr': '21',
        'io_filter':'o'
    },
    'SIFTR sndbuf': {
        'calculate': None,
        'extract': extract_siftr,
        'siftr': '22',
        'io_filter': 'o'
    },
    'SIFTR recvbufsize': {
        'calculate': None,
        'extract': extract_siftr,
        'siftr': '23',
        'io_filter':'i'
    },
    'SIFTR recvbuf': {
        'calculate': None,
        'extract': extract_siftr,
        'siftr': '24',
        'io_filter': 'i'
    },
    'SIFTR unackbytes': {
        'calculate': None,
        'extract': extract_siftr,
        'siftr': '25',
        'io_filter':'o'
    },
    'SIFTR reassemblyqueue': {
        'calculate': None,
        'extract': extract_siftr,
        'siftr': '26',
        'io_filter': 'io'
    },
}

WEB10G_LIST = {
    'Web10G Timestamp sec.usec': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '1'
    },
    'Web10G CID (internal flow ID)': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '2'
    },
    'Web10G Source IP': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '3'
    },
    'Web10G Source port': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '4'
    },
    'Web10G Destination IP': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '5'
    },
    'Web10G Destination port': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '6'
    },
    'Web10G SegsOut': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '7'
    },
    'Web10G DataSegsOut': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '8'
    },
    'Web10G DataOctetsOut': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '9'
    },
    'Web10G HCDataOctetsOut': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '10'
    },
    'Web10G SegsRetrans': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '11'
    },
    'Web10G OctetsRetrans': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '12'
    },
    'Web10G SegsIn': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '13'
    },
    'Web10G DataSegsIn': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '14'
    },
    'Web10G DataOctetsIn': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '15'
    },
    'Web10G HCDataOctetsIn': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '16'
    },
    'Web10G ElapsedSecs': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '17'
    },
    'Web10G ElapsedMicroSecs': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '18'
    },
    'Web10G StartTimeStamp': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '19'
    },
    'Web10G CurMSS': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '20'
    },
    'Web10G PipeSize': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '21'
    },
    'Web10G MaxPipeSize': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '22'
    },
    'Web10G SmoothedRTT': {

        'extract': extract_web10g,
        'calculate': None,
        'web10g': '23'
    },
    'Web10G CurRTO': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '24'
    },
    'Web10G CongSignals': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '25'
    },
    'Web10G CurCwnd': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '26'
    },
    'Web10G CurSsthresh': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '27'
    },
    'Web10G Timeouts': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '28'
    },
    'Web10G CurRwinSent': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '29'
    },
    'Web10G MaxRwinSent': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '30'
    },
    'Web10G ZeroRwinSent': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '31'
    },
    'Web10G CurRwinRcvd': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '32'
    },
    'Web10G MaxRwinRcvd': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '33'
    },
    'Web10G ZeroRwinRcvd': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '34'
    },
    'Web10G SndLimTransRwin': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '35'
    },
    'Web10G SndLimTransCwnd': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '36'
    },
    'Web10G SndLimTransSnd': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '37'
    },
    'Web10G SndLimTimeRwin': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '38'
    },
    'Web10G SndLimTimeCwnd': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '39'
    },
    'Web10G SndLimTimeSnd': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '40'
    },
    'Web10G RetranThresh': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '41'
    },
    'Web10G NonRecovDAEpisodes': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '42'
    },
    'Web10G SumOctetsReordered': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '43'
    },
    'Web10G NonRecovDA': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '44'
    },
    'Web10G SampleRTT': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '45'
    },
    'Web10G RTTVar': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '46'
    },
    'Web10G MaxRTT': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '47'
    },
    'Web10G MinRTT': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '48'
    },
    'Web10G SumRTT': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '49'
    },
    'Web10G HCSumRTT': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '50'
    },
    'Web10G CountRTT': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '51'
    },
    'Web10G MaxRTO': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '52'
    },
    'Web10G MinRTO': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '53'
    },
    'Web10G IpTtl': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '54'
    },
    'Web10G IpTosIn': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '55'
    },
    'Web10G IpTosOut': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '56'
    },
    'Web10G PreCongSumCwnd': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '57'
    },
    'Web10G PreCongSumRTT': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '58'
    },
    'Web10G PostCongSumRTT': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '59'
    },
    'Web10G PostCongCountRTT': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '60'
    },
    'Web10G ECNsignals': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '61'
    },
    'Web10G DupAckEpisodes': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '62'
    },
    'Web10G RcvRTT': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '63'
    },
    'Web10G DupAcksOut': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '64'
    },
    'Web10G CERcvd': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '65'
    },
    'Web10G ECESent': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '66'
    },
    'Web10G ActiveOpen': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '67'
    },
    'Web10G MSSSent': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '68'
    },
    'Web10G MSSRcvd': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '69'
    },
    'Web10G WinScaleSent': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '70'
    },
    'Web10G WinScaleRcvd': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '71'
    },
    'Web10G TimeStamps': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '72'
    },
    'Web10G ECN': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '73'
    },
    'Web10G WillSendSACK': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '74'
    },
    'Web10G WillUseSACK': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '75'
    },
    'Web10G State': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '76'
    },
    'Web10G Nagle': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '77'
    },
    'Web10G MaxSsCwnd': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '78'
    },
    'Web10G MaxCaCwnd': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '79'
    },
    'Web10G MaxSsthresh': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '80'
    },
    'Web10G MinSsthresh': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '81'
    },
    'Web10G InRecovery': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '82'
    },
    'Web10G DupAcksIn': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '83'
    },
    'Web10G SpuriousFrDetected': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '84'
    },
    'Web10G SpuriousRtoDetected': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '85'
    },
    'Web10G SoftErrors': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '86'
    },
    'Web10G SoftErrorReason': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '87'
    },
    'Web10G SlowStart': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '88'
    },
    'Web10G CongAvoid': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '89'
    },
    'Web10G OtherReductions': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '90'
    },
    'Web10G CongOverCount': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '91'
    },
    'Web10G FastRetran': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '92'
    },
    'Web10G SubsequentTimeouts': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '93'
    },
    'Web10G CurTimeoutCount': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '94'
    },
    'Web10G AbruptTimeouts': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '95'
    },
    'Web10G SACKsRcvd': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '96'
    },
    'Web10G SACKBlocksRcvd': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '97'
    },
    'Web10G SendStall': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '98'
    },
    'Web10G DSACKDups': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '99'
    },
    'Web10G MaxMSS': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '100'
    },
    'Web10G MinMSS': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '101'
    },
    'Web10G SndInitial': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '102'
    },
    'Web10G RecInitial': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '103'
    },
    'Web10G CurRetxQueue': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '104'
    },
    'Web10G MaxRetxQueue': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '105'
    },
    'Web10G CurReasmQueue': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '106'
    },
    'Web10G MaxReasmQueue': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '107'
    },
    'Web10G SndUna': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '108'
    },
    'Web10G SndNxt': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '109'
    },
    'Web10G SndMax': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '110'
    },
    'Web10G ThruOctetsAcked': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '111'
    },
    'Web10G HCThruOctetsAcked': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '112'
    },
    'Web10G RcvNxt': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '113'
    },
    'Web10G ThruOctetsReceived': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '114'
    },
    'Web10G HCThruOctetsReceived': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '115'
    },
    'Web10G CurAppWQueue': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '116'
    },
    'Web10G MaxAppWQueue': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '117'
    },
    'Web10G CurAppRQueue': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '118'
    },
    'Web10G MaxAppRQueue': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '119'
    },
    'Web10G LimCwnd': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '120'
    },
    'Web10G LimSsthresh': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '121'
    },
    'Web10G LimRwin': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '122'
    },
    'Web10G LimMSS': {
        'extract': extract_web10g,
        'calculate': None,
        'web10g': '123'
    },

}

METRIC_LIST = {
    'throughput': {
        'calculate': calculate_throughput,
        'extract': None
    },
    'spprtt':  {
        'calculate': None,
        'extract': None
    },
    'tcprtt':  {
        'calculate': None,
        'extract': None
    },
    'cwnd': {
        'calculate': None,
        'extract': None
    },
    'ackseq': {
        'calculate': None,
        'extract': None
    },
    'goodput': {
        'calculate': calculate_goodput,
        'extract': extract_goodput
    },

}

if os.environ['TEACUP_SIFTR'] == '1':
    METRIC_LIST.update(SIFTR_LIST);

if os.environ['TEACUP_WEB10G'] == '1':
    METRIC_LIST.update(WEB10G_LIST);

def get_experiments_from_teacup():
    """
    Returns the result of the read_experiment_ids function in TEACUP.
    Also captures the sys.exit() calls resulting from TEACUP errors
    """
    try:
        experiments = read_experiment_ids(EXP_COMPLETED)
    except SystemExit:
        return {'result': 'TEACUP Error (see log)'}
    return {'result': 'Success', 'experiments':  experiments}



def read_raw_file(filename):
    """
    Reads entries as CSV from filename and normalises the first
    column relative to the first entry
    """
    LOG.info('Reading "%s"…', filename)
    with open(filename, 'r') as raw_file:
        try:
            data = np.loadtxt(raw_file, delimiter=',')
        except ValueError:
            # Probably space separated
            data = np.loadtxt(raw_file, delimiter=' ')
    if data is not None and (len(data) > 0):
        LOG.info('File contains %s records', len(data))
        return data.copy()
    return None



def get_value_from_request(dictionary, key):
    """
    Returns the value corresponding to the key in the given dictionary.
    """
    try:
        if isinstance(dictionary[key], str) or isinstance(dictionary[key], list):
            return dictionary[key] if (len(dictionary[key]) > 0) else None
        else:
            return dictionary[key]
    except KeyError:
        return None

def get_data_summary(filename):
    """
    Returns the summary regarding the data inside the TEACUP file specified
    """
    LOG.info('Obtaining summary information for "' + filename + '"…')
    data = read_raw_file(filename)
    if data is None:
        return None
    col = data[:, 0]

    return {
        'size': data.shape[0],
        'duration': col[-1] - col[0],
        'start': col[0]
    }

def normalise_summary_start_times(out_files, metric, result,out_groups):
    """
    Normalise start times by iterating through and finding earliest
    """
    earliest = {}
    if len(result['data'][metric]) == 0:
        LOG.warning('No data found for "' + metric + '"')
        return result
    for flow, file in out_files.iteritems():
        if out_groups[file] not in earliest:
            earliest.update({out_groups[file]:0})
        try:
            entry = result['data'][metric][flow]
        except KeyError:
            LOG.warning('Error finding earliest time for "' + flow + '"')
        else:
            group = out_groups[file]
            if entry['start'] < earliest[group] or earliest[group] == 0:
                earliest[group] = entry['start']
            entry['group'] = group
    # Normalise times
    for flow, file in  out_files.iteritems():
        try:
            entry = result['data'][metric][flow]
        except KeyError:
            LOG.warning('Error normalising time for "' + flow + '"')
        else:
            entry['start'] = entry['start'] - earliest[out_groups[file]]

    return result

# Lock to stop multiple extract jobs from conflicting with each other
EXTRACT_LOCK = Lock()

def post_process_metric(metric, result, filename, flow):
    """
    Performs summary generation of a single metric
    """
    LOG.info('Working with "' + filename + '" for flow "' + flow + '".')
    summary = get_data_summary(filename)
    if summary is not None and summary['size'] > 10:
        result['data'][metric].update({flow: []})
        result['data'][metric][flow] = {
            'filename': filename,
            'size': summary['size'],
            'duration': summary['duration'],
            'start': summary['start']
        }
    else:
        LOG.warning('Error processing "' + flow + '"')

def process_metric(result,
                   metric,
                   source_filter,
                   exp_id_list):
    """
    Performs the extraction of a single metric pertaining to the given
    parameters
    """
    LOG.info('Extracting "' + metric + '"…')
    result['data'].update({metric: {}})
    # Use extract function from METRIC_LIST, or, if not present, use TEACUP's
    if 'extract' in METRIC_LIST[metric] \
        and METRIC_LIST[metric]['extract'] is not None:
        ex_function = METRIC_LIST[metric]['extract']
        kwargs = {'metric': metric}
    else:
        try:
            (ex_function, kwargs) = get_extract_function(metric=metric)
        except KeyError:
            result = {'result': '"' + metric + '" is not yet implemented.'}
            return True
    error = False;
    # Block thread while another extract task is running
    EXTRACT_LOCK.acquire()
    try:
        (_, out_files, out_groups) = \
            ex_function(test_id=exp_id_list,
                        out_dir=OUT_DIR,
                        source_filter=source_filter if source_filter is not None else '',
                        ts_correct='1',
                        replot_only='1',
                        ** kwargs)

    except Exception as exc:
        LOG.error('Something went wrong with TEACUP\'s extraction process: ' + repr(exc))
        LOG.info(traceback.format_exc())
        error = True
    else:
        LOG.info('Extraction produced %s files. Running post-processing…', len(out_files))
        for flow, filename in out_files.iteritems():
            post_process_metric(metric=metric,
                                result=result,
                                filename=filename,
                                flow=flow)
        result = normalise_summary_start_times(out_files, metric, result,out_groups)
        LOG.info('Finished extracting and post-processing "' + metric + '".')
    finally:
        EXTRACT_LOCK.release()
    return error

def get_metrics_from_request(request):
    """
    Extracts the data pertaining to the given metrics, exp_id, and source filter
    """
    request = literal_eval(request)
    metrics = get_value_from_request(request, 'metrics')
    source_filter = get_value_from_request(request, 'src_filter')
    exp_id = get_value_from_request(request, 'exp_id')

    if exp_id is None:
        return {'result': 'No data sources selected. Please select at least one \
                experiment ID and optionally provide a source \
                filter.'}
    elif metrics is None:
        return {'result': 'No metrics selected. Please select at least one metric to show.'}

    orig_dir = os.getcwd()
    os.chdir(EXP_DIR)
    result = {'result': 'Success', 'data': {}}
    fail = False
    LOG.info('Received request for experiment(s) "' + repr(exp_id) + '".')

    exp_id_list = ''
    for exp in exp_id:
        exp_id_list = exp_id_list + (';' if len(exp_id_list) > 0 else '') + exp
    try:
        for metric in metrics:
            fail = process_metric(result=result,
                                  metric=metric,
                                  source_filter=source_filter,
                                  exp_id_list=exp_id_list)
            if fail:
                break
    except SystemExit:
        # Intercept sys.exit call
        LOG.error('TEACUP process aborted')
        fail = True
    except Exception as exc:
        fail = True
        LOG.error('Something went wrong with data post-processing: ' + repr(exc))
        LOG.info(traceback.format_exc())
    finally:
        os.chdir(orig_dir)
    if fail:
        LOG.warning('Error occurred during extraction.')
        return {'result': 'Error performing analysis (TEACUP error)'}
    else:
        LOG.info('Successfully processed request.')
        return result

def read_metric(filename, metric):
    """
    Reads the raw data of a metric and performs any calculation required
    for that metric as specified in METRIC_LIST
    """
    data = read_raw_file(filename)
    if metric in METRIC_LIST and METRIC_LIST[metric]['calculate'] is not None:
        LOG.info('Running calculation function for "' + metric + '"…')
        calc_function = METRIC_LIST[metric]['calculate']
        data = calc_function(data)
    return data

def do_2d_density_with_time(axis, primary, secondary, scales):
    """
    Calculates a 2D density plot against time using an interpolated univariate
    spline.
    """
    primary_file = primary['file']
    primary_dataset = primary['dataset']
    primary_metric = primary['metric']
    secondary_file = secondary['file']
    secondary_dataset = secondary['dataset']
    secondary_metric = secondary['metric']
    x_scale = scales['x']
    y_scale = scales['y']
    z_scale = scales['z']

    if secondary_file is None or len(secondary_file) == 0:
        raise ValueError('Must provide 2 sources (for now)')
    if not (os.path.exists(primary_file) and os.path.exists(secondary_file)):
        raise ValueError('One or more files does not exist!')

    primary = read_metric(primary_file, primary_metric)[:, [0, primary_dataset]]
    secondary = read_metric(secondary_file, secondary_metric)[:, [0, secondary_dataset]]

    if len(secondary) > len(primary):
        temp = secondary
        secondary = primary
        primary = temp

    p_time = primary[:, 0]
    p_data = primary[:, 1]

    s_time = secondary[:, 0]
    s_data = secondary[:, 1]

    LOG.info('Interpolating…')
    interp_function = InterpolatedUnivariateSpline(x=s_time, y=s_data, ext='zeros')
    #f = interpolate.interp1d(x=s_time, y=s_data)
    znew = interp_function(p_time)
    LOG.info('Finished.')
    data = [p_time, p_data, znew]
    if axis == 'x':
        return np.dstack([data[0] * x_scale, data[1] * y_scale, data[2] * z_scale])
    elif axis == 'z':
        return np.dstack([data[1] * x_scale, data[2] * y_scale, data[0] * z_scale])
    else:
        raise ValueError('Invalid axis')

def do_1d_time_series(axis, y_file, y_dataset, y_metric, scales):
    """
    Calculates the 2D graph values for the given metric
    """
    x_scale = scales['x']
    y_scale = scales['y']
    z_scale = scales['z']
    data = read_metric(y_file, y_metric)[:, [0, y_dataset]]
    if data is None:
        raise ValueError('Empty dataset')
    if axis == 'x':
        return np.dstack([data[:, 0] * x_scale, data[:, 1] * y_scale, np.zeros(data.shape[0])])
    elif axis == 'z':
        return np.dstack([np.zeros(data.shape[0]), data[:, 1] * y_scale, data[:, 0] * z_scale])
    else:
        raise ValueError('Invalid axis')

def process_plot(x, y, z):
    """
    Performs the appropriate calculations for the requested plot
    """
    scales = {'x': x['scale'], 'y': y['scale'], 'z': z['scale']}
    if x['metric'] == 'TIME' and z['metric'] == 'NOTHING':
        # 1D time series with time on X axis
        return do_1d_time_series(axis='x',
                                 y_file=y['file'],
                                 y_dataset=y['dataset'],
                                 y_metric=y['metric'],
                                 scales=scales)
    elif z['metric'] == 'TIME' and x['metric'] == 'NOTHING':
        # 1D time series with time on Z axis
        return do_1d_time_series(axis='z',
                                 y_file=y['file'],
                                 y_dataset=y['dataset'],
                                 y_metric=y['metric'],
                                 scales=scales)
    elif x['metric'] == 'TIME' and z['metric'] != 'TIME':
        # 2D Density with time on xaxis
        return do_2d_density_with_time(axis='x',
                                       primary=y,
                                       secondary=z,
                                       scales=scales)
    elif x['metric'] != 'TIME' and z['metric'] == 'TIME':
        # 2D Density with time on z axis
        return do_2d_density_with_time(axis='z',
                                       primary=x,
                                       secondary=y,
                                       scales=scales)
    elif x['metric'] != 'TIME' and z['metric'] != 'TIME':
        # 3D Density
        raise ValueError('3D scatter plots not yet implemented')
    else:
        # Something else - error
        raise ValueError('Not a valid metric combination')

def parse_info_from_map_entry(map_entry):
    """
    Pulls the request parameters from the map_entry with sane defaults and
    constructs dicts holding the information for each axis
    """
    x_file = map_entry['x']['file'] if 'file' in map_entry['x'] else ''
    y_file = map_entry['y']['file'] if 'file' in map_entry['y'] else ''
    z_file = map_entry['z']['file'] if 'file' in map_entry['z'] else ''

    x_metric = map_entry['x']['metric'] if 'metric' in map_entry['x'] else 'NOTHING'
    y_metric = map_entry['y']['metric'] if 'metric' in map_entry['y'] else 'NOTHING'
    z_metric = map_entry['z']['metric'] if 'metric' in map_entry['z'] else 'NOTHING'

    # Dataset currently unused in the web client
    x_dataset = (map_entry['x']['dataset'] if 'dataset' in map_entry['x'] else 0) + 1
    y_dataset = (map_entry['y']['dataset'] if 'dataset' in map_entry['y'] else 0) + 1
    z_dataset = (map_entry['z']['dataset'] if 'dataset' in map_entry['z'] else 0) + 1

    x_scale = float(map_entry['x']['scale']) if 'scale' in map_entry['x'] else 1.0
    y_scale = float(map_entry['y']['scale']) if 'scale' in map_entry['y'] else 1.0
    z_scale = float(map_entry['z']['scale']) if 'scale' in map_entry['z'] else 1.0

    x_info = {
        'file': x_file,
        'metric': x_metric,
        'dataset': x_dataset,
        'scale': x_scale,
    }
    y_info = {
        'file': y_file,
        'metric': y_metric,
        'dataset': y_dataset,
        'scale': y_scale,
        'group' :  int(map_entry['y']['group'] if 'group' in map_entry['y'] else 0)
    }
    z_info = {
        'file': z_file,
        'metric': z_metric,
        'dataset': z_dataset,
        'scale': z_scale,
    }

    return (x_info, y_info, z_info)

def process_map_request(map_entry):
    """
    Processes the map requests sent by the client. These map requests are used to
    calculate the values to be plotted on the graph shown on the client's screen.
    Graph co-ordinates are always 3D (x,y,z)
    """
    x_info, y_info, z_info = parse_info_from_map_entry(map_entry)

    try:
        plot = process_plot(x=x_info, y=y_info, z=z_info)
    except ValueError as exc:
        LOG.error('Something went wrong with processing map request: %s', repr(exc))
        LOG.info(traceback.format_exc())
        result = 'Error: ' + repr(exc)
    else:
        result = 'Success'
    return {
        'result':result,
        'map': map_entry['map'],
        'plot': plot,
        'metrics': {
            'x': x_info['metric'],
            'y': y_info['metric'],
            'z': z_info['metric']
            },
        'group' : y_info['group']
        }

def make_graph(request):
    """
    Begins the process of parsing the request to calculate the points for the
    graph to plot on the client's screen. Iterates through each request in the
    request array.
    """
    orig_dir = os.getcwd()
    os.chdir(EXP_DIR)
    return_array = []
    result = 'Success'
    try:
        request = literal_eval(request)
        for map_entry in request:
            return_array = return_array + [process_map_request(map_entry),]
    except Exception as exc:
        LOG.error('Error evaluating graph data points: ' + repr(exc))
        LOG.info(traceback.format_exc())
        result = repr(exc)
    else:
        # Normalise times according to earliest time
        earliest = {}
        # Find earliest
        for data_set in return_array:
            metric = data_set['metrics']['y']
            if metric not in earliest:
                earliest.update({metric:{}})
            group = data_set['group']
            if group not in earliest[metric]:
                earliest[metric].update({group:0.0})
            minimum = np.amin(data_set['plot'][0][:, 0])
            if minimum < earliest[metric][group] or earliest[metric][group] == 0:
                earliest[metric][group] = minimum
        # Normalise times
        for data_set in return_array:
            metric = data_set['metrics']['y']
            group = data_set['group']
            plot = data_set['plot'][0]
            col = plot[:, 0]
            plot[:, 0] = col - np.full(fill_value=earliest[metric][group], shape=col.shape)
            data_set['plot'] = [plot.tolist(),]
    finally:
        os.chdir(orig_dir)

    return {'result': result, 'data': return_array}


def load_default():
    """
    Returns the values specified when the fabric command was run as defaults for the
    web client.
    """
    return {
        'source_filter': os.environ['TEACUP_DEFAULT_SOURCE_FILTER'],
        'test_id': [f for f in os.environ['TEACUP_DEFAULT_TEST_ID'].split(';') if len(f) > 0],
        'metric': [f for f in os.environ['TEACUP_DEFAULT_METRIC'].split(';') if len(f) > 0],
        'lnames': [f for f in os.environ['TEACUP_DEFAULT_LNAMES'].split(';') if len(f) > 0],
        'graph_names': [f for f in os.environ['TEACUP_DEFAULT_GRAPH_NAMES'].split(';') if len(f) > 0],
        'graph_count': os.environ['TEACUP_DEFAULT_GRAPH_COUNT'],
        'stime':  float(os.environ['TEACUP_STIME']),
        'etime':  float(os.environ['TEACUP_ETIME'])
    }