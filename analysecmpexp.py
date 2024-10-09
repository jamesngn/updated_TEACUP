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
## @package analysecmpexp
# Analyse experiment data -- functions for comparing metrics across experiments
#
# $Id: analysecmpexp.py,v 1920bf13a9bf 2018/02/07 09:03:39 garmitage $

import os
import errno
import time
import datetime
import re
from fabric.api import task, warn, put, puts, get, local, run, execute, \
    settings, abort, hosts, env, runs_once, parallel, hide

import config
from internalutil import mkdir_p, valid_dir
from clockoffset import DATA_CORRECTED_FILE_EXT
from filefinder import get_testid_file_list
from sourcefilter import SourceFilter
from analyseutil import merge_data_files
from analyse import _extract_rtt, _extract_cwnd, _extract_tcp_rtt, \
    _extract_dash_goodput, _extract_tcp_stat, _extract_incast, \
    _extract_pktsizes, _extract_incast_iqtimes, _extract_incast_restimes, \
    _extract_ackseq
from plot import plot_cmpexp, plot_2d_density, sort_by_flowkeys


###############################################################################
# Helper functions
###############################################################################

## Read experiment IDs from file
#  @param exp_list List of all test IDs (allows to filter out certain experiments,
#                  i.e. specific value comnbinations)
#  @return List of experiment IDs
def read_experiment_ids(exp_list):
    # read test ids
    try:
        with open(exp_list) as f:
            # read lines without newlines
            experiments = f.read().splitlines()
    except IOError:
        abort('Cannot open file %s' % exp_list)

    if len(experiments) < 1:
        abort('No experiment IDs specified')

    # strip off right white space
    experiments = [e.rstrip() for e in experiments]

    return experiments


## Get path from first experiment in list
#  @param experiments List of experiment ids
#  @return Path name
def get_first_experiment_path(experiments):
    # get path based on first experiment id 
    dir_name = ''
    files = get_testid_file_list('', experiments[0],
                                 '', 'LC_ALL=C sort')
    if len(files) > 0:
        dir_name = os.path.dirname(files[0])
    else:
        abort('Cannot find experiment %s\n'
              'Remove outdated teacup_dir_cache.txt if files were moved.' % experiments[0])

    return dir_name


## Build match string to match test IDs based on specified variables, and a second
## string to extract the test id prefix. does not require access to the config, 
## instead it tries to get the sames from the file name and some specified prefix
#  @param test_id_prefix Regular expression
#  @param test_id Test ID of one experiment
#  @param variables Semicolon-separated list of <var>=<value> where <value> means
#                   we only want experiments where <var> had the specific value
#  @return match string to match test IDs, match string to extract test ID prefix
def build_match_strings(test_id='', variables='',
                        #test_id_prefix='[0-9]{8}\-[0-9]{6}_experiment_'):
                        test_id_prefix='exp_[0-9]{8}\-[0-9]{6}_'):

    match_str = ''
    var_dict = {}

    if variables != '':
        for var in variables.split(';'):
            name, val = var.split('=')
            var_dict[name] = val

    res = re.search(test_id_prefix, test_id)
    if res == None:
        abort('Cannot find test ID prefix in test ID %s' % test_id)

    # cut off the test_id_prefix part
    test_id = test_id[res.end():]
    # strip leading underscore (if any)
    if test_id[0] == '_':
        test_id = test_id[1:]

    # now we have a number of parameter names and values separated by '_'
    # split on '_' and then all the even elements are the names
    param_short_names = test_id.split('_')[::2]

    for name in param_short_names:
        val = var_dict.get(name, '')
        if val == '':
            # we specify only fixed so this is a wildcard then
            match_str += '(' + name + '_.*)' + '_'
        else:
            match_str += '(' + name + '_' + val + ')' + '_'

    match_str = match_str[:-1]  # chomp of last underscore
    match_str2 = '(.*)_' + match_str # test id prefix is before match_str
    match_str = test_id_prefix + match_str # add test id prefix

    #print(match_str)
    #print(match_str2)

    return (match_str, match_str2)


## Filter out experiments based on the variables and also return 
## test id prefix and list of labels to plot underneath x-axis
#  @param experiments Experiment list
#  @param match_str Match string to match experiment
#  @param match_str2 Match string for test ID prefix extraction
#  @return List of filtered experiments, test ID prefix, x-axis labels
def filter_experiments(experiments, match_str, match_str2):
    fil_experiments = []
    test_id_pfx = ''
    xlabs = []

    for experiment in experiments:
        # print(experiment)
        res = re.search(match_str, experiment)
        if res:
            fil_experiments.append(experiment)
            xlabs.append('\n'.join(map(str, res.groups())))
            if test_id_pfx == '':
                res = re.search(match_str2, experiment)
                if res:
                    test_id_pfx = res.group(1)

    xlabs = [x.replace('_', ' ') for x in xlabs]

    # print(fil_experiments)
    # print(xlabs)

    return (fil_experiments, test_id_pfx, xlabs)


## Get plot parameters based on metric
#  @param metric Metric name
#  @param smoothed If '1' plot smoothed RTT, if '0' plot unsmoothed RTT
#  @param ts_correct If '1' use file with corrected timestamps, if '0' use uncorrected file
#  @param stat_index See analyse_tcp_stat 
#  @param dupacks See analyse_ackseq
#  @param cum_ackseq See analyse_ackseq
#  @param slowest_only See analyse_incast
#  @return File extension, y-axis label, index of metric in file, scaler, separator,
#          aggregation flag, difference flag
def get_metric_params(metric='', smoothed='0', ts_correct='1', stat_index='0', dupacks='0',
                     cum_ackseq='1', slowest_only='0'):

    diff = '0'
    if metric == 'throughput':
        ext = '.psiz'
        ylab = 'Throughput (kbps)'
        yindex = 2
        yscaler = 0.008
        sep = ' '
        aggr = '1'
    elif metric == 'spprtt':
        ext = '.rtts'
        ylab = 'SPP RTT (ms)'
        yindex = 2
        yscaler = 1000.0
        sep = ' '
        aggr = '0'
    elif metric == 'tcprtt':
        ext = '.tcp_rtt'
        ylab = 'TCP RTT (ms)'
        if smoothed == '1':
            yindex = 2
        else:
            yindex = 3
        yscaler = 1.0
        sep = ','
        aggr = '0'
    elif metric == 'cwnd':
        ext = '.cwnd'
        ylab = 'CWND'
        yindex = 2
        yscaler = 1.0
        sep = ','
        aggr = '0'
    elif metric == 'tcpstat':
        ext = '.tcpstat_' + stat_index
        ylab = 'TCP statistic ' + stat_index
        yindex = 2
        yscaler = 1.0
        sep = ','
        aggr = '0'
    elif metric == 'ackseq':
        ext = '.acks'
        if dupacks == '0' :
            if cum_ackseq == '1':
                ylab = 'Bytes acknowledged (Kbytes)'
            else:
                ylab = 'Bytes acknowledged (Kbytes/s)'
            yindex = 2
            yscaler =  (1.0 / 1024.0)
        else :
            if cum_ackseq == '1':
                ylab = 'Cummulative dupACKs'
            else:
                ylab = 'dupACKs per second'
            yindex = 3
            yscaler = 1.0
        sep = ' '
        if cum_ackseq == '1':
            aggr = '0'
            diff = '0'
        else:
            aggr = '1'
            diff = '1'
    elif metric == 'restime':
        # XXX cannot select the tcpdump times here at the moment
        ext = '.rtimes'
        ylab = 'Response time (s)'
        yindex = 3
        yscaler = 1.0
        sep = ' '
        aggr = '0'
        if slowest_only != '0':
            ext = 'rtimes.slowest'
            yindex = 2
    elif metric == 'iqtime':
        ext = '.iqtimes'
        ylab = 'Inter-query time (ms)'
        yindex = 5 # time gap to previous request
        yscaler = 1000.0
        sep = ' '
        aggr = '0'
    #elif metric == 'pktloss':
        #ext = '.loss'
        #ylab = 'Packet loss (%)'
        #yindex = 2
        #yscaler = 1.0
        #sep = ' '
        #aggr = '2'
    # elif add more
    else:
        return None

    if ts_correct == '1' and metric != 'restime':
        ext += DATA_CORRECTED_FILE_EXT

    if metric == 'spprtt' or metric == 'ackseq':
        # select the all bursts file
        ext += '.0'
    elif metric == 'iqtime':
        # select the all responders file
        ext += '.all'

    return (ext, ylab, yindex, yscaler, sep, aggr, diff)


## Get extract function based on metric
#  @param metric Metric name
#  @param link_len See analyse_throughput
#  @param stat_index See analyse_tcp_stat
#  @param slowest_only See analyse_incast
#  @param sburst Start plotting with burst N (bursts are numbered from 1)
#  @param eburst End plotting with burst N (bursts are numbered from 1)
#  @param query_host See analyse_incast_iqtimes
#  @return extract function, keyword arguments to pass to extract function 
def get_extract_function(metric='', link_len='0', stat_index='0', slowest_only='0',
                         sburst='1', eburst='0', query_host=''):

    # define a map of metrics and corresponding extract functions
    extract_functions = {
        'throughput' : _extract_pktsizes,
        'spprtt'     : _extract_rtt,
        'tcprtt'     : _extract_tcp_rtt,
        'cwnd'       : _extract_cwnd,
        'tcpstat'    : _extract_tcp_stat,
        'ackseq'     : _extract_ackseq,
        'restime'    : _extract_incast,
        'iqtime'     : _extract_incast_iqtimes,
        #'pktloss'    : _extract_pktloss,
    }

    # additonal arguments for extract functions
    extract_kwargs = {
        'throughput' : { 'link_len' : link_len },
        'spprtt'     : { },
        'tcprtt'     : { },
        'cwnd'       : { },
        'tcpstat'    : { 'siftr_index'  : stat_index,
                         'web10g_index' : stat_index,
                         'ttprobe_index': stat_index },
        'ackseq'     : { 'burst_sep'    : 0.0,
                         'sburst'       : sburst,
                         'eburst'       : eburst },
        'restime'    : { 'sburst'       : sburst,
                         'eburst'       : eburst,
                         'slowest_only' : slowest_only },
        'iqtime'     : { 'cumulative'   : '0',
                         'by_responder' : '0',
                         'query_host'   : query_host },
        #'pktloss'    : { },
    }

    return (extract_functions[metric], extract_kwargs[metric])


####################################################################################
# Analyse functions
####################################################################################


## Function that plots mean, median, boxplot of throughput, RTT and other metrics 
## for different parameter combinations
## XXX currently can't reorder the experiment parameters, order is the one given by
##     config.py (and in the file names)
#  @param exp_list List of all test IDs (allows to filter out certain experiments,
#                  i.e. specific value comnbinations)
#  @param res_dir Directory with result files from analyse_all
#  @param out_dir Output directory for result files
#  @param source_filter Filter on specific sources
#                       (number of filters must be smaller equal to 12)
#  @param min_values Ignore flows with less output values / packets
#  @param omit_const '0' don't omit anything,
#                    '1' omit any series that are 100% constant
#                        (e.g. because there was no data flow)
#  @param metric Metric can be 'throughput', 'spprtt' (spp rtt), 'tcprtt' (unsmoothed tcp rtt), 
#                'cwnd', 'tcpstat', with 'tcpstat' must specify siftr_index or web10g_index 
#                'restime', 'ackseq', 'iqtime'
#  @param ptype Plot type: 'mean', 'median', 'box' (boxplot)
#  @param variables Semicolon-separated list of <var>=<value> where <value> means
#                   we only want experiments where <var> had the specific value
#  @param out_name Name prefix for resulting pdf file
#  @param ymin Minimum value on y-axis
#  @param ymax Maximum value on y-axis
#  @param lnames Semicolon-separated list of legend names
#  @param group_by_prefix Group by prefix instead of group by traffic flow
#  @param omit_const_xlab_vars '0' show all variables in the x-axis labels,
#                              '1' omit constant variables in the x-axis labels
#  @param pdf_dir Output directory for pdf files (graphs), if not specified it
#                 is the same as out_dir
#  @param stime Start time of time window to analyse
#               (by default 0.0 = start of experiment)
#  @param etime End time of time window to analyse (by default 0.0 = end of
#               experiment)
#  @param ts_correct '0' use timestamps as they are (default)
#                    '1' correct timestamps based on clock offsets estimated
#                        from broadcast pings
#  @param smoothed '0' plot non-smooth RTT (enhanced RTT in case of FreeBSD),
#                  '1' plot smoothed RTT estimates (non enhanced RTT in case of FreeBSD)
#  @param link_len '0' throughput based on IP length (default),
#                  '1' throughput based on link-layer length
#  @param replot_only '0' extract data
#                     '1' don't extract data again, just redo the plot
#  @param plot_params Parameters passed to plot function via environment variables
#  @param plot_script Specify the script used for plotting, must specify full path
#                     (default is config.TPCONF_script_path/plot_cmp_experiments.R)
#  @param stat_index Integer number of the column in siftr/web10g log files
#                    need when metric is 'tcpstat'
#  @param dupacks '0' to plot ACKed bytes vs time
#                 '1' to plot dupACKs vs time
#  @param cum_ackseq '0' average per time window data 
#                    '1' cumulative counter data
#  @param merge_data '0' by default don't merge data
#                    '1' merge data for each experiment, i.e. merge statistics of all flows
#                    (merging does not make sense in every case, user need to decide)
#  @param sburst Start plotting with burst N (bursts are numbered from 1)
#  @param eburst End plotting with burst N (bursts are numbered from 1)
#  @param test_id_prefix Prefix used for the experiments (used to get variables 
#                        names from the file names
#  @param slowest_only '0' plot all response times (metric restime)
#                      '1' plot only the slowest response times for each burst
#                      '2' plot time between first request and last response finished
#  @param res_time_mode '0' normal plot (default)
#                       '1' plot nominal response times in addition box/median/mean of
#                           observed response times
#                       '2' plot ratio of median/mean (as per ptype) and nominal response
#                           time
#  @param query_host Name of querier (only for iqtime metric)
@task
def analyse_cmpexp(exp_list='experiments_completed.txt', res_dir='', out_dir='',
                   source_filter='', min_values='3', omit_const='0', metric='throughput',
                   ptype='box', variables='', out_name='', ymin='0', ymax='0', lnames='',
                   group_by_prefix='0', omit_const_xlab_vars='0', replot_only='0',
                   pdf_dir='', stime='0.0', etime='0.0', ts_correct='1', smoothed='1',
                   link_len='0', plot_params='', plot_script='', stat_index='',
                   dupacks='0', cum_ackseq='1', merge_data='0', sburst='1',
                   #eburst='0', test_id_prefix='[0-9]{8}\-[0-9]{6}_experiment_',
                   eburst='0', test_id_prefix='exp_[0-9]{8}\-[0-9]{6}_',
                   slowest_only='0', res_time_mode='0', query_host=''):
    "Compare metrics for different experiments"

    if ptype != 'box' and ptype != 'mean' and ptype != 'median':
        abort('ptype must be either box, mean or median')

    check = get_metric_params(metric, smoothed, ts_correct)
    if check == None:
        abort('Unknown metric %s specified' % metric)

    if source_filter == '':
        abort('Must specify at least one source filter')

    if len(source_filter.split(';')) > 12:
        abort('Cannot have more than 12 filters')

    # prevent wrong use of res_time_mode
    if metric != 'restime' and res_time_mode != '0':
        res_time_mode = '0'
    if ptype == 'box' and res_time_mode == '2':
        res_time_mode = '0'

    # XXX more param checking

    # Initialise source filter data structure
    sfil = SourceFilter(source_filter)

    # read test ids
    experiments = read_experiment_ids(exp_list)

    # get path based on first experiment id 
    dir_name = get_first_experiment_path(experiments)

    # if we haven' got the extracted data run extract method(s) first
    if res_dir == '':
        for experiment in experiments:

            (ex_function, kwargs) = get_extract_function(metric, link_len,
                                    stat_index, sburst=sburst, eburst=eburst,
                                    slowest_only=slowest_only, query_host=query_host)

            (dummy, out_files, out_groups) = ex_function(
                test_id=experiment, out_dir=out_dir,
                source_filter=source_filter,
                replot_only=replot_only,
                ts_correct=ts_correct,
                **kwargs)

        if out_dir == '' or out_dir[0] != '/':
            res_dir = dir_name + '/' + out_dir
        else:
            res_dir = out_dir
    else:
        if res_dir[0] != '/':
            res_dir = dir_name + '/' + res_dir

    # make sure we have trailing slash
    res_dir = valid_dir(res_dir)

    if pdf_dir == '':
        pdf_dir = res_dir
    else:
        if pdf_dir[0] != '/':
            pdf_dir = dir_name + '/' + pdf_dir
        pdf_dir = valid_dir(pdf_dir)
        # if pdf_dir specified create if it doesn't exist
        mkdir_p(pdf_dir)

    #
    # build match string from variables
    #

    (match_str, match_str2) = build_match_strings(experiments[0], variables,
                                  test_id_prefix)

    #
    # filter out the experiments to plot, generate x-axis labels, get test id prefix
    #

    (fil_experiments,
     test_id_pfx,
     xlabs) = filter_experiments(experiments, match_str, match_str2)

    #
    # get out data files based on filtered experiment list and source_filter
    #

    (ext,
     ylab,
     yindex,
     yscaler,
     sep,
     aggr,
     diff) = get_metric_params(metric, smoothed, ts_correct, stat_index, dupacks,
                              cum_ackseq, slowest_only)

    if res_time_mode == '1':
        plot_params += ' NOMINAL_RES_TIME="1"'
    if res_time_mode == '2':
        if ptype == 'median':
            ylab = 'Median resp time / nominal resp time'
        elif ptype == 'mean':
            ylab = 'Mean resp time / nominal resp time'
        plot_params += ' RATIO_RES_TIME="1"'

    leg_names = source_filter.split(';')

    # if we merge responders make sure we only use the merged files
    if merge_data == '1':
        # set label to indicate merged data
        leg_names = ['Merged data']
        # reset source filter so we match the merged file
        sfil.clear()
        source_filter = 'S_0.0.0.0_0'
        sfil = SourceFilter(source_filter)

    file_names = []
    for experiment in fil_experiments:
        out_files = {}
        _ext = ext

        files = get_testid_file_list('', experiment,
                                      '%s' % _ext,
                                      'LC_ALL=C sort', res_dir)
        if merge_data == '1':
            # change extension
            _ext += '.all'
            files = merge_data_files(files)

        #print(files)
        match_str = '.*_([0-9\.]*_[0-9]*_[0-9\.]*_[0-9]*)[0-9a-z_.]*' + _ext
        for f in files:
            # print(f)
            res = re.search(match_str, f)
            #print(res.group(1))
            if res and sfil.is_in(res.group(1)):
                # only add file if enough data points
                rows = int(
                    local('wc -l %s | awk \'{ print $1 }\'' %
                          f, capture=True))
                if rows > int(min_values):
                    out_files[res.group(1)] = f

        #print(out_files)
        #print(leg_names)
        if len(out_files) < len(leg_names):
            abort(
                'No data files for some of the source filters for experiment %s' %
                experiment)

        sorted_files = sort_by_flowkeys(out_files, source_filter)

        for name, file_name in sorted_files:
            file_names.append(file_name)

    if group_by_prefix == '1':
        # group by test prefix (and flow)

        # first, get all test id prefixes
        test_id_pfxs = {}
        for experiment in fil_experiments:
            res = re.search(match_str2, experiment)
            if res:
                test_id_pfxs[res.group(1)] = 1

        # second, sort files so that same parameter combinations for different
        # prefixes are together
        # if we have multiple prefixes, create legend entry for each
        # prefix+flow combination
        _file_names = [''] * len(file_names)
        _leg_names = []
        pfx_cnt = len(test_id_pfxs)
        i = 0
        j = -1
        last_pfx = ''
        for name in file_names:
            for p in test_id_pfxs:
                if name.find(p) > -1:
                    curr_pfx = p
                    break

            if curr_pfx != last_pfx:
                i = 0
                j += 1
                for l in leg_names:
                    _leg_names.append(curr_pfx + '-' + l)

            _file_names[i * pfx_cnt + j] = name

            i += 1
            last_pfx = curr_pfx

        file_names = _file_names
        leg_names = _leg_names

        # remove duplicates in the x-axis labels
        xlabs = list(set(xlabs))

    if lnames != '':
        lnames_arr = lnames.split(';')
        if len(lnames_arr) != len(leg_names):
            abort(
                'Number of legend names must be qual to the number of source filters')
        leg_names = lnames_arr

    # filter out unchanged variables in the x labels (need at least 2 labels)
    if omit_const_xlab_vars == '1' and len(xlabs) > 1:

        xlabs_arrs = {}
        xlabs_changed = {}

        for i in range(len(xlabs)):
            xlabs_arrs[i] = xlabs[i].split('\n')

        for i in range(len(xlabs_arrs[0])):
            changed = False
            xlab_var = xlabs_arrs[0][i]
            for j in range(1, len(xlabs)):
                if xlabs_arrs[j][i] != xlab_var:
                    changed = True
                    break

            xlabs_changed[i] = changed

        for i in range(len(xlabs)):
            tmp = []
            for j in range(len(xlabs_arrs[i])):
                if xlabs_changed[j]:
                    tmp.append(xlabs_arrs[i][j].replace('_', ' ', 1))

            xlabs[i] = '\n'.join(tmp)

    print(leg_names)
    print(file_names)

    #
    # pass the data files and auxilary info to plot function
    #

    if out_name != '':
        oprefix = out_name + '_' + test_id_pfx + '_' + metric + '_' + ptype
    else:
        oprefix = test_id_pfx + '_' + metric + '_' + ptype
    title = oprefix

    plot_cmpexp(title, file_names, xlabs, ylab, yindex, yscaler, 'pdf', oprefix,
                pdf_dir, sep, aggr, diff, omit_const, ptype, ymin, ymax, leg_names,
                stime, etime, plot_params, plot_script)

    # done
    puts('\n[MAIN] COMPLETED analyse_cmpexp %s \n' % test_id_pfx)
                      

## Generate a 2d density plot with one paramter on x, one one y and the third
## one expressed as different colours of the "blobs" 
#  @param exp_list List of all test IDs (allows to filter out certain experiments,
#                  i.e. specific value comnbinations)
#  @param res_dir Directory with result files from analyse_all
#  @param out_dir Output directory for result files
#  @param source_filter Filter on specific sources. typically one source. if multiple sources
#                       are specified they are all aggregated. unlike analyse_cmpexp here we
#                       can't have per-source categories.
#  @param min_values Ignore flows with less output values / packets
#  @param xmetric Can be 'throughput', 'spprtt' (spp rtt), 'tcprtt' (unsmoothed tcp rtt), 'cwnd',
#                 'tcpstat', with 'tcpstat' must specify siftr_index or web10g_index 
#  @param ymetric: Can be 'throughput', 'spprtt' (spp rtt), 'tcprtt' (unsmoothed tcp rtt), 'cwnd',
#                  'tcpstat', with 'tcpstat' must specify siftr_index or web10g_index 
#  @param variables Semicolon-separated list of <var>=<value> where <value> means
#                   we only want experiments where <var> had the specific value
#  @param out_name File name prefix
#  @param xmin Minimum value on x-axis
#  @param xmax Maximum value on x-axis
#  @param ymin Minimum value on y-axis
#  @param ymax Maximum value on y-axis
#  @param lnames Semicolon-separated list of legend names
#  @param group_by Semicolon-separated list of experiment variables defining the different categories 
#                  the variables are the variable names used in the file names
#  @param pdf_dir Output directory for pdf files (graphs), if not specified it
#                 is the same as out_dir
#  @param stime Start time of time window to analyse
#               (by default 0.0 = start of experiment)
#  @param etime End time of time window to analyse (by default 0.0 = end of
#               experiment)
#  @param ts_correct '0' use timestamps as they are (default)
#                    '1' correct timestamps based on clock offsets estimated
#                        from broadcast pings
#  @param smoothed '0' plot non-smooth RTT (enhanced RTT in case of FreeBSD),
#                  '1' plot smoothed RTT estimates (non enhanced RTT in case of FreeBSD)
#  @param link_len '0' throughput based on IP length (default),
#                  '1' throughput based on link-layer length
#  @param replot_only '0' extract data
#                     '1' don't extract data again, just redo the plot
#  @param plot_params Parameters passed to plot function via environment variables
#  @param plot_script Specify the script used for plotting, must specify full path
#                     (default is config.TPCONF_script_path/plot_contour.R)
#  @param xstat_index Integer number of the column in siftr/web10g log files (for xmetric)
#  @param ystat_index Integer number of the column in siftr/web10g log files (for ymetric)
#  @param dupacks '0' to plot ACKed bytes vs time
#                 '1' to plot dupACKs vs time
#  @param cum_ackseq '0' average per time window data 
#                    '1' cumulative counter data
#  @param merge_data '0' by default don't merge data
#                    '1' merge data for each experiment 
#  @param sburst Start plotting with burst N (bursts are numbered from 1)
#  @param eburst End plotting with burst N (bursts are numbered from 1)
#  @param test_id_prefix Prefix used for the experiments (used to get variables 
#                        names from the file names
#  @param slowest_only '0' plot all response times (metric restime)
#                      '1' plot only the slowest response times for each burst
#  @param query_host Name of querier (only for iqtime metric)
# NOTE: that xmin, xmax, ymin and ymax don't just zoom, but govern the selection of data points
#       used for the density estimation. this is how ggplot2 works by default, although possibly
#       can be changed
@task
def analyse_2d_density(exp_list='experiments_completed.txt', res_dir='', out_dir='',
                   source_filter='', min_values='3', xmetric='throughput',
                   ymetric='tcprtt', variables='', out_name='', xmin='0', xmax='0',
                   ymin='0', ymax='0', lnames='', group_by='aqm', replot_only='0',
                   pdf_dir='', stime='0.0', etime='0.0', ts_correct='1', smoothed='1', 
                   link_len='0', plot_params='', plot_script='', xstat_index='', ystat_index='',
                   dupacks='0', cum_ackseq='1', merge_data='0',
                   #sburst='1', eburst='0', test_id_prefix='[0-9]{8}\-[0-9]{6}_experiment_',
                   sburst='1', eburst='0', test_id_prefix='exp_[0-9]{8}\-[0-9]{6}_',
                   slowest_only='0', query_host=''):
    "2d density / ellipse plot for different experiments"

    test_id_pfx = ''

    check = get_metric_params(xmetric, smoothed, ts_correct)
    if check == None:
        abort('Unknown metric %s specified with xmetric' % xmetric)
    check = get_metric_params(ymetric, smoothed, ts_correct)
    if check == None:
        abort('Unknown metric %s specified with ymetric' % ymetric)

    #if source_filter == '':
    #    abort('Must specify at least one source filter')

    if len(source_filter.split(';')) > 12:
        abort('Cannot have more than 12 filters')

    # XXX more param checking

    # make sure res_dir has valid form (out_dir is handled by extract methods)
    res_dir = valid_dir(res_dir)

    # Initialise source filter data structure
    sfil = SourceFilter(source_filter)

    # read test ids
    experiments = read_experiment_ids(exp_list)

    # get path based on first experiment id 
    dir_name = get_first_experiment_path(experiments)

    # if we haven' got the extracted data run extract method(s) first
    if res_dir == '':
        for experiment in experiments:

            (ex_function, kwargs) = get_extract_function(xmetric, link_len,
                                    xstat_index, sburst=sburst, eburst=eburst,
                                    slowest_only=slowest_only, query_host=query_host)

            (dummy, out_files, out_groups) = ex_function(
                test_id=experiment, out_dir=out_dir,
                source_filter=source_filter,
                replot_only=replot_only,
                ts_correct=ts_correct,
                **kwargs)

            (ex_function, kwargs) = get_extract_function(ymetric, link_len,
                                    ystat_index, sburst=sburst, eburst=eburst,
                                    slowest_only=slowest_only, query_host=query_host)

            (dummy, out_files, out_groups) = ex_function(
                test_id=experiment, out_dir=out_dir,
                source_filter=source_filter,
                replot_only=replot_only,
                ts_correct=ts_correct,
                **kwargs)

        if out_dir == '' or out_dir[0] != '/':
            res_dir = dir_name + '/' + out_dir
        else:
            res_dir = out_dir
                               
    else:
        if res_dir[0] != '/':
            res_dir = dir_name + '/' + res_dir

    # make sure we have trailing slash
    res_dir = valid_dir(res_dir)

    if pdf_dir == '':
        pdf_dir = res_dir
    else:
        if pdf_dir[0] != '/':
            pdf_dir = dir_name + '/' + pdf_dir
        pdf_dir = valid_dir(pdf_dir)
        # if pdf_dir specified create if it doesn't exist
        mkdir_p(pdf_dir)

    #
    # build match string from variables
    #

    (match_str, match_str2) = build_match_strings(experiments[0], variables,
                                  test_id_prefix)

    #
    # filter out the experiments to plot, generate x-axis labels, get test id prefix
    #

    (fil_experiments,
     test_id_pfx,
     dummy) = filter_experiments(experiments, match_str, match_str2)

    #
    # get groups based on group_by variable
    #

    group_idx = 1
    levels = {}
    groups = []
    leg_names = []
    _experiments = []
    for experiment in fil_experiments:
        level = ''
        add_exp = True
        for g in group_by.split(';'):
            p = experiment.find(g)
            if p > -1:
                s = experiment.find('_', p)
                s += 1
                e = experiment.find('_', s)
                level += g + ':' + experiment[s:e] + ' '
            else:
                add_exp = False
                break

        # remove the final space from the string
        level = level[:-1]

        if add_exp == True:
            _experiments.append(experiment)
            #print('level: ' + level)

            if level not in levels:
                levels[level] = group_idx
                group_idx += 1
                leg_names.append(level)

            if merge_data == '1':
                groups.append(levels[level])
            else:
                for i in range(len(source_filter.split(';'))):
                    groups.append(levels[level])

    fil_experiments = _experiments

    #
    # get metric parameters and list of data files
    #

    # get the metric parameter for both x and y
    x_axis_params = get_metric_params(xmetric, smoothed, ts_correct, xstat_index,
                                      dupacks, cum_ackseq, slowest_only)
    y_axis_params = get_metric_params(ymetric, smoothed, ts_correct, ystat_index,
                                      dupacks, cum_ackseq, slowest_only)

    x_ext = x_axis_params[0]
    y_ext = y_axis_params[0]

    # if we merge responders make sure we only use the merged files
    if merge_data == '1':
        # reset source filter so we match the merged file
        sfil.clear()
        sfil = SourceFilter('S_0.0.0.0_0')

    x_files = []
    y_files = []
    for experiment in fil_experiments:
        _x_files = []
        _y_files = []
        _x_ext = x_ext
        _y_ext = y_ext

        _files = get_testid_file_list('', experiment, _x_ext,
                                      'LC_ALL=C sort', res_dir)
        if merge_data == '1':
            _x_ext += '.all'
            _files = merge_data_files(_files)
        _x_files += _files

        _files = get_testid_file_list('', experiment, _y_ext,
                                      'LC_ALL=C sort', res_dir)
        if merge_data == '1':
            _y_ext += '.all'
            _files = merge_data_files(_files)
        _y_files += _files

        match_str = '.*_([0-9\.]*_[0-9]*_[0-9\.]*_[0-9]*)[0-9a-z_.]*' + _x_ext
        for f in _x_files:
            #print(f)
            res = re.search(match_str, f)
            #print(res.group(1))
            if res and sfil.is_in(res.group(1)):
                # only add file if enough data points
                rows = int(
                    local('wc -l %s | awk \'{ print $1 }\'' %
                          f, capture=True))
                if rows > int(min_values):
                    x_files.append(f)

        match_str = '.*_([0-9\.]*_[0-9]*_[0-9\.]*_[0-9]*)[0-9a-z_.]*' + _y_ext
        for f in _y_files:
            # print(f)
            res = re.search(match_str, f)
            if res and sfil.is_in(res.group(1)):
                # only add file if enough data points
                rows = int(
                    local('wc -l %s | awk \'{ print $1 }\'' %
                          f, capture=True))
                if rows > int(min_values):
                    y_files.append(f)

    yindexes = [str(x_axis_params[2]), str(y_axis_params[2])]
    yscalers = [str(x_axis_params[3]), str(y_axis_params[3])]
    aggr_flags = [x_axis_params[5], y_axis_params[5]]
    diff_flags = [x_axis_params[6], y_axis_params[6]]

    if lnames != '':
        lnames_arr = lnames.split(';')
        if len(lnames_arr) != len(leg_names):
            abort(
                'Number of legend names must be qual to the number of source filters')
        leg_names = lnames_arr

    print(x_files)
    print(y_files)
    print(groups)
    print(leg_names)

    #
    # pass the data files and auxilary info to plot function
    #

    if out_name != '':
        oprefix = out_name + '_' + test_id_pfx + '_' + xmetric + '_' + ymetric
    else:
        oprefix = test_id_pfx + '_' + xmetric + '_' + ymetric
    title = oprefix

    plot_2d_density(title, x_files, y_files, x_axis_params[1], y_axis_params[1], yindexes,
                    yscalers, 'pdf', oprefix, pdf_dir, x_axis_params[4], y_axis_params[4],
                    aggr_flags, diff_flags, xmin, xmax, ymin, ymax, stime, etime, 
                    groups, leg_names, plot_params, plot_script)

    # done
    puts('\n[MAIN] COMPLETED analyse_2d_density %s \n' % test_id_pfx)

