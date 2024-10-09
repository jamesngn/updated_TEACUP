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
## @package plot
# Plotting functions
#
# $Id: plot.py,v 60196b1683ea 2016/06/03 10:20:04 s $

import os
import errno
import time
import datetime
from fabric.api import task, warn, put, puts, get, local, run, execute, \
    settings, abort, hosts, env, runs_once, parallel, hide

import config
from internalutil import mkdir_p, valid_dir


#############################################################################
# Flow sorting functions
#############################################################################


## Compare low keys by flow source port (lowest source port first)
#  @param x Flow key of the form something_<src_ip>_<src_port>_<dst_ip>_<dst_port>
#  @param y Flow key of the form something_<src_ip>_<src_port>_<dst_ip>_<dst_port>
def _cmp_src_port(x, y):
    "Compare flow keys by flow source port (lowest source port first)"

    xflow = str(x)
    yflow = str(y)

    # split into src/dst IP/port
    xflow_arr = xflow.split('_')
    xflow_arr = xflow_arr[len(xflow_arr)-4:len(xflow_arr)]
    yflow_arr = yflow.split('_')
    yflow_arr = yflow_arr[len(yflow_arr)-4:len(yflow_arr)]

    # sort by numeric source port
    return cmp(int(xflow_arr[1]), int(yflow_arr[1]))


## Compare flow keys by flow dest port (lowest dest port first)
#  @param x Flow key of the form something_<src_ip>_<src_port>_<dst_ip>_<dst_port>
#  @param y Flow key of the form something_<src_ip>_<src_port>_<dst_ip>_<dst_port>
def _cmp_dst_port(x, y):
    "Compare flow keys by flow dest port (lowest dest port first)"

    xflow = str(x)
    yflow = str(y)

    # split into src/dst IP/port
    xflow_arr = xflow.split('_')
    xflow_arr = xflow_arr[len(xflow_arr)-4:len(xflow_arr)]
    yflow_arr = yflow.split('_')
    yflow_arr = yflow_arr[len(yflow_arr)-4:len(yflow_arr)]

    # sort by numeric dest port
    return cmp(int(xflow_arr[3]), int(yflow_arr[3]))


## Sort flow keys
## If all flows are bidirectional, sort so that server-client flows appear
## at left and client-server flows at right. Otherwise we always have 
## server-client flow followed by client-server flow (if the latter exists)
#  @param files Name to file name map
#  @param source_filter Source filter
#  @return List of sorted (flow_name, file_name) tuples
def sort_by_flowkeys(files={}, source_filter=''):
    "Sort flow names"

    sorted_files = []

    # convert source_filter string into list of source filters
    source_filter_list = []
    if source_filter != '':
        for fil in source_filter.split(';'):
            fil = fil.strip()
            source_filter_list.append(fil)

    #
    # 1. if filter string was specified graph in order of filters
    #

    if len(source_filter_list) > 0:
        for fil in source_filter_list:
            # strip of the (S|D) part a the start
            arr = fil.split('_')
            if arr[2] == '*':
                fil = arr[1] + '_'
            else:
                fil = arr[1] + '_' + arr[2]

            # find the file entries that matches the filter
            # then alphabetically sort file names for each filter
            # before adding to return array. note we sort the reversed
            # file names, so order is determined by flow tuple which is
            # at the end of the names ([::-1] reverses the string)
            # make sure we only add entry if it is not in the list yet
            tmp = []
            for name in files:
                if fil in name and (name, files[name]) not in tmp and \
                   (name, files[name]) not in sorted_files:
                    tmp.append((name, files[name]))

            sorted_files.extend(sorted(tmp, key=lambda x: x[1][::-1]))

        return sorted_files

    #
    # 2. otherwise do our best to make sure we have a sensible and consistent
    #    ordering based on server ports

    rev_files = {}

    # sort by dest port if and only if dest port is always lower than source
    # port
    cmp_fct = _cmp_dst_port
    for name in files:
        a = name.split('_')
        a = a[len(a)-4:len(a)]
        if int(a[1]) < int(a[3]):
            cmp_fct = _cmp_src_port
            break

    for name in sorted(files, cmp=cmp_fct):
        # print(name)
        if rev_files.get(name, '') == '':
            sorted_files.append((name, files[name]))
            a = name.split('_')
            a = a[len(a)-4:len(a)]
            rev_name = a[2] + '_' + a[3] + '_' + a[0] + '_' + a[1]
            if files.get(rev_name, '') != '':
                sorted_files.append((rev_name, files[rev_name]))
                rev_files[rev_name] = files[rev_name]

    if len(rev_files) == len(files) / 2:
        # order them so that server-client are left and client-server are right
        # in plot
        sorted_files_c2sleft = [('', '')] * len(files)

        idx = 0
        for name, file_name in sorted_files:
            if idx % 2 == 0:
                sorted_files_c2sleft[int(idx / 2)] = (name, file_name)
            else:
                sorted_files_c2sleft[
                    int((idx - 1) / 2) + len(files) / 2] = (name, file_name)
            idx += 1

        return sorted_files_c2sleft
    else:
        return sorted_files


## Sort flow keys by group ID
## If we have groups make sure that group order is the same for all flows
#  @param files (flow name, file name) tuples (sorted by sort_by_flowkeys)
#  @param groups File name to group number map
#  @return List of sorted (flow_name, file_name) tuples 
def sort_by_group_id(files={}, groups={}):

    sorted_files = [('', '')] * len(files)

    if max(groups.values()) == 1:
        return files
    else:
        num_groups = max(groups.values())
        cnt = 0
        for fil in files:
            start = int(cnt / num_groups)
            grp = groups[fil[1]]
            sorted_files[start * num_groups + grp - 1] = fil
            cnt += 1

        return sorted_files


## Sort flow keys by group ID
## like sort_by_group_id()  function, but the tuples in files are (string,list) instead
# of (string, string). Assumption: all files in one list belong to the same group! 
#  @param files (flow name, file name) tuples (sorted by sort_by_flowkeys)
#  @param groups File name to group number map
#  @return List of sorted (flow_name, file_name) tuples
def sort_by_group_id2(files={}, groups={}):

    sorted_files = [('', [])] * len(files)

    if max(groups.values()) == 1:
        return files
    else:
        num_groups = max(groups.values())
        cnt = 0
        for fil in files:
            start = int(cnt / num_groups)
            grp = groups[fil[1][0]]
            sorted_files[start * num_groups + grp - 1] = fil
            cnt += 1

        return sorted_files


#############################################################################
# Plot functions
#############################################################################

## Plot time series
#  @param title Title of plot at the top
#  @param files Dictionary with legend names (keys) and files with the data
#               to plot (values)
#  @param ylab Label for y-axis
#  @param yindex Index of the column in data file to plot
#  @param yscaler Scaler for y-values (data in file is multiplied with the scaler)
#  @param otype Type of output file
#  @param oprefix Output file name prefix
#  @param pdf_dir Output directory for graphs
#  @param sep Character that separates columns in data file
#  @param aggr Aggregation of data in time intervals
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
#  @param groups Map data files to groups (all files of same experiment must have
#                same group number)
#  @param sort_flowkey '1' sort by flow key (default)
#                      '0' don't sort by flow key
#  @param boxplot '0' normal time series
#                 '1' do boxplot for all values at one point in time
#  @param plot_params Parameters passed to plot function via environment variables
#  @param plot_script Specify the script used for plotting, must specify full path
#                     (default is config.TPCONF_script_path/plot_time_series.R)
#  @param source_filter Source filter
def plot_time_series(title='', files={}, ylab='', yindex=2, yscaler=1.0, otype='',
                     oprefix='', pdf_dir='', sep=' ', aggr='', omit_const='0',
                     ymin=0, ymax=0, lnames='',
                     stime='0.0', etime='0.0', groups={}, sort_flowkey='1',
                     boxplot='', plot_params='', plot_script='', source_filter=''):

    file_names = []
    leg_names = []
    _groups = []

    if sort_flowkey == '1':
        sorted_files = sort_by_flowkeys(files, source_filter)
    else:
        sorted_files = files.items()

    sorted_files = sort_by_group_id(sorted_files, groups)

    for name, file_name in sorted_files:
        leg_names.append(name)
        file_names.append(file_name)
        _groups.append(groups[file_name])

    if lnames != '':
        lname_arr = lnames.split(';')
        if boxplot == '0' and len(lname_arr) != len(leg_names):
            abort(
                'Number of legend names must be the same as the number of flows')
        else:
            leg_names = lname_arr

    # get the directory name here if not specified
    if pdf_dir == '':
        pdf_dir = os.path.dirname(file_names[0]) + '/'
    else:
        pdf_dir = valid_dir(pdf_dir)
        # if not absolute dir, make it relative to experiment_dir
        # assume experiment dir is part before first slash
        if pdf_dir[0] != '/':
            pdf_dir = file_names[0].split('/')[0] + '/' + pdf_dir
        # if pdf_dir specified create if it doesn't exist
        mkdir_p(pdf_dir)

    if plot_script == '':
        plot_script = 'R CMD BATCH --vanilla %s/plot_time_series.R' % \
                      config.TPCONF_script_path

    # interface between this code and the plot function are environment variables
    # the following variables are passed to plot function:
    # TC_TITLE:  character string that is plotted over the graph
    # TC_FNAMES: comma-separated list of file names (each file contains one date series,
    #         e.g. data for one flow). The format of each file is CSV-style, but the
    #         separator does not have to be a comma (can be set with SEP). The first
    #         column contains the timestamps. The second, third etc. columns contain
    #         data, but only one of these columns will be plotted (set with YINDEX). 
    # TC_LNAMES: comma-separated list of legend names. this list has the same length
    #         as FNAMES and each entry corresponds to data in file name with the
    #         same index in FNAMES
    # TC_YLAB:   y-axis label character string
    # TC_YINDEX: index of data column in file to plot on y-axis (file can have more than
    #         one data column)
    # TC_YSCALER: factor which is multiplied with each data value before plotting
    # TC_SEP:    column separator used in data file
    # TC_OTYPE:  type of output graph (default is 'pdf')
    # TC_OPREFIX: the prefix (first part) of the graph file name
    # TC_ODIR:   directory where output files, e.g. pdfs are placed
    # TC_AGGR:   set to '1' means data is aggregated over time intervals, more specifically
    #         the data is summed over the time intervals (used to determine throughput
    #         over time windows based on packet lengths)  
    #         set to '0' means plot data as is 
    # TC_OMIT_CONST: '0' don't omit anything,
    #             '1' omit any data series from plot that are 100% constant 
    # TC_YMIN:   minimum value on y-axis (for zooming in), default is 0 
    # TC_YMAX:   maximum value on y-axis (for zooming in), default is 0 meaning the 
    #         maximum value is determined from the data
    # TC_STIME:  start time on x-axis (for zooming in), default is 0.0 meaning the start 
    #         of an experiment
    # TC_ETIME:  end time on x-axis (for zooming in), default is 0.0 meaning the end of an
    #         experiment a determined from the data
    # TC_GROUPS: comma-separated list of group IDs (integer numbers). This list has  
    #         the same length as FNAMES. If data from different experiments is plotted,
    #         each experiment will be assigned a different number and these are passed
    #         via GROUPS. This allows the plotting function to determine which data
    #         series are (or are not) from the same experiment, so that results 
    #         from different experiments, that started at different times, can be 
    #         plotted in the same graph.
    # TC_BOXPL:  '0' plot each point on time axis
    #         '1' plot a boxplot over all data points from all data seres for each 
    #         distinct timestamp (instead of a point for each a data series) 

    #local('which R')
    local('TC_TITLE="%s" TC_FNAMES="%s" TC_LNAMES="%s" TC_YLAB="%s" TC_YINDEX="%d" TC_YSCALER="%f" '
          'TC_SEP="%s" TC_OTYPE="%s" TC_OPREFIX="%s" TC_ODIR="%s" TC_AGGR="%s" TC_OMIT_CONST="%s" '
          'TC_YMIN="%s" TC_YMAX="%s" TC_STIME="%s" TC_ETIME="%s" TC_GROUPS="%s" TC_BOXPL="%s" %s '
          '%s %s%s_plot_time_series.Rout' %
          (title, ','.join(file_names), ','.join(leg_names), ylab, yindex, yscaler,
           sep, otype, oprefix, pdf_dir, aggr, omit_const, ymin, ymax, stime, etime,
           ','.join(map(str, _groups)), boxplot, plot_params,
           plot_script, pdf_dir, oprefix))

    if config.TPCONF_debug_level == 0:
        local('rm -f %s%s_plot_time_series.Rout' % (pdf_dir, oprefix))


## Plot DASH goodput
#  @param title Title of plot at the top
#  @param files Dictionary with legend names (keys) and files with the data to plot
#               (values)
#  @param groups Map data files to groups (all files of same experiment must have
#                same group number)
#  @param ylab Label for y-axis
#  @param otype Type of output file
#  @param oprefix Output file name prefix
#  @param pdf_dir Output directory for graphs
#  @param sep Character that separates columns in data file
#  @param ymin Minimum value on y-axis
#  @param ymax Maximum value on y-axis
#  @param lnames Semicolon-separated list of legend names
#  @param stime Start time of plot window in seconds
#               (by default 0.0 = start of experiment)
#  @param etime End time of plot window in seconds (by default 0.0 = end of
#               experiment)
#  @param plot_params Parameters passed to plot function via environment variables
#  @param plot_script Specify the script used for plotting, must specify full path
#                     (default is config.TPCONF_script_path/plot_dash_goodput.R)
def plot_dash_goodput(title='', files={}, groups={}, ylab='', otype='', oprefix='',
                      pdf_dir='', sep=' ', ymin=0, ymax=0, lnames='', stime='0.0',
                      etime='0.0', plot_params='', plot_script=''):

    file_names = []
    leg_names = []

    sorted_files = sorted(files.items())
    sorted_files = sort_by_group_id(sorted_files, groups)
    #print(sorted_files)

    for name, file_name in sorted_files:
        leg_names.append(name)
        file_names.append(file_name)

    if lnames != '':
        lname_arr = lnames.split(';')
        if len(lname_arr) != len(leg_names):
            abort(
                'Number of legend names must be the same as the number of flows')
        else:
            leg_names = lname_arr

    # get the directory name here if not specified
    if pdf_dir == '':
        pdf_dir = os.path.dirname(file_names[0]) + '/'
    else:
        pdf_dir = valid_dir(pdf_dir)
        # if not absolute dir, make it relative to experiment_dir
        # assume experiment dir is part before first slash
        if pdf_dir != '/':
            pdf_dir = file_names[0].split('/')[0] + '/' + pdf_dir
        # if pdf_dir specified create if it doesn't exist
        mkdir_p(pdf_dir)

    if plot_script == '':
        plot_script = 'R CMD BATCH --vanilla %s/plot_dash_goodput.R' % \
                      config.TPCONF_script_path

    # interface between this code and the plot function are environment variables
    # the following variables are passed to plot function:
    # TC_TITLE:  character string that is plotted over the graph
    # TC_FNAMES: comma-separated list of file names (each file contains one date series,
    #         e.g. data for one flow). The format of each file is CSV-style, but the
    #         separator does not have to be a comma (can be set with SEP). The first
    #         column contains the timestamps. The second, third etc. columns contain
    #         data, but only one of these columns will be plotted (set with YINDEX). 
    # TC_LNAMES: comma-separated list of legend names. this list has the same length
    #         as FNAMES and each entry corresponds to data in file name with the
    #         same index in FNAMES
    # TC_YLAB:   y-axis label character string
    # TC_SEP:    column separator used in data file
    # TC_OTYPE:  type of output graph (default is 'pdf')
    # TC_OPREFIX: the prefix (first part) of the graph file name
    # TC_ODIR:   directory where output files, e.g. pdfs are placed
    # TC_YMIN:   minimum value on y-axis (for zooming in), default is 0 
    # TC_YMAX:   maximum value on y-axis (for zooming in), default is 0 meaning the 
    #         maximum value is determined from the data
    # TC_STIME:  start time on x-axis (for zooming in), default is 0.0 meaning the start 
    #         of an experiment
    # TC_ETIME:  end time on x-axis (for zooming in), default is 0.0 meaning the end of an
    #         experiment a determined from the data

    #local('which R')
    local('TC_TITLE="%s" TC_FNAMES="%s" TC_LNAMES="%s" TC_YLAB="%s" TC_SEP="%s" TC_OTYPE="%s" '
          'TC_OPREFIX="%s" TC_ODIR="%s" TC_YMIN="%s" TC_YMAX="%s" TC_STIME="%s" TC_ETIME="%s" %s '
          '%s %s%s_plot_dash_goodput.Rout' %
          (title, ','.join(file_names), ','.join(leg_names), ylab, sep, otype, oprefix,
           pdf_dir, ymin, ymax, stime, etime, plot_params, plot_script,
           pdf_dir, oprefix))

    if config.TPCONF_debug_level == 0:
        local('rm -f %s%s_plot_dash_goodput.Rout' % (pdf_dir, oprefix))


## plot_incast_ACK_series
## (based on plot_time_series, but massages the filenames and legend names a little
## differently to handle a trial being broken into 'bursts'.)
#  @param title Title of plot at the top
#  @param files Dictionary with legend names (keys) and files with the data
#               to plot (values)
#  @param ylab Label for y-axis
#  @param yindex Index of the column in data file to plot
#  @param yscaler Scaler for y-values (data in file is multiplied with the scaler)
#  @param otype Type of output file
#  @param oprefix Output file name prefix
#  @param pdf_dir Output directory for graphs
#  @param sep Character that separates columns in data file
#  @param aggr Aggregation of data in 1-seond intervals
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
#  @param groups Map data files to groups (all files of same experiment must have
#                same group number)
#  @param sort_flowkey '1' sort by flow key (default)
#                      '0' don't sort by flow key
#  @param burst_sep '0' plot seq numbers as they come, relative to 1st seq number
#                   > '0' plot seq numbers relative to 1st seq number after gaps
#                         of more than burst_sep seconds (e.g. incast query/response bursts)
#                   < 0,  plot seq numbers relative to 1st seq number after each abs(burst_sep)
#                         seconds since the first burst @ t = 0 (e.g. incast query/response bursts)
#  @param sburst Default 1, or a larger integer indicating the burst number of the first burst
#                in the provided list of filenames. Used as an offset to calculate new legend suffixes.
#  @param plot_params Parameters passed to plot function via environment variables
#  @param plot_script Specify the script used for plotting, must specify full path
#                    (default is config.TPCONF_script_path/plot_bursts.R)
#  @param source_filter Source filter
def plot_incast_ACK_series(title='', files={}, ylab='', yindex=2, yscaler=1.0, otype='',
                     oprefix='', pdf_dir='', sep=' ', aggr='', omit_const='0',
                     ymin=0, ymax=0, lnames='', stime='0.0', etime='0.0',
                     groups={}, sort_flowkey='1', burst_sep='1.0', sburst=1,
                     plot_params='', plot_script='', source_filter=''):

    file_names = []
    leg_names = []
    _groups = []

    # Pick up case where the user has supplied a number of legend names
    # that doesn't match the number of distinct trials (as opposed to the
    # number of bursts detected within each trial)
    if lnames != '':
        if len(lnames.split(";")) != len(files.keys()) :
            abort(
                'Number of legend names must be the same as the number of flows')

    if sort_flowkey == '1':
        sorted_files = sort_by_flowkeys(files, source_filter)
    else:
        sorted_files = files.items()

    #print("MAIN: sorted_files: %s" % sorted_files)

    # sort by group id
    sorted_files = sort_by_group_id2(sorted_files, groups)

    for name, file_name in sorted_files:
        # Create a sequence of burst-specific legend names,
        # derived from the flowID-based legend name.
        # Keep the .R code happy by creating a groups entry
        # for each burst-specific file.
        for burst_index in range(len(file_name)) :
            leg_names.append(name+"%"+str(burst_index+sburst))
            file_names.append(file_name[burst_index])
            _groups.append(groups[file_name[burst_index]])

    if lnames != '':
        # Create a sequence of burst-specific legend names,
        # derived from the per-trial legend names provided by user.
        lname_arr_orig = lnames.split(';')
        lname_arr = []
        i = 0
        for name, file_name in sorted_files:
            for burst_index in range(len(file_name)) :
                lname_arr.append(lname_arr_orig[i]+"%"+str(burst_index+sburst))
            i += 1

        if len(lname_arr) != len(leg_names):
            abort(
                'Number of legend names must be the same as the number of flows')
        else:
            leg_names = lname_arr

    # get the directory name here if not specified
    if pdf_dir == '':
        pdf_dir = os.path.dirname(file_names[0]) + '/'
    else:
        pdf_dir = valid_dir(pdf_dir)
        # if no absolute path make it relative to experiment_dir
        # assume experiment dir is part before first slash
        if pdf_dir[0] != '/':
            pdf_dir = file_names[0].split('/')[0] + '/' + pdf_dir
        # if pdf_dir specified create if it doesn't exist
        mkdir_p(pdf_dir)

    if plot_script == '':
        plot_script = 'R CMD BATCH --vanilla %s/plot_bursts.R' % \
                       config.TPCONF_script_path

    # for a description of parameters see plot_time_series above
    #local('which R')
    local('TC_TITLE="%s" TC_FNAMES="%s" TC_LNAMES="%s" TC_YLAB="%s" TC_YINDEX="%d" TC_YSCALER="%f" '
          'TC_SEP="%s" TC_OTYPE="%s" TC_OPREFIX="%s" TC_ODIR="%s" TC_AGGR="%s" TC_OMIT_CONST="%s" '
          'TC_YMIN="%s" TC_YMAX="%s" TC_STIME="%s" TC_ETIME="%s" TC_GROUPS="%s" %s '
          'TC_BURST_SEP=1 '
          '%s %s%s_plot_bursts.Rout' %
          (title, ','.join(file_names), ','.join(leg_names), ylab, yindex, yscaler,
           sep, otype, oprefix, pdf_dir, aggr, omit_const, ymin, ymax, stime, etime,
           ','.join(map(str, _groups)), plot_params, plot_script, pdf_dir, oprefix))

    if config.TPCONF_debug_level == 0:
        local('rm -f %s%s_plot_bursts.Rout' % (pdf_dir, oprefix))


## plot comparison plot for different metrics across different experiment parameter
## combinations
#  @param title Title of plot at the top
#  @param file_names List of data file names
#  @param xlabs List of x-axis labels
#  @param ylab Label for y-axis
#  @param yindex Index of the column in data file to plot
#  @param yscaler Scaler for y-values (data in file is multiplied with the scaler)
#  @param otype Type of output file
#  @param oprefix Output file name prefix
#  @param pdf_dir Output directory for graphs
#  @param sep Character that separates columns in data file
#  @param aggr Aggregation of data in 1-seond intervals
#  @param diff '0' plot values as they are
#              '1' plot difference of consecutive values
#  @param omit_const '0' don't omit anything,
#                    '1' omit any series that are 100% constant
#                       (e.g. because there was no data flow)
#  @param ptype Plot type ('box', 'median', 'mean')
#  @param ymin Minimum value on y-axis
#  @param ymax Maximum value on y-axis
#  @param leg_names List of legend names
#  @param stime Start time of plot window in seconds
#               (by default 0.0 = start of experiment)
#  @param etime End time of plot window in seconds
#               (by default 0.0 = end of experiment)
#  @param plot_params Parameters passed to plot function via environment variables
#  @param plot_script Specify the script used for plotting, must specify full path
#                    (default is config.TPCONF_script_path/plot_bursts.R)
def plot_cmpexp(title='', file_names=[], xlabs=[], ylab='', yindex=2, yscaler=1.0, 
                otype='', oprefix='', pdf_dir='', sep=' ', aggr='', diff='', omit_const='0',
                ptype='', ymin=0, ymax=0, leg_names=[], stime='0.0', etime='0.0',
                plot_params='', plot_script=''):

    if plot_script == '':
        plot_script = 'R CMD BATCH --vanilla %s/plot_cmp_experiments.R' % \
                      config.TPCONF_script_path

    # interface between this code and the plot function are environment variables
    # the following variables are passed to plot function:
    # TC_TITLE:  character string that is plotted over the graph
    # TC_FNAMES: comma-separated list of file names (each file contains one date series,
    #         e.g. data for one flow). The format of each file is CSV-style, but the
    #         separator does not have to be a comma (can be set with SEP). The first
    #         column contains the timestamps. The second, third etc. columns contain
    #         data, but only one of these columns will be plotted (set with YINDEX). 
    # TC_LNAMES: comma-separated list of legend names. this list has the same length
    #         as FNAMES and each entry corresponds to data in file name with the
    #         same index in FNAMES
    # TC_XLABS:  comma-separated list of labels for the x-axis ticks, one for each parameter
    #         combination that is plotted 
    # TC_YLAB:   y-axis label character string
    # TC_YINDEX: index of data column in file to plot on y-axis (file can have more than
    #         one data column)
    # TC_YSCALER: factor which is multiplied with each data value before plotting
    # TC_SEP:    column separator used in data file
    # TC_OTYPE:  type of output graph (default is 'pdf')
    # TC_OPREFIX: the prefix (first part) of the graph file name
    # TC_ODIR:   directory where output files, e.g. pdfs are placed
    # TC_AGGR:   set to '1' means data is aggregated over time intervals, more specifically
    #         the data is summed over the time intervals (used to determine throughput
    #         over time windows based on packet lengths)  
    #         set to '0' means plot data as is 
    # TC_OMIT_CONST: '0' don't omit anything,
    #             '1' omit any data series from plot that are 100% constant 
    # TC_PTYPE:  the type of plot identified by name, it can be 'box', 'mean' or 'median' 
    #         for the default R script
    # TC_YMIN:   minimum value on y-axis (for zooming in), default is 0 
    # TC_YMAX:   maximum value on y-axis (for zooming in), default is 0 meaning the 
    #         maximum value is determined from the data
    # TC_STIME:  start time on x-axis (for zooming in), default is 0.0 meaning the start 
    #         of an experiment
    # TC_ETIME:  end time on x-axis (for zooming in), default is 0.0 meaning the end of an
    #         experiment a determined from the data

    #local('which R')
    local('TC_TITLE="%s" TC_FNAMES="%s" TC_LNAMES="%s" TC_XLABS="%s" TC_YLAB="%s" TC_YINDEX="%d" '
          'TC_YSCALER="%f" TC_SEP="%s" TC_OTYPE="%s" TC_OPREFIX="%s" TC_ODIR="%s" TC_AGGR="%s" TC_DIFF="%s" '
          'TC_OMIT_CONST="%s" TC_PTYPE="%s" TC_YMIN="%s" TC_YMAX="%s" TC_STIME="%s" TC_ETIME="%s" %s '
          '%s %s%s_plot_cmp_experiments.Rout' %
          (title, ','.join(file_names), ','.join(leg_names), ','.join(xlabs), ylab,
           yindex, yscaler, sep, otype, oprefix, pdf_dir, aggr, diff,
           omit_const, ptype, ymin, ymax, stime, etime, plot_params,
           plot_script, pdf_dir, oprefix))

    if config.TPCONF_debug_level == 0:
        local('rm -f %s%s_plot_cmp_experiments.Rout' % (pdf_dir, oprefix))


## plot comparison plot for different metrics across different experiment parameter
## combinations
#  @param title Title of plot at the top
#  @param x_files List of data file names for x-axis
#  @param y_files List of data file names for y-axis
#  @param xlab Label for x-axis
#  @param ylab Label for y-axis
#  @param yindexes List of the columns in data files to plot
#  @param yscalers List of y-values scalers (data in file is multiplied with the scaler)
#  @param otype Type of output file
#  @param oprefix Output file name prefix
#  @param pdf_dir Output directory for graphs
#  @param xsep Character that separates columns in x-axis data file
#  @param ysep Character that separates columns in y-axis data file
#  @param aggrs List of aggregation flags 
#  @param diffs List of diff flags ('0' plot values as they are
#                                   '1' plot difference of consecutive values)
#  @param xmin Minimum value on x-axis
#  @param xmax Maximum value on x-axis
#  @param ymin Minimum value on y-axis
#  @param ymax Maximum value on y-axis
#  @param stime Start time of plot window in seconds
#               (by default 0.0 = start of experiment)
#  @param etime End time of plot window in seconds
#               (by default 0.0 = end of experiment)
#  @param groups List of group numbers
#  @param leg_names List of legend names
#  @param plot_params Parameters passed to plot function via environment variables
#  @param plot_script Specify the script used for plotting, must specify full path
#                    (default is config.TPCONF_script_path/plot_bursts.R)
def plot_2d_density(title='', x_files=[], y_files=[], xlab='', ylab='', yindexes=[], yscalers=[],
                otype='', oprefix='', pdf_dir='', xsep=' ', ysep=' ' , aggrs=[], diffs=[], 
                xmin=0, xmax=0, ymin=0, ymax=0, stime='0.0', etime='0.0', groups=[], leg_names=[],
                plot_params='', plot_script=''):

    if plot_script == '':
        plot_script = 'R CMD BATCH --vanilla %s/plot_contour.R' % config.TPCONF_script_path

    # interface between this code and the plot function are environment variables
    # the following variables are passed to plot function:
    # TC_TITLE:  character string that is plotted over the graph
    # TC_XFNAMES: comma-separated list of x-axis file names (each file contains one date series,
    #         e.g. data for one flow). The format of each file is CSV-style, but the
    #         separator does not have to be a comma (can be set with SEP). The first
    #         column contains the timestamps. The second, third etc. columns contain
    #         data, but only one of these columns will be plotted (set with YINDEX). 
    # TC_YFNAMES: comma-separated list of y-axis file names (each file contains one date series,
    #         e.g. data for one flow). The format of each file is CSV-style, but the
    #         separator does not have to be a comma (can be set with SEP). The first
    #         column contains the timestamps. The second, third etc. columns contain
    #         data, but only one of these columns will be plotted (set with YINDEX).
    # TC_LNAMES: comma-separated list of legend names. this list has the same length
    #         as FNAMES and each entry corresponds to data in file name with the
    #         same index in FNAMES
    # TC_XLAB:   x-axis label character string 
    # TC_YLAB:   y-axis label character string
    # TC_YINDEXES: comma-separated list of indexes of data column in data files. The list
    #           must have exactly two entries, one index for x-axis data files and one
    #           for y-axis data files
    # TC_YSCALERS: comma-separated list of factors which are multiplied with each data value 
    #           before plotting. Again, must have length two, first factor for x-axis and
    #           second factor for y-axis.
    # TC_XSEP:    column separator used for x-axis data files
    # TC_YSEP:    column separator used for y-axis data files
    # TC_OTYPE:  type of output graph (default is 'pdf')
    # TC_OPREFIX: the prefix (first part) of the graph file name
    # TC_ODIR:   directory where output files, e.g. pdfs are placed
    # TC_AGGRS:   comma-separated list with two entries (first for x-axis, second for y-axis) 
    #         '0' means plot data as is, i.e. values over time
    #         '1' means data is aggregated over time intervals, more specifically
    #         the data (specified by YINDEXES) is summed over the time intervals (used 
    #         to determine throughput over time windows based on packet lengths)  
    #         (in the future could use other values to signal different aggregations)
    # TC_DIFFS:   convert cummulative data into non-cummulative data. list with two
    #          0/1 entries (first for x-axis, second for y-axis)
    #          '0' means use data as is
    #          '1' means use differemce of consecutive data values
    # TC_XMIN:   minimum value on x-axis (for zooming in), default is 0 
    # TC_XMAX:   maximum value on x-axis (for zooming in), default is 0 meaning the 
    #         maximum value is determined from the data
    # TC_YMIN:   minimum value on y-axis (for zooming in), default is 0 
    # TC_YMAX:   maximum value on y-axis (for zooming in), default is 0 meaning the 
    #         maximum value is determined from the data
    # TC_GROUPS: comma-separated list of group IDs (integer numbers). This list must  
    #         have the same length as XFNAMES and YFNAMES. The data is grouped using colour
    #         as per the specified group numbers. 

    #local('which R')
    local('TC_TITLE="%s" TC_XFNAMES="%s" TC_YFNAMES="%s", TC_LNAMES="%s" TC_XLAB="%s" TC_YLAB="%s" TC_YINDEXES="%s" '
          'TC_YSCALERS="%s" TC_XSEP="%s" TC_YSEP="%s" TC_OTYPE="%s" TC_OPREFIX="%s" TC_ODIR="%s" TC_AGGRS="%s" '
          'TC_DIFFS="%s" TC_XMIN="%s" TC_XMAX="%s" TC_YMIN="%s" TC_YMAX="%s" TC_STIME="%s" TC_ETIME="%s" TC_GROUPS="%s" %s '
          '%s %s%s_plot_contour.Rout' %
          (title, ','.join(x_files), ','.join(y_files), ','.join(leg_names),
           xlab, ylab, ','.join(yindexes), ','.join(yscalers),
           xsep, ysep, 'pdf', oprefix, pdf_dir, ','.join(aggrs),
           ','.join(diffs), xmin, xmax, ymin, ymax, stime, etime, 
	   ','.join([str(x) for x in groups]),
           plot_params, plot_script, pdf_dir, oprefix))

    if config.TPCONF_debug_level == 0:
        local('rm -f %s%s_plot_contour.Rout' % (pdf_dir, oprefix))

