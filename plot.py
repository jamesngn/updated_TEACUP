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
# 
# Copyright (c) 2024 
# Author: Mitchell Lowe (101607237@student.swin.edu.au)
#         
# 

import os
import errno
import time
import datetime
from fabric2 import Connection, Config, task
from invoke import run, Local, UnexpectedExit, Context as env
from fabric2.exceptions import NetworkError
from invoke.exceptions import Exit

import config
from internalutil import mkdir_p, valid_dir


#############################################################################
# Flow sorting functions
#############################################################################

# In Python 3, cmp is removed, so we use a key function instead.

def _cmp_src_port(x):
    "Compare flow keys by flow source port (lowest source port first)"
    xflow = str(x)
    xflow_arr = xflow.split('_')[-4:]
    return int(xflow_arr[1])

    # split into src/dst IP/port
    xflow_arr = xflow.split('_')
    xflow_arr = xflow_arr[len(xflow_arr)-4:len(xflow_arr)]
    yflow_arr = yflow.split('_')
    yflow_arr = yflow_arr[len(yflow_arr)-4:len(yflow_arr)]

    # sort by numeric source port
    return (int(xflow_arr[1]) <  int(yflow_arr[1])) - (int(xflow_arr[1]) > int(yflow_arr[1]))
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
    return (int(xflow_arr[3]) > int(yflow_arr[3])) - (int(xflow_arr[3]) < int(yflow_arr[3]))
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
        source_filter_list = [fil.strip() for fil in source_filter.split(';')]

    #
    # 1. if filter string was specified graph in order of filters
    #

    if len(source_filter_list) > 0:
        for fil in source_filter_list:
            arr = fil.split('_')
            if arr[2] == '*':
                fil = arr[1] + '_'
            else:
                fil = arr[1] + '_' + arr[2]

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

    cmp_fct = _cmp_dst_port if all(int(name.split('_')[-4]) > int(name.split('_')[-2]) for name in files) else _cmp_src_port

    for name in sorted(files.keys(), key=cmp_fct):
        if rev_files.get(name, '') == '':
            sorted_files.append((name, files[name]))
            a = name.split('_')[-4:]
            rev_name = a[2] + '_' + a[3] + '_' + a[0] + '_' + a[1]
            if files.get(rev_name, '') != '':
                sorted_files.append((rev_name, files[rev_name]))
                rev_files[rev_name] = files[rev_name]

    if len(rev_files) == len(files) / 2:
        sorted_files_c2sleft = [('', '')] * len(files)

        for idx, (name, file_name) in enumerate(sorted_files):
            if idx % 2 == 0:
                sorted_files_c2sleft[int(idx / 2)] = (name, file_name)
            else:
                sorted_files_c2sleft[
                    int((idx - 1) / 2) + len(files) // 2] = (name, file_name)

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

def plot_time_series(c: env, title='', files={}, ylab='', yindex=2, yscaler=1.0, otype='',
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
        sorted_files = list(files.items())

    sorted_files = sort_by_group_id(sorted_files, groups)

    for name, file_name in sorted_files:
        leg_names.append(name)
        file_names.append(file_name)
        _groups.append(groups[file_name])

    if lnames != '':
        lname_arr = lnames.split(';')
        if boxplot == '0' and len(lname_arr) != len(leg_names):
            #abort(
            #    'Number of legend names must be the same as the number of flows')
            raise Exit(
                'Number of legend names must be the same as the number of flows')
        else:
            leg_names = lname_arr

    if pdf_dir == '':
        pdf_dir = os.path.dirname(file_names[0]) + '/'
    else:
        pdf_dir = valid_dir(pdf_dir)
        if pdf_dir[0] != '/':
            pdf_dir = file_names[0].split('/')[0] + '/' + pdf_dir
        mkdir_p(pdf_dir)

    if plot_script == '':
        plot_script = f'R CMD BATCH --vanilla {config.TPCONF_script_path}/plot_time_series.R'

    c.run('TC_TITLE="%s" TC_FNAMES="%s" TC_LNAMES="%s" TC_YLAB="%s" TC_YINDEX="%d" TC_YSCALER="%f" '
          'TC_SEP="%s" TC_OTYPE="%s" TC_OPREFIX="%s" TC_ODIR="%s" TC_AGGR="%s" TC_OMIT_CONST="%s" '
          'TC_YMIN="%s" TC_YMAX="%s" TC_STIME="%s" TC_ETIME="%s" TC_GROUPS="%s" TC_BOXPL="%s" %s '
          '%s %s%s_plot_time_series.Rout' %
          (title, ','.join(file_names), ','.join(leg_names), ylab, yindex, yscaler,
           sep, otype, oprefix, pdf_dir, aggr, omit_const, ymin, ymax, stime, etime,
           ','.join(map(str, _groups)), boxplot, plot_params,
           plot_script, pdf_dir, oprefix))

    if config.TPCONF_debug_level == 0:
        c.run(f'rm -f {pdf_dir}{oprefix}_plot_time_series.Rout')


def plot_dash_goodput(c: env, title='', files={}, groups={}, ylab='', otype='', oprefix='',
                      pdf_dir='', sep=' ', ymin=0, ymax=0, lnames='', stime='0.0',
                      etime='0.0', plot_params='', plot_script=''):

    file_names = []
    leg_names = []

    sorted_files = sorted(files.items())
    sorted_files = sort_by_group_id(sorted_files, groups)

    for name, file_name in sorted_files:
        leg_names.append(name)
        file_names.append(file_name)

    if lnames != '':
        lname_arr = lnames.split(';')
        if len(lname_arr) != len(leg_names):
            #abort(
            #    'Number of legend names must be the same as the number of flows')
            raise Exit(
                'Number of legend names must be the same as the number of flows')
        else:
            leg_names = lname_arr

    if pdf_dir == '':
        pdf_dir = os.path.dirname(file_names[0]) + '/'
    else:
        pdf_dir = valid_dir(pdf_dir)
        if pdf_dir != '/':
            pdf_dir = file_names[0].split('/')[0] + '/' + pdf_dir
        mkdir_p(pdf_dir)

    if plot_script == '':
        plot_script = f'R CMD BATCH --vanilla {config.TPCONF_script_path}/plot_dash_goodput.R'

    c.run('TC_TITLE="%s" TC_FNAMES="%s" TC_LNAMES="%s" TC_YLAB="%s" TC_SEP="%s" TC_OTYPE="%s" '
          'TC_OPREFIX="%s" TC_ODIR="%s" TC_YMIN="%s" TC_YMAX="%s" TC_STIME="%s" TC_ETIME="%s" %s '
          '%s %s%s_plot_dash_goodput.Rout' %
          (title, ','.join(file_names), ','.join(leg_names), ylab, sep, otype, oprefix,
           pdf_dir, ymin, ymax, stime, etime, plot_params, plot_script,
           pdf_dir, oprefix))

    if config.TPCONF_debug_level == 0:
        c.run(f'rm -f {pdf_dir}{oprefix}_plot_dash_goodput.Rout')


def plot_incast_ACK_series(c: env, title='', files={}, ylab='', yindex=2, yscaler=1.0, otype='',
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
            #abort(
            #    'Number of legend names must be the same as the number of flows')
            raise Exit(
                'Number of legend names must be the same as the number of flows')

    if sort_flowkey == '1':
        sorted_files = sort_by_flowkeys(files, source_filter)
    else:
        sorted_files = list(files.items())

    sorted_files = sort_by_group_id2(sorted_files, groups)

    for name, file_name in sorted_files:
        for burst_index in range(len(file_name)):
            leg_names.append(f"{name}%{burst_index + sburst}")
            file_names.append(file_name[burst_index])
            _groups.append(groups[file_name[burst_index]])

    if lnames != '':
        lname_arr_orig = lnames.split(';')
        lname_arr = []
        for i, (name, file_name) in enumerate(sorted_files):
            for burst_index in range(len(file_name)):
                lname_arr.append(f"{lname_arr_orig[i]}%{burst_index + sburst}")

        if len(lname_arr) != len(leg_names):
            #abort(
            #    'Number of legend names must be the same as the number of flows')
            raise Exit(
                'Number of legend names must be the same as the number of flows')
        else:
            leg_names = lname_arr

    if pdf_dir == '':
        pdf_dir = os.path.dirname(file_names[0]) + '/'
    else:
        pdf_dir = valid_dir(pdf_dir)
        if pdf_dir[0] != '/':
            pdf_dir = file_names[0].split('/')[0] + '/' + pdf_dir
        mkdir_p(pdf_dir)

    if plot_script == '':
        plot_script = f'R CMD BATCH --vanilla {config.TPCONF_script_path}/plot_bursts.R'

    c.run('TC_TITLE="%s" TC_FNAMES="%s" TC_LNAMES="%s" TC_YLAB="%s" TC_YINDEX="%d" TC_YSCALER="%f" '
          'TC_SEP="%s" TC_OTYPE="%s" TC_OPREFIX="%s" TC_ODIR="%s" TC_AGGR="%s" TC_OMIT_CONST="%s" '
          'TC_YMIN="%s" TC_YMAX="%s" TC_STIME="%s" TC_ETIME="%s" TC_GROUPS="%s" %s '
          'TC_BURST_SEP=1 '
          '%s %s%s_plot_bursts.Rout' %
          (title, ','.join(file_names), ','.join(leg_names), ylab, yindex, yscaler,
           sep, otype, oprefix, pdf_dir, aggr, omit_const, ymin, ymax, stime, etime,
           ','.join(map(str, _groups)), plot_params, plot_script, pdf_dir, oprefix))

    if config.TPCONF_debug_level == 0:
        c.run(f'rm -f {pdf_dir}{oprefix}_plot_bursts.Rout')


def plot_cmpexp(c: env, title='', file_names=[], xlabs=[], ylab='', yindex=2, yscaler=1.0, 
                otype='', oprefix='', pdf_dir='', sep=' ', aggr='', diff='', omit_const='0',
                ptype='', ymin=0, ymax=0, leg_names=[], stime='0.0', etime='0.0',
                plot_params='', plot_script=''):

    if plot_script == '':
        plot_script = f'R CMD BATCH --vanilla {config.TPCONF_script_path}/plot_cmp_experiments.R'

    c.run('TC_TITLE="%s" TC_FNAMES="%s" TC_LNAMES="%s" TC_XLABS="%s" TC_YLAB="%s" TC_YINDEX="%d" '
          'TC_YSCALER="%f" TC_SEP="%s" TC_OTYPE="%s" TC_OPREFIX="%s" TC_ODIR="%s" TC_AGGR="%s" TC_DIFF="%s" '
          'TC_OMIT_CONST="%s" TC_PTYPE="%s" TC_YMIN="%s" TC_YMAX="%s" TC_STIME="%s" TC_ETIME="%s" %s '
          '%s %s%s_plot_cmp_experiments.Rout' %
          (title, ','.join(file_names), ','.join(leg_names), ','.join(xlabs), ylab,
           yindex, yscaler, sep, otype, oprefix, pdf_dir, aggr, diff,
           omit_const, ptype, ymin, ymax, stime, etime, plot_params,
           plot_script, pdf_dir, oprefix))

    if config.TPCONF_debug_level == 0:
        c.run(f'rm -f {pdf_dir}{oprefix}_plot_cmp_experiments.Rout')


def plot_2d_density(c: env, title='', x_files=[], y_files=[], xlab='', ylab='', yindexes=[], yscalers=[],
                    otype='', oprefix='', pdf_dir='', xsep=' ', ysep=' ', aggrs=[], diffs=[], 
                    xmin=0, xmax=0, ymin=0, ymax=0, stime='0.0', etime='0.0', groups=[], leg_names=[],
                    plot_params='', plot_script=''):

    if plot_script == '':
        plot_script = f'R CMD BATCH --vanilla {config.TPCONF_script_path}/plot_contour.R'

    c.run('TC_TITLE="%s" TC_XFNAMES="%s" TC_YFNAMES="%s", TC_LNAMES="%s" TC_XLAB="%s" TC_YLAB="%s" TC_YINDEXES="%s" '
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
        c.run(f'rm -f {pdf_dir}{oprefix}_plot_contour.Rout')