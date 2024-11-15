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
## @package trafficgens
# Traffic generators
#
# $Id: trafficgens.py,v 066d6f004887 2018/02/07 19:40:37 garmitage $
# 
# Copyright (c) 2024 
# Author: Sanyam Verma  (103165193@student.swin.edu.au)

import time
import random
from fabric import Connection, task
from invoke import run
from invoke import Connection, SerialGroup
from fabric import task
import bgproc
import config
from hosttype import get_type_cached
from hostint import get_address_pair
from runbg import runbg
import os

#
# nttcp
#

## Start nttcp server (UDP only)
#  @param counter Unique ID
#  @param file_prefix File prefix for log file (nttcp server output)
#  @param remote_dir Directory to create log file in
#  @param port Listen on this port
#  @param srv_host Bind to interface with this address
#  @param buf_size Size of send buffer
#  @param extra_params Extra params to be set
#  @param check '0' don't check for nttcp executable,
#               '1' check for nttcp executable
#  @param wait Time to wait before process is started
def start_nttcp_server(c, counter='1', file_prefix='', remote_dir='',
                       port='', srv_host='', buf_size='', extra_params='',
                       check='1', wait=''):
    if port == '':
        raise ValueError('Must specify port')

    if srv_host == '':
        raise ValueError('Must specify server host')

    if check == '1':
        # make sure we have executable
        run('which nttcp', pty=False)
        
    hostOS = get_type_cached(c.host)
    
    if hostOS == 'FreeBSD':
        # Reduces TIME_WAIT state to 30 seconds (2*MSL)
        run('sysctl -w net.inet.tcp.msl=15000')
    
    elif hostOS == 'Linux':
        # Recycle TIME_WAIT sockets faster   
        run('sysctl -w net.ipv4.tcp_tw_recycle=1')

    # start nttcp
    logfile = os.path.join(remote_dir, f"{file_prefix}_{c.host.replace(':', '_')}_{counter}_nttcp.log")
    nttcp_cmd = f'nttcp -i -p {port} -u -v'
    if buf_size != '':
        nttcp_cmd += f' -w {buf_size}'  # can only set send buffer
    if extra_params != '':
        nttcp_cmd += f' {extra_params}'
    pid = runbg(nttcp_cmd, wait, out_file=logfile)
    bgproc.register_proc(c.host, 'nttcp', counter, pid, logfile)


## Start nttcp client (UDP only)
#  @param counter Unique ID
#  @param file_prefix File prefix for log file (nttcp client output)
#  @param remote_dir Directory to create log file in
#  @param port Listen on this port
#  @param srv_host Bind to interface with this address
#  @param duration Duration in seconds
#  @param interval Packet interval in milliseconds
#  @param psize Size of the UDP payload (excluding IP/UDP header) in bytes
#  @param buf_size Size of send buffer
#  @param extra_params Extra params to be set
#  @param check '0' don't check for nttcp executable,
#               '1' check for nttcp executable
#  @param wait Time to wait before process is started
def start_nttcp_client(c, counter='1', file_prefix='', remote_dir='', port='',
                       srv_host='', duration='', interval='1000', psize='100',
                       buf_size='', extra_params='', check='1', wait=''):

    if port == '':
        raise ValueError('Must specify port')
    if srv_host == '':
        raise ValueError('Must specify server host')
    if duration == '':
        raise ValueError('Must specify duration')

    if check == '1':
        # make sure we have nttcp
        run('which nttcp', pty=False)
        
    hostOS = get_type_cached(c.host)
    
    if hostOS == 'FreeBSD':
        # Reduces TIME_WAIT state to 30 seconds (2*MSL)
        run('sysctl -w net.inet.tcp.msl=15000')
    
    elif hostOS == 'Linux':
        # Recycle TIME_WAIT sockets faster   
        run('sysctl -w net.ipv4.tcp_tw_recycle=1')

    # start nttcp
    # number of bufs to send
    bufs = str(int(float(duration) / (float(interval) / 1000.0)))
    gap = str(int(interval) * 1000)  # gap in microseconds
    logfile = os.path.join(remote_dir, f"{file_prefix}_{c.host.replace(':', '_')}_{counter}_nttcp.log")
    nttcp_cmd = f'nttcp -g {gap} -l {psize} -n {bufs} -p {port} -u -t -T -v {srv_host}'
    
    if buf_size != '':
        nttcp_cmd += f' -w {buf_size}'  # can only set send buffer
    if extra_params != '':
        nttcp_cmd += f' {extra_params}'
    nttcp_cmd += ' %s' % srv_host
    pid = runbg(c, nttcp_cmd, wait, out_file=logfile)
    bgproc.register_proc(c.host, 'nttcp', counter, pid, logfile)


## Start nttcp sender and receiver
## For parameters see start_nttcp_client() and start_nttcp_server()
def start_nttcp(c, counter='1', file_prefix='', remote_dir='', local_dir='',
                port='', client='', server='', duration='', interval='', psize='',
                buf_size='', extra_params_client='', extra_params_server='',
                check='1', wait=''):
    "Start nttcp traffic sender and receiver"

    server, server_internal = get_address_pair(server)
    client, dummy = get_address_pair(client)
    start_nttcp_server(c, counter, file_prefix, remote_dir, port,
            server_internal, buf_size, extra_params_server,
            check, wait, hosts=[server])
    start_nttcp_client(c, counter, file_prefix, remote_dir, port,
            server_internal, duration, interval, psize, buf_size,
            extra_params_client, check, wait, hosts=[client])


#
# iperf
#

## Start iperf server
#  @param counter Unique ID
#  @param file_prefix File prefix for log file (iperf server output)
#  @param remote_dir Directory to create log file in
#  @param port Listen on this port
#  @param srv_host Bind to interface with this address
#  @param duration Duration in seconds (only used if kill='1')
#  @param mss Maximum segment size
#  @param buf_size Size of send and receive buffer
#                  (assumes iperf modified with CAIA patch)
#  @param proto Must be 'tcp' or 'udp'
#  @param extra_params Extra params to be set
#  @param check '0' don't check for iperf executable, '1' check for iperf executable
#  @param wait Time to wait before process is started
#  @param kill If '0' server will terminate according to duration (default),
#              if '1' kill server after duration to work around
#              "feature" in iperf that prevents it from stopping after duration
def start_iperf_server(c, counter='1', file_prefix='', remote_dir='', port='',
                       srv_host='', duration='', mss='', buf_size='', proto='tcp',
                       extra_params='', check='1', wait='', kill='0'):
    if port == '':
        raise ValueError('Must specify port')
    if srv_host == '':
        raise ValueError('Must specify server host')
    if proto != 'tcp' and proto != 'udp':
        raise ValueError("Protocol must be 'tcp' or 'udp'")

    if check == '1':
        # make sure we have iperf
        run('which iperf', pty=False)

    # start iperf
    logfile = f"{remote_dir}{file_prefix}_{c.host.replace(':', '_')}_{counter}_iperf.log"
    iperf_cmd = f"iperf -i 1 -s -p {port} -B {srv_host}"
    if proto == 'udp':
        iperf_cmd += ' -u'
    if mss != '':
        iperf_cmd += f' -M {mss}'
    if buf_size != '':
        # only for CAIA patched iperf
        iperf_cmd += f' -j {buf_size} -k {buf_size}'
    if extra_params != '':
        iperf_cmd += ' ' + extra_params
    pid = runbg(iperf_cmd, wait, out_file=logfile)

    bgproc.register_proc(c.host, 'iperf', counter, pid, logfile)

    if kill == '1':
        if duration == '':
            raise ValueError("If kill is set to '1', duration must be specified")

        # kill iperf server (send SIGTERM first, then SIGKILL after 1 second)
        kill_cmd = 'kill_iperf.sh {pid}'
        # do this shortly after iperf client is expected to finish
        wait = str(float(wait) + float(duration) + 2.0)
        pid = runbg(kill_cmd, wait)

        bgproc.register_proc(c.host, 'kill_iperf', counter, pid, '')


## Start iperf client
#  @param counter Unique ID
#  @param file_prefix File prefix for log file (iperf server output)
#  @param remote_dir Directory to create log file in
#  @param port Listen on this port
#  @param srv_host Bind to interface with this address
#  @param duration Duration in seconds
#  @param congestion_algo Congestion control algo to use (Linux only!)
#  @param mss Maximum segment size
#  @param buf_size Size of send and receive buffer
#                  (assumes iperf modified with CAIA patch)
#  @param proto Must be 'tcp' or 'udp'
#  @param bandw Bandwidth in n[KM] (K for kilo, M for mega)
#  @param extra_params Extra params to be set
#  @param check '0' don't check for iperf executable,
#               '1' check for iperf executable
#  @param wait Time to wait before process is started
#  @param kill If '0' client will terminate according to duration (default),
#              if '1' kill client after duration to work around
#              "feature" in iperf that prevents it from stopping after duration
def start_iperf_client(c, counter='1', file_prefix='', remote_dir='', port='',
                       srv_host='', duration='', congestion_algo='', mss='',
                       buf_size='', proto='tcp', bandw='', extra_params='',
                       check='1', wait='', kill='0'):

    if port == '':
        raise ValueError('Must specify port')
    if srv_host == '':
        raise ValueError('Must specify server host')
    if proto != 'tcp' and proto != 'udp':
        raise ValueError("Protocol must be 'tcp' or 'udp'")

    if check == '1':
        # make sure we have iperf
        run('which iperf', pty=False)

    # start iperf
    logfile = f"{remote_dir}{file_prefix}_{c.host.replace(':', '_')}_{counter}_iperf.log"
    iperf_cmd = f"iperf -i 1 -c {srv_host} -p {port} -t {duration}"
    if proto == 'udp':
        iperf_cmd += ' -u'
        if bandw != '':
            iperf_cmd += f' -b {bandw}'
    else:
        if bandw != '':
            # note that this option does not exist in older iperf versions!
            iperf_cmd += f' -a {bandw}'
        if congestion_algo != '':
            iperf_cmd += f' -Z {congestion_algo}'
        if mss != '':
            iperf_cmd += f' -M {mss}'
    if buf_size != '':
        # only for CAIA patched iperf
        iperf_cmd += f' -j {buf_size} -k {buf_size}'
    if extra_params != '':
        iperf_cmd += f' {extra_params}'
    pid = runbg(iperf_cmd, wait, out_file=logfile)

    bgproc.register_proc(c.host, 'iperf', counter, pid, logfile)

    if kill == '1':
        if duration == '':
            raise ValueError("If kill is set to '1', duration must be specified")

        # kill iperf client (send SIGTERM first, then SIGKILL after 1 second)
        kill_cmd = f'kill_iperf.sh {pid}'
        # do this shortly after iperf client is expected to finish
        wait = str(float(wait) + float(duration) + 1.0)
        pid = runbg(c, kill_cmd, wait)

        bgproc.register_proc(c.host, 'kill_iperf', counter, pid, '')


## Start iperf sender and receiver
## For parameters see start_iperf_client() and start_iperf_server()
def start_iperf(c, counter='1', file_prefix='', remote_dir='', local_dir='',
                port='', client='', server='', duration='', congestion_algo='',
                mss='', buf_size='', proto='tcp', rate='', extra_params_client='',
                extra_params_server='', check='1', wait='', kill='0'):
    "Start iperf traffic sender and receiver"

    server, server_internal = get_address_pair(server)
    client, dummy = get_address_pair(client)
    start_iperf_server(c, counter, file_prefix, remote_dir, port,
            server_internal, duration, mss, buf_size, proto, extra_params_server,
            check, wait, kill, hosts=[server])
    start_iperf_client(c, counter, file_prefix, remote_dir, port,
            server_internal, duration, congestion_algo, mss, buf_size,
            proto, rate, extra_params_client, check, wait, kill, hosts=[client])


#
# ping
#

## Start ping
#  @param counter Unique ID
#  @param file_prefix File prefix for log file (iperf server output)
#  @param remote_dir Directory to create log file in
#  @param dest Target to ping
#  @param duration Duration in seconds
#  @param rate Number of pings per second
#  @param extra_params Other parameters passed directly to ping
#  @param check: '0' don't check for ping executable, '1' check for ping executable
#  @param wait: time to wait before process is started
def _start_ping(c, counter='1', file_prefix='', remote_dir='', dest='',
                duration='', rate='1', extra_params='', check='1', wait=''):

    if check == '1':
        # make sure we have ping
        run('which ping', pty=False)

    # get host type
    htype = get_type_cached(c.host)
    logfile = f"{remote_dir}{file_prefix}_{c.host.replace(':', '_')}_{counter}_ping.log"

    if htype == 'CYGWIN':
        ping_cmd = 'ping -n %s' % duration
        # windows ping does not support setting the rate
        if rate != '1':
            print(
                'windows ping does not support setting the rate, using rate=1')
    else:
        count = str(int(round(float(duration) * float(rate), 0)))
        ping_cmd = f'ping -c {count}'
        if rate != '1':
            interval = str(round(1 / float(rate), 3))
            ping_cmd += f' -i {interval}'

    if extra_params != '':
        ping_cmd += f' {extra_params}'

    ping_cmd += ' {dest}'
    pid = runbg(c, ping_cmd, wait, out_file=logfile)
    bgproc.register_proc(c.host, 'ping', counter, pid, logfile)


## Start ping wrapper
#  @param counter Unique ID
#  @param file_prefix File prefix for log file (iperf server output)
#  @param remote_dir Directory to create log file in
#  @param local_dir Unused
#  @param client Host to run ping on
#  @param dest Target to ping
#  @param duration Duration in seconds
#  @param rate Number of pings per second
#  @param extra_params Other parameters passed directly to ping
#  @param check: '0' don't check for ping executable, '1' check for ping executable
#  @param wait: time to wait before process is started
def start_ping(c, counter='1', file_prefix='', remote_dir='', local_dir='',
               client='', dest='', duration='', rate='1', extra_params='',
               check='1', wait=''):
    "Start ping"

    if client == '':
        raise ValueError('Must specify client')
    if dest == "":
        raise ValueError("Must specify destination")

    client, dummy = get_address_pair(client)
    dummy, dest_internal = get_address_pair(dest)
    _start_ping(c,
        counter,
        file_prefix,
        remote_dir,
        dest_internal,
        duration,
        rate,
        extra_params,
        check,
        wait,
        hosts=[client])


#
# httperf
#


## Return default document root depending on host OS
#  @param htype Host type string
def _get_document_root(htype):
    if htype == 'FreeBSD':
        docroot = '/usr/local/www/data'
    elif htype == 'Darwin':
        docroot = '/opt/local/www/htdocs'
    else:
        docroot = '/srv/www/htdocs'

    return docroot


## Start lighttpd web server
#  @param counter Unique ID
#  @param file_prefix File prefix for log file (iperf server output)
#  @param remote_dir Directory to create log file in
#  @param local_dir Local directory to put files in
#  @param port Port to listen to
#  @param config_dir Directory that contains config file
#  @param config_in Config file template to use
#  @param docroot Document root on server
#  @param check If '0' don't check for lighttpd executable, if '1' check for 
#               lighttpd executable
#  @param wait: time to wait before process is started
def _start_http_server(c, counter='1', file_prefix='', remote_dir='',
                       local_dir='', port='', config_dir='', config_in='',
                       docroot='', check='1'):
    global config

    if port == "":
        raise ValueError("Must specify port")

    if check == '1':
             # make sure we have lighttpd
        run('which lighttpd', pty=False)

    # get host type
    htype = get_type_cached(c.host)

    # automatic config if not specified explicitely
    if config_dir == '':
        if htype == 'FreeBSD':
            config_dir = '/usr/local/etc/lighttpd'
        elif htype == 'Darwin':
            config_dir = '/opt/local/etc/lighttpd'
        else:
            config_dir = '/etc/lighttpd'
    if config_in == '':
        config_in = config.TPCONF_script_path + \
            '/lighttpd_' + htype + '.conf.in'
    if docroot == '':
        docroot = _get_document_root(htype)

    # start server
    logfile = f"{file_prefix}_{c.host.replace(':', '_')}_{counter}_access.log"
    # XXX currently we overwrite the main config file if we start multiple
    # servers
    config_file_remote = config_dir + '/lighttpd.conf'
    config_file = f"{local_dir}/{file_prefix}_{c.host.replace(':', '_')}_{counter}_lighttpd.conf"
    docroot_sed = docroot.replace("/", "\/")
    pid_file = f"/{file_prefix}_{c.host.replace(':', '_')}_{counter}_lighttpd.pid"
    pid_file_sed = pid_file.replace("/", "\/")
    run(f"sed -e 's/@SERVER_PORT@/{port}/' "
        f"-e 's/@DOCUMENT_ROOT@/{docroot_sed}/' "
        f"-e 's/@ACCESS_LOG_NAME@/{logfile}/' "
        f"-e 's/@PID_FILE@/{pid_file_sed}/' {config_in} > {config_file}")

    logdir = c.local(f"grep '^var.log_root' {config_file}", capture=True).split()[-1].strip('"')
    logfile = f"{logdir}/{logfile}"
    statedir = c.local(f"grep '^var.state_dir' {config_file}", capture=True).split()[-1].strip('"')

    # Ensure directories exist
    run(f'mkdir -p {logdir}')
    run(f'mkdir -p {docroot}')

    c.put(config_file, config_file_remote)
    run(f'gzip {config_file}')
    run(f'rm -f {logfile}')


    # generate dummy /index.html
    run(f'cd {docroot} && dd if=/dev/zero of=index.html bs=1024 count=1')

    if htype == 'FreeBSD' or htype == 'Linux' or htype == 'Darwin':
        run(f'lighttpd -f {config_file_remote} ; sleep 0.1')
    elif htype == "CYGWIN":
         run('/usr/sbin/lighttpd -f %{config_file_remote} ; sleep 0.1')

    pid = run(f'cat {statedir}{pid_file}')
    # currently we only download the access.log, but not the error.log
    bgproc.register_proc(c.host, 'lighttpd', counter, pid, logfile)


## Start lighttpd web server wrapper
#  @param counter Unique ID
#  @param file_prefix File prefix for log file (iperf server output)
#  @param remote_dir Directory to create log file in
#  @param server Server host 
#  @param local_dir Directory to create log file in
#  @param local_dir Local directory to put files in
#  @param port Port to listen to
#  @param config_dir Directory that contains config file
#  @param config_in Config file template to use
#  @param docroot Document root on server
#  @param check If '0' don't check for lighttpd executable, if '1' check for 
#               lighttpd executable
#  @param wait: time to wait before process is started
def start_http_server(c, counter='1', file_prefix='', remote_dir='', local_dir='',
                      server='', port='', config_dir='', config_in='', docroot='',
                      check='1', wait=''):
    "Start HTTP server"

    if server == '':
        raise ValueError('Must specify server')
    server, dummy = get_address_pair(server)
    _start_http_server(c,
        counter,
        file_prefix,
        remote_dir,
        local_dir,
        port,
        config_dir,
        config_in,
        docroot,
        check,
        hosts=[server])


## Create DASH content on web server
#  @param counter Unique ID
#  @param file_prefix File prefix for log file (iperf server output)
#  @param local_dir Local directory to put files in
#  @param docroot Document root on server
#  @param duration Duration of 'video' files in seconds
#  @param rates Comma-separated list of 'video' rates
#  @param cycles Comma-separated list of cycle times
def _create_http_dash_content(c,
        counter='1', file_prefix='', local_dir='', docroot='', duration='',
        rates='', cycles=''):
    "Create dummy video chunks"

    # get host type
    htype = get_type_cached(c.host)

    if docroot == '':
        docroot = _get_document_root(htype)

    # make a copy of script and set parameters
    script_in = config.TPCONF_script_path + '/generate_http_content.sh.in'
    script_file = file_prefix + '_generate_http_content.sh'
    script_file_local = local_dir + '/' + script_file
    cycles = cycles.replace(',', ' ')
    rates = rates.replace(',', ' ')
    run(f"sed -e 's/@PERIODS@/{cycles}/' "
        f"-e 's/@BRATES@/{rates}/' "
        f"-e 's/@DURATION@/{duration}/' {script_in} > {script_file_local}")
    # upload, run script, remove script
    c.put(script_file_local, docroot)
    run(f'chmod a+x {docroot}/{script_file}')
    run(f'cd {docroot} && ./{script_file} && rm -f {script_file}')


## Create DASH content on web server wrapper
#  @param counter Unique ID
#  @param file_prefix File prefix for log file (iperf server output)
#  @param remote_dir Not used, only for symmetry with the other functions
#  @param local_dir Local directory to put files in
#  @param server Host to run server on
#  @param docroot Document root on server
#  @param duration Duration of 'video' files in seconds
#  @param rates Comma-separated list of 'video' rates
#  @param cycles Comma-separated list of cycle times
#  @param check Not used, only for symmetry with the other functions
#  @param wait Not used, only for symmetry with the other functions
def create_http_dash_content(c,
        counter='1', file_prefix='', remote_dir='', local_dir='',
        server='', docroot='', duration='', rates='', cycles='',
        check='1', wait=''):
    "Setup content for DASH on HTTP server"

    if server == '':
        raise ValueError('Must specify server')
    server, dummy = get_address_pair(server)
    _create_http_dash_content(c,
        counter,
        file_prefix,
        local_dir,
        docroot,
        duration,
        rates,
        cycles,
        hosts=[server])


## Create incast content on web server
#  @param counter Unique ID
#  @param file_prefix File prefix for log file (iperf server output)
#  @param local_dir Local directory to put files in
#  @param docroot Document root on server
#  @param duration Not used
#  @param sizes Comma-separated list of file sizes
def _create_http_incast_content(c,
        counter='1', file_prefix='', local_dir='', docroot='', duration='',
        sizes=''):
    "Create dummy content"

    # get host type
    htype = get_type_cached(c.host)

    if docroot == '':
        docroot = _get_document_root(htype)

    # make a copy of script and set parameters
    script_in = config.TPCONF_script_path + \
        '/generate_http_incast_content.sh.in'
    script_file = file_prefix + '_generate_http_incast_content.sh'
    script_file_local = local_dir + '/' + script_file
    sizes = sizes.replace(',', ' ')
    #duration = duration.replace(',', ' ')
    run(f'cat {script_in} | sed -e "s/@SIZES@/{sizes}/" > {script_file_local}')
    # upload, run script, remove script
    c.put(script_file_local, docroot)
    run(f'chmod a+x {docroot}/{script_file}')
    run(f'cd {docroot} && ./{script_file} && rm -f {script_file}')



## Create incast content on web server wrapper
#  @param counter Unique ID
#  @param file_prefix File prefix for log file (iperf server output)
#  @param remote_dir Not used, only for symmetry with the other functions
#  @param local_dir Local directory to put files in
#  @param server Host to run server on
#  @param docroot Document root on server
#  @param duration Not used
#  @param sizes Comma-separated list of file sizes
#  @param check Not used, only for symmetry with the other functions
#  @param wait Not used, only for symmetry with the other functions
def create_http_incast_content(c,
        counter='1', file_prefix='', remote_dir='',
        local_dir='', server='', docroot='', duration='', sizes='', check='1',
        wait=''):
    "Setup content for DASH on HTTP server"

    if server == '':
        raise ValueError('Must specify server')
    server, dummy = get_address_pair(server)
    _create_http_incast_content(c,
        counter,
        file_prefix,
        local_dir,
        docroot,
        duration,
        sizes,
        hosts=[server])


## Start httperf
#  @param counter Unique ID
#  @param file_prefix File prefix for log file (iperf server output)
#  @param remote_dir Directory to create log file in
#  @param port Server port
#  @param server Server host
#  @param conns Number of connections
#  @param rate Connections per second
#  @param timeout Timeout for each connection
#  @param calls Number of calls
#  @param burst Length of burst
#  @param wsesslog Session description (requests to send)
#  @param wsesslog_timeout Default timeout for session in wsesslog
#  @param period Time between sessions/bursts
#  @param sessions Number of sessions
#  @param call_stats Maximum number of slots for call_stats
#                    (one usef for each request)
#  @param extra_params Extra parameters
#  @param check If '0' don't check for ping executable,
#               if '1' check for ping executable
#  @param wait Time to wait before process is started
def _start_httperf(c, counter='1', name='httperf', file_prefix='', remote_dir='',
                   port='80', server='', conns='', rate='', timeout='',
                   calls='', burst='', wsesslog='', wsesslog_timeout='0',
                   period='', sessions='1', call_stats=1000, extra_params='',
                   check='1', wait=''):

    if check == '1':
        # make sure we have httperf
        run('which httperf', pty=False)

    # set it to high value just in case...
    if call_stats < 1000:
        call_stats = 1000

    logfile = remote_dir + file_prefix + '_' + \
        c.host + '_' + counter + '_' + name + '.log'

    # set send and receive buffer to higher than default
    # need to set --call-stats (number of slots for stats),
    # otherwise the pace_time in wsesslog does not work properly
    # (without --call-stats>0 pace_time is basically the same as think)
    # also with call-stats>0 we get detailed statistics about each call/request
    # NOTE: setting send-buffer or recv-buffer to 2MB causes httperf to not
    #       run properly and finally crash on FreeBSD!
    #       also the whole FreeBSD machine becomes unresponsive!
    httperf_cmd = f'httperf --send-buffer=65536 --recv-buffer=1048576 --call-stats={call_stats}'

    if server != '':
        httperf_cmd += f' --server {server} --port {port}'
    if conns != '':
        httperf_cmd += f' --num-conns {conns}'
    if rate != '':
        httperf_cmd += f' --rate {rate}'
    if timeout != '':
        httperf_cmd += f' --timeout {timeout}'
    if calls != '':
        httperf_cmd += f' --num-calls {calls}'
    if burst != '':
        httperf_cmd += f' --burst-length {burst}'
    if period != '':
        httperf_cmd += f' --period={period}'
    if wsesslog != '':
        # use set --retry-on-failure to avoid new connection in case of failure
        # (we should only have transient failures)
        httperf_cmd += f' --wsesslog {sessions},
                {wsesslog_timeout},{wsesslog} --retry-on-failure'
    if extra_params != '':
        httperf_cmd += ' ' + extra_params

    pid = runbg(httperf_cmd, wait, out_file=logfile)
    bgproc.register_proc(c.host, name, counter, pid, logfile)


## Start httperf wrapper
#  @param counter Unique ID
#  @param file_prefix File prefix for log file (iperf server output)
#  @param remote_dir Directory to create log file in
#  @param local_dir Local directory to put files in (not used)
#  @param port Server port
#  @param client Client host
#  @param server Server host
#  @param conns Number of connections
#  @param rate Connections per second
#  @param timeout Timeout for each connection
#  @param calls Number of calls
#  @param burst Length of burst
#  @param wsesslog Session description (requests to send)
#  @param wsesslog_timeout Default timeout for session in wsesslog
#  @param period Time between sessions/bursts
#  @param sessions Number of sessions
#  @param extra_params Extra parameters
#  @param check If '0' don't check for ping executable,
#               if '1' check for ping executable
#  @param wait Time to wait before process is started
def start_httperf(c, counter='1', file_prefix='', remote_dir='', local_dir='', port='',
                  client='', server='', conns='', rate='', timeout='', calls='',
                  burst='', wsesslog='', wsesslog_timeout='', period='', sessions='1',
                  extra_params='', check='1', wait=''):
    "Start httperf on client"

    if client == '':
        raise ValueError('Must specify client')
    if server == "":
        raise ValueError("Must specify server")

    client, dummy = get_address_pair(client)
    dummy, server_internal = get_address_pair(server)
    _start_httperf(c, counter=counter, name='httperf', file_prefix=file_prefix,
            remote_dir=remote_dir, port=port, server=server_internal,
            conns=conns, rate=rate, timeout=timeout, calls=calls, burst=burst,
            wsesslog=wsesslog, wsesslog_timeout=wsesslog_timeout,
            period=period, sessions=sessions, call_stats=1000,
            extra_params=extra_params, check=check, wait=wait, hosts=[client])


## Start httperf DASH-like client
#  @param counter Unique ID
#  @param file_prefix File prefix for log file (iperf server output)
#  @param remote_dir Directory to create log file in
#  @param local_dir Local directory to put files in
#  @param port Server port
#  @param server Server host
#  @param duration Duration of session in seconds
#  @param rate DASH rate in kbps
#  @param cycle Cycle length in seconds
#  @param prefetch Prefetch time in seconds of 'content' to prefetch
#                  (specified as float) (default = 0.0)
#  @param prefetch_timeout Timeout during prefetch phase
#  @param extra_params Extra parameters
#  @param with_timeout '0' no timeouts for requests (default),
#                      '1' with timeouts for request (httperf will close connection 
#                          if timeout expires and end session)
#  @param check '0' don't check for ping executable, '1' check for ping executable
#  @param wait Time to wait before process is started
def _start_httperf_dash(c,
        counter='1', file_prefix='', remote_dir='', local_dir='',
        port='', server='', duration='', rate='', cycle='', prefetch='0.0',
        prefetch_timeout='', extra_params='', with_timeout='0',
        check='1', wait=''):

    # generate session log
    spath = f"/video_files-{cycle}-{rate}"
    wlog = f"{file_prefix}_{c.host}_{counter}_wlog.log"
    wlog_local = local_dir + '/' + wlog
    cpath = "/tmp/" + wlog

    # determine number of requests dpeending on duration and cycle length
    # round down to nearest integer, so the actual duration may be up to a cycle
    # shorter then duration (it must kept shorter than duration to collect
    # httperf log file)
    play_cnt = int(float(duration) / float(cycle))

    # with timeout for chplay chunk fetching, allow for a tiny bit of slack 
    # with the cycles by multiplying with 1.01
    play_timeout = str(float(cycle) * 1.01)
    
    # now determine size of play chunk in bytes
    play_chunk_size = str(float(cycle) * float(rate) * 1000 / 8)

    run('rm -f  {wlog_local}; touch {wlog_local}')

    if float(prefetch) > 60.0:
        raise ValueError('Prefetch time cannot be more than 60 seconds')

    if float(prefetch) > 0.0:
        prefetch_last_byte = str(
            int(float(prefetch) * float(rate) * 1000 / 8) - 1)
        prefetch_chunk_size = str(float(prefetch) * float(rate) * 1000 / 8)
        if prefetch_timeout == '':
            prefetch_timeout = play_timeout

        if with_timeout == '1':
            c.local(
                'echo {}/0 size={} pace_time=0 timeout={} headers=\'Range: '
                'bytes=0-{}\' >> {}'.format
                (spath,
                 prefetch_chunk_size,
                 prefetch_timeout,
                 prefetch_last_byte,
                 wlog_local))
        else:
            c.local(
                'echo {}/0 size={} pace_time=0 headers=\'Range: '
                'bytes=0-{}\' >> {}'.format
                (spath, prefetch_chunk_size, prefetch_last_byte, wlog_local))

        # adjust the number of bursts
        play_cnt = int(
            (float(duration) -
             float(prefetch_timeout)) /
            float(cycle))

    calls = 1
    for i in range(play_cnt):
        if with_timeout == '1':
            c.local(f"echo {spath}/{calls} size={play_chunk_size} 
                pace_time={cycle} timeout={play_timeout} >> {wlog_local}")
        else:
            c.local(f"echo {spath}/{calls} size={play_chunk_size} 
            pace_time={cycle} >> {wlog_local}")

        calls += 1

    # upload to client
    c.put(wlog_local, cpath)
    # gzip local copy
    c.local(f"gzip {wlog_local}")

    # start httperf
    _start_httperf(c, counter=counter, name='httperf_dash',
            file_prefix=file_prefix, remote_dir=remote_dir, port=port,
            server=server, wsesslog=cpath, period=0.000001,
            wsesslog_timeout=play_timeout, call_stats=calls,
            extra_params=extra_params, check=check, wait=wait)


## Start httperf DASH-like client wrapper
#  @param counter Unique ID
#  @param file_prefix File prefix for log file (iperf server output)
#  @param remote_dir Directory to create log file in
#  @param local_dir Local directory to put files in
#  @param port Server port
#  @param client Client host
#  @param server Server host
#  @param duration Duration of session in seconds
#  @param rate DASH rate in kbps
#  @param cycle Cycle length in seconds
#  @param prefetch Prefetch time in seconds of 'content' to prefetch
#                  (specified as float) (default = 0.0)
#  @param prefetch_timeout Timeout during prefetch phase
#  @param extra_params Extra parameters
#  @param with_timeout '0' no timeouts for requests (default),
#                      '1' with timeouts for request (httperf will close connection 
#                          if timeout expires and start a new connection)
#  @param check '0' don't check for ping executable, '1' check for ping executable
#  @param wait Time to wait before process is started
def start_httperf_dash(c, counter='1', file_prefix='', remote_dir='', local_dir='',
                       port='', client='', server='', duration='', rate='', cycle='',
                       prefetch='', prefetch_timeout='', extra_params='',
                       with_timeout='0', check='1', wait=''):
    "Start httperf DASH client"

    if client == "":
        raise ValueError("Must specify client")

    client, dummy = get_address_pair(client)
    dummy, server_internal = get_address_pair(server)
    _start_httperf_dash(c, counter, file_prefix, remote_dir, local_dir, port,
            server_internal, duration, rate, cycle, prefetch, prefetch_timeout,
            extra_params, with_timeout, check, wait, hosts=[client])


## Start httperf incast congestion querier
#  @param counter Unique ID
#  @param file_prefix File prefix for log file (iperf server output)
#  @param remote_dir Directory to create log file in
#  @param local_dir Local directory to put files in
#  @param servers Comma-separated list of servers
#                 (server1:port1,server2:port2,...,serverN:portN)
#  @param duration Duration of session in seconds
#  @param period Time between queries
#  @param burst_size Number of queries to send to each server
#  @param response_size Size of the response in kB
#  @param extra_params Extra parameters
#  @param check: '0' don't check for ping executable, '1' check for ping executable
#  @param wait: time to wait before process is started
def _start_httperf_incast(c,
        counter='1', file_prefix='', remote_dir='', local_dir='', servers='',
        duration='', period='', burst_size='', response_size='', extra_params='',
        check='1', wait=''):

    # generate session log
    spath = '/incast_files-%s' % (response_size)
    wlog = f'{file_prefix}_{c.host}_{counter}_wlog.log'
    wlog_local = local_dir + '/' + wlog
    cpath = '/tmp/' + wlog

    request_cnt = int(float(duration) / float(period))
    if burst_size == '':
        burst_size = '1'
    burst_cnt = int(burst_size) - 1

    c.local(f'rm -f {wlog_local} ; touch {wlog_local}')

    sessions = 0
    calls = 0
    for server in servers.split(','):
        server, port = server.split(':')
        # remove leading/trailing whitespaces
        server = server.strip()
        port = port.strip()
        # get internal address
        dummy, server_internal = get_address_pair(server)

        c.local(
            f'echo session server={server_internal} port={port} >> 
            {wlog_local}')
        for i in range(request_cnt):
            for j in range(burst_cnt):
                c.local(
                f'echo {spath}/1 pace_time=0 timeout={period} >> {wlog_local}')
                calls += 1

            _period = float(period)
            # if sessions == 0 and i == 0:
            if sessions == 0:
                # add 1ms from time for first server to better synchronise the 2-N bursts
                # for some reason there is a larger gap between first
                # server/session and the rest while the other session/servers
                # are well synchronised
                _period += 0.001

            c.local(f'echo {spath}/1 pace_time={_period:.6f} timeout={_period:.6f} >> {wlog_local}')
            calls += 1

        c.local(f'echo \' \' >> {wlog_local}')
        sessions += 1

    # upload to client
    c.put(wlog_local, cpath)
    # gzip local copy
    c.local(f'gzip {wlog_local}')

    # start httperf
    _start_httperf(c, counter=counter, name='httperf_incast',
            file_prefix=file_prefix, remote_dir=remote_dir, port='', server='',
            wsesslog=cpath, period=0.000001, sessions=sessions, call_stats=calls,
            extra_params=extra_params, check=check, wait=wait)


## Start httperf incast congestion querier wrapper
#  @param counter Unique ID
#  @param file_prefix File prefix for log file (iperf server output)
#  @param remote_dir Directory to create log file in
#  @param local_dir Local directory to put files in
#  @param client Client host
#  @param servers Comma-separated list of servers
#                 (server1:port1,server2:port2,...,serverN:portN)
#  @param duration Duration of session in seconds
#  @param period Time between queries
#  @param burst_size Number of queries to send to each server
#  @param response_size Size of the response in kB
#  @param extra_params Extra parameters
#  @param check: '0' don't check for ping executable, '1' check for ping executable
#  @param wait: time to wait before process is started
def start_httperf_incast(c,
        counter='1', file_prefix='', remote_dir='', local_dir='', client='', servers='',
        duration='', period='', burst_size='', response_size='', extra_params='',
        check='1', wait=''):
    "Start httperf incast congestion client"

    if client == "":
        raise ValueError("Must specify client")

    client, dummy = get_address_pair(client)
    _start_httperf_incast(c,
        counter,
        file_prefix,
        remote_dir,
        local_dir,
        servers,
        duration,
        period,
        burst_size,
        response_size,
        extra_params,
        check,
        wait,
        hosts=[client])


## Start incast with n responders
#  @param counter Unique start ID
#  @param file_prefix File prefix for log file (iperf server output)
#  @param remote_dir Directory to create log file in
#  @param local_dir Local directory to put files in
#  @param client Client host
#  @param servers Comma-separated list of servers
#                 (server1:port1,server2:port2,...,serverN:portN)
#  @param duration Duration of session in seconds
#  @param period Time between queries
#  @param burst_size Number of queries to send to each server
#  @param response_size Size of the response in kB
#  @param server_port_start first server port to use, each server will run on different
#                           consecutive port starting with this port number
#  @param config_dir Directory that contains config file
#  @param config_in Config file template to use
#  @param docroot Document root on server
#  @param sizes Comma-separated list of file sizes on server
#  @param num_responders Number of responders actually used
#  @param extra_params Extra parameters
#  @param check: '0' don't check for ping executable, '1' check for ping executable
#  @param wait: time to wait before process is started
def start_httperf_incast_n(c,
        counter='1', file_prefix='', remote_dir='', local_dir='', client='', servers='',
        duration='', period='', burst_size='', response_size='', server_port_start='', 
        config_dir='', config_in='', docroot='', sizes='', num_responders='',
        extra_params='', check='1', wait=''):
    "Start httperf incast scenario with q querier and n responders"

    if client == "":
        raise ValueError("Must specify client")
    if servers == '':
        raise ValueError('Must specify servers')

    # convert to int to we can increment it
    counter = int(counter)

    num_responders_int = int(num_responders)
    servers_list = servers.split(',')
    if num_responders_int < 1:
        raise ValueError('num_responders must be at least 1')
    if num_responders_int > len(servers_list):
        raise ValueError('num_responders cannot exceed number of servers specified with servers')

    servers_list = servers_list[0:num_responders_int] 
    client_servers_list = [] # for client

    # start all servers
    port = int(server_port_start)
    for server in servers_list:
        server, dummy = get_address_pair(server)

        client_servers_list.append(server + ':' + str(port))

        _start_http_server(c,
            str(counter),
            file_prefix,
            remote_dir,
            local_dir,
            str(port),
            config_dir,
            config_in,
            docroot,
            check,
            hosts=[server])

        counter += 1
        port += 1

    # wait for servers to come up
    time.sleep(0.5)

    # create content on all servers
    for server in servers_list:
        server, dummy = get_address_pair(server)

        _create_http_incast_content(c,
            str(counter),
            file_prefix,
            local_dir,
            docroot,
            duration,
            sizes,
            hosts=[server])

        counter += 1

    # start client/querier
    client, dummy = get_address_pair(client)
    _start_httperf_incast(c,
        str(counter),
        file_prefix,
        remote_dir,
        local_dir,
        ','.join(client_servers_list),
        duration,
        period,
        burst_size,
        response_size,
        extra_params,
        check,
        wait,
        hosts=[client])


## Start broadcast ping for post timestamp correction
## Router does the broadcast as control host in jail may not be able to
## Broadcast on the control subnet, so we don't interfere with data traffic
#  @param file_prefix File prefix for log file (iperf server output)
#  @param remote_dir Directory to create log file in
#  @param local_dir Local directory to put files in
#  @param bc_addr Broadcast or multicast address
#  @param rate Number of pings per second
#  @param use_multicast Empty string means use broadcast address (default), 
#                       otherwise must set this to IP of the outgoing interface 
def start_bc_ping(c, file_prefix='', remote_dir='', local_dir='', bc_addr='', 
                  rate='1', use_multicast=''):
    "Start broadcast ping"

    if bc_addr == '':
        raise ValueError('Must specify broadcast address')

    # get host type
    htype = get_type_cached(c.host)

    name = 'bc_ping'
    logfile = f"{remote_dir}{file_prefix}_{c.host_string}_{name}.log"

    # use stdbuf to turn off buffering of output
    # set size to 56 bytes (+ 8bytes header), this should be the default anyway
    ping_cmd = 'stdbuf -o0 -e0 ping -s 56'
    if use_multicast == '' and htype == 'Linux':
        ping_cmd += ' -b' # must explicitely set broadcast
    if use_multicast != '':
        ping_cmd += f' -I {use_multicast}'
    if rate != '1':
        interval = str(round(1 / float(rate), 3))
        ping_cmd += f' -i {interval}'
    ping_cmd += f' {bc_addr}'

    pid = runbg(ping_cmd, '0.0', out_file=logfile)
    bgproc.register_proc(c.host, name, '0', pid, logfile)


## Start server-to-client single traffic flow with BITSS pktgen
#  @param counter Unique ID
#  @param file_prefix File prefix for log file (iperf server output)
#  @param remote_dir Directory to create log file in
#  @param local_dir Local directory to put files in
#  @param game_type Set to q3, hl2cs, hl2dm, hlcs, hldm, et2pro or q4
#  @param client_num Emulate traffic of a game with this many clients
#  @param port Client port
#  @param src_port Server port
#  @param client Client IP or name
#  @param pkt_interval Packet interval in seconds
#  @param duration Duration of traffic in seconds
#  @param extra_params Extra params to be set
#  @param check '0' don't check for pktgen executable,
#              '1' check for pktgen executable
#  @param wait Time to wait before process is started
def _start_s2c_game(c, counter='', file_prefix='', remote_dir='', local_dir='', 
                game_type='q3', client_num='', port='', src_port='', client='', 
                pkt_interval='0.05', duration='', extra_params='', check='1', wait=''):
    "Start s2c game traffic flow"

    if client_num == '':
        raise ValueError('Must specify number of clients with client_num')
    if client == '':
        raise ValueError('Must specify client')
    if port == '':
        raise ValueError('Must specify port')

    if check == '1':
        # make sure we have pktgen 
        run('which pktgen.sh', pty=False)

    # get client's internal address
    dummy, client_internal = get_address_pair(client) 

    # start pktgen 
    logfile = f"{remote_dir}{file_prefix}_{c.host.replace(':', '_')}_{counter}_pktgen.log"
    pktgen_cmd =  f"pktgen.sh -w -game {game_type} -N {client_num} -IP {client_internal} -port 
                  {port} -sport {src_port} -iat {pkt_interval} -secs {duration}"
    if extra_params != '':
        pktgen_cmd += ' ' + extra_params

    pid = runbg(pktgen_cmd, wait, out_file=logfile)
    bgproc.register_proc(c.host, 'pktgen', counter, pid, logfile)


## Start client-to-server single traffic flow with BITSS pktgen
#  @param counter Unique ID
#  @param file_prefix File prefix for log file (iperf server output)
#  @param remote_dir Directory to create log file in
#  @param local_dir Local directory to put files in
#  @param game_type Set to q3, hl2cs, hl2dm, hlcs, hldm, et2pro or q4
#  @param client_num Total number of clients
#  @param port Client port
#  @param src_port Server port
#  @param server Client IP or name
#  @param pkt_interval Packet interval in seconds
#  @param psize Packet size in bytes
#  @param duration Duration of traffic in seconds
#  @param extra_params Extra params to be set
#  @param check '0' don't check for pktgen executable,
#               '1' check for pktgen executable
#  @param wait Time to wait before process is started
def _start_c2s_game(c, counter='', file_prefix='', remote_dir='', local_dir='', 
                game_type='q3', client_num='', port='', src_port='', server='', 
                pkt_interval='0.05', psize='60', duration='', extra_params='', 
                check='1', wait=''):
    "Start c2s game traffic flow"

    if client_num == '':
        raise ValueError('Must specify number of clients with client_num')
    if server == '':
        raise ValueError('Must specify server')
    if port == '':
        raise ValueError('Must specify port')

    if check == '1':
        # make sure we have pktgen 
        run('which pktgen.sh', pty=False)

    # get client's internal address
    dummy, server_internal = get_address_pair(server)

    # start pktgen 
    logfile = f"{remote_dir}{file_prefix}_{c.host.replace(':', '_')}_{counter}_pktgen.log"
    pktgen_cmd = (f"pktgen.sh -c -game {game_type} -N {client_num} -IP {server_internal} "
               f"-port {port} -sport {src_port} -iat {pkt_interval} -secs {duration} "
               f"-c2s_psize {psize}")
    if extra_params != '':
        pktgen_cmd += ' ' + extra_params

    pid = runbg(pktgen_cmd, wait, out_file=logfile)
    bgproc.register_proc(c.host, 'pktgen', counter, pid, logfile)


## Start emulated FPS game traffic session using pktgen 0.3.1 or later
## from http://caia.swin.edu.au/bitss
##
## Server side is emulated with one instance of pktgen in server mode per client end point
## in TEACUP testbed. The actual traffic emitted by pktgen can be set to correspond to a game
## having more clients than actually exist in the testbed (e.g. to emulate the N client game
## traffic that would be seen by one client, without needing N actual client machines.)
## 
## For client to server traffic we run pktgen in client mode, which currently (pktgen 0.3.1)
## produces not very realistic, simplified UDP packet stream back to the server)
##
#  @param counter Unique ID start
#  @param file_prefix File prefix for log file (iperf server output)
#  @param remote_dir Directory to create log file in
#  @param local_dir Local directory to put files in
#  @param clients Comma-separated list of clients (name|IP:port) 
#  @param server Server (name|IP:port) 
#  @param game_type Set to q3, hl2cs, hl2dm, hlcs, hldm, et2pro or q4
#  @param c2s_interval Interval of client to server packets in seconds 
#  @param c2s_psize Packet size of client to server packets in bytes
#                   (size of UDP data)
#  @param s2c_interval Interval of server to client packets in seconds 
#  @param duration Duration of game in seconds
#  @param client_start_delay Number of seconds clients are started after servers
#                            are started
#  @param extra_params_client Extra params to be set for clients
#  @param extra_params_server Extra params to be set for server 
#  @param check '0' don't check for executable,
#               '1' check for executable
#  @param wait Time to wait before process is started
#  @param noclients_game    Emulate server to client traffic of this many clients, or
#               number of clients in 'clients' parameter if not set (hsnguyen@swin.edu.au)

def start_fps_game(c, counter='', file_prefix='', remote_dir='', local_dir='', clients='',
                  server='', game_type='q3', c2s_interval='0.01', c2s_psize='60',
		  s2c_interval='0.05', duration='', client_start_delay='3.0',
                  extra_params_client='', extra_params_server='', check='1', wait='', noclients_game=''):
    "Start FPS game traffic using pktgen from http://caia.swin.edu.au/bitss"

    if clients == '':
        raise ValueError('Must specify at least one client with clients')
    if server == '':
        raise ValueError('Must specify server')

    counter = int(counter)

    fields = server.split(':')
    server_name = fields[0]
    server_port = '27960' # not used yet
    if len(fields) > 1:
        server_port = fields[1]

    clients_list = clients.split(',')
    
    if noclients_game == '':
        noclients_game = str(len(clients_list))

    # make sure number of clients is within pktgen's allowed range
    if int(noclients_game) < 4 or int(noclients_game) > 32:
       raise ValueError('Number of clients must be between 4 and 32')

    for client in clients_list:
        fields = client.split(':')
        client_name = fields[0]
        client_port = '27960' 
        if len(fields) > 1:
            client_port = fields[1]

        # start s2c traffic
        _start_s2c_game(c,
                counter=str(counter),
                file_prefix=file_prefix,
                remote_dir=remote_dir,
                local_dir=local_dir,
                game_type=game_type,
                client_num=noclients_game,
                port=client_port,
                src_port=server_port,
                #src_port=client_port,
                client=client_name,
                pkt_interval=s2c_interval,
                duration=duration,
                extra_params=extra_params_server,
                check=check,
                # randomise the start times a bit
                wait=str(float(wait) + random.random()/25),
                hosts=[server_name])
                     
        counter += 1

    for client in clients_list:
        fields = client.split(':')
        client_name = fields[0]
        client_port = '27960'
        if len(fields) > 1:
            client_port = fields[1]

        # start c2s traffic
        _start_c2s_game(c,
                counter=str(counter),
                file_prefix=file_prefix,
                remote_dir=remote_dir,
                local_dir=local_dir,
                game_type=game_type,
                client_num=noclients_game,
                port=server_port,
                #port=client_port,
                src_port=client_port,
                server=server_name,
                pkt_interval=c2s_interval,
                psize=c2s_psize,
                duration=duration,
                extra_params=extra_params_client,
                check=check,
                # delay client start to make sure server is started first
                # (pktgen is a bit slow to start). if we see failed connections
                # increase this number!
                wait=str(float(wait) + float(client_start_delay)),
                hosts=[client_name])

        counter += 1

## Start DASH streaming at the client side with dash.js player in Chrome or Firefox
#  @param counter: Unique ID
#  @param file_prefix: File prefix for log file
#  @param remote_dir: Directory to create log file in
#  @param serv: IP address/hostname of DASH server
#  @param duration: Video streaming duration in seconds
#  @param wait: Time to wait before process is started
#  @param serv_port: Port number of DASH server serving the video dataset
#  @param browser: Browser in which dash.js runs (chrome, firefox)
#  @param chunk_size: Video chunk size in seconds (depending on dataset)
#  @param mpd: File name of Media Presentation Description (depending on dataset)
#  @param player_path: Path to dash.js player's index.html page

def _start_dash_streaming_dashjs(c, counter='1', file_prefix='', remote_dir='', serv='',
		duration='', rate='1', check='1', wait='', serv_port='',
		browser='chrome', chunk_size='', mpd='', player_path=''):
    "Start dash.js DASH traffic flow"
    
    htype = get_type_cached(c.host)
      
    logfile = f"{remote_dir}{file_prefix}_{c.host.replace(':', '_')}_{counter}_dash_streaming_dashjs.log"
    logfile2 = f"{remote_dir}{file_prefix}_{c.host.replace(':', '_')}_{counter}_dash_streaming_dashjs2.log"

    count = str(int(round(float(duration) * float(rate), 0)))

    xinit_filename = os.path.join(config.TPCONF_script_path, "/tmp/xinitrc_dash")
    with open(xinit_filename,"w") as xinitrc:     

        if browser == 'chrome':

            xinitrc.write(
                f"chrome --disable-web-security --incognito --user-data-dir 
                        'http://{player_path}/index.html?mpd=http://{serv}:{serv_port}/{chunk_size}sec/{mpd}'"
            )
        elif browser == 'firefox':

            xinitrc.write(f"dbus-run-session firefox -private-window
                         'http://{player_path}/index.html?mpd=http://{serv}:{serv_port}/{chunk_size}sec/{mpd}'"
            )  

        else:
            raise ValueError('Browser not supported')

    c.put(xinit_filename, '/root/.xinitrc')
    
    os.remove(xinit_filename)	    
    
    dash_streaming_cmd = 'startx'
    pid = runbg(dash_streaming_cmd, wait, out_file=logfile)
    bgproc.register_proc(c.host, 'dash_streaming_dashjs', counter, pid, logfile)

    pkill_cmd = 'pkill ' + browser
    pid = runbg(pkill_cmd, float(wait) + float(duration), out_file=logfile2)
    bgproc.register_proc(c.host, 'dash_streaming_pkill', counter, pid, logfile2)
	
## Start DASH streaming at the client side with dash.js player in Chrome or Firefox
#  @param counter: Unique ID
#  @param file_prefix: File prefix for log file
#  @param remote_dir: Directory to create log file in
#  @param client: IP address/hostname of DASH client
#  @param serv: IP address/hostname of DASH server
#  @param duration: Video streaming duration in seconds
#  @param wait: Time to wait before process is started
#  @param serv_port: Port number of DASH server serving the video dataset
#  @param browser: Browser in which dash.js runs (chrome, firefox)
#  @param chunk_size: Video chunk size in seconds (depending on dataset)
#  @param mpd: File name of Media Presentation Description (depending on dataset)
#  @param player_path: Path to dash.js player's index.html page

def start_dash_streaming_dashjs(c, counter='1', file_prefix='', remote_dir='', local_dir='', client='',
		  serv='', duration='', rate='1', check='1', wait='',serv_port='',
		  browser='chrome', chunk_size='', mpd='', player_path=''):
    "Start dash.js DASH traffic flow"
     
    if client == '':
        raise ValueError('Must specify client')
    if serv == '':
        raise ValueError('Must specify server')
    if serv_port == '':
        raise ValueError('Must specify server port')
    if chunk_size == '':
        raise ValueError('Must specify video chunk size')
    if mpd == '':
        raise ValueError('Must specify MPD')
    if player_path == '':
        raise ValueError('Must specify player path')
	
    client, dummy = get_address_pair(client)
    dummy, dest_internal = get_address_pair(serv)
    _start_dash_streaming_dashjs(c,
        counter,
        file_prefix,
        remote_dir,
        dest_internal,
        duration,
        rate,
        check,
        wait,
        serv_port,
        browser,
        chunk_size, 
        mpd,
        player_path,
        hosts=[client])

## Start nginx web server
#  @param counter Unique ID
#  @param file_prefix File prefix for log file
#  @param remote_dir Directory to create log file in
#  @param local_dir Local directory to put files in
#  @param port Port to listen to
#  @param config_dir Directory that contains config file
#  @param config_in Config file template to use
#  @param docroot Document root on server
#  @param check If '0' don't check for nginx executable, if '1' check for 
#               nginx executable
#  @param wait Time to wait before process is started
def _start_nginx_server(c, counter='1', file_prefix='', remote_dir='',
                       local_dir='', port='', config_dir='', config_in='',
                       docroot='', check='1'):
    global config

    if port == "":
        raise ValueError("Must specify port")

    if check == '1':
             # make sure we have nginx
        run('which nginx', pty=False)

    # get host type
    htype = get_type_cached(c.host)

    # automatic config if not specified explicitely
    if config_dir == '':
        if htype == 'FreeBSD':
            config_dir = '/usr/local/etc/nginx'
        elif htype == 'Darwin':
            config_dir = '/opt/local/etc/nginx'
        else:
            config_dir = '/etc/nginx'
    if config_in == '':
        config_in = config.TPCONF_script_path + \
            '/nginx_' + htype + '.conf.in'
    if docroot == '':
        docroot = _get_document_root(htype)

    # start server
    logfile = f"{file_prefix}_{c.host.replace(':', '_')}_{counter}_access.log"
    # XXX currently we overwrite the main config file if we start multiple
    # servers
    config_file_remote = config_dir + '/nginx.conf'
    config_file = f"{local_dir}/{file_prefix}_{c.host.replace(':', '_')}_{counter}_nginx.conf"
    docroot_sed = docroot.replace("/", "\/")
    pid_file = f"/{file_prefix}_{c.host.replace(':', '_')}_{counter}_nginx.pid"
    pid_file_sed = pid_file.replace("/", "\/")
    c.local('cat %s | sed -e "s/@SERVER_PORT@/%s/" | '
    'sed -e "s/@DOCUMENT_ROOT@/%s/" | '
    'sed -e "s/@ACCESS_LOG_NAME@/%s/" | '
    'sed -e "s/@PID_FILE@/%s/" > %s' %
    (config_in, port, docroot_sed, logfile, pid_file_sed, config_file))
    
    # Statically set logdir and statedir location
    logdir = "/var/log/nginx"
    logfile = logdir + "/" + logfile
    statedir = "/var/run"
    
    run(f'mkdir -p {logdir}', pty=False)
    run(f'mkdir -p {docroot}', pty=False, warn=True)
    c.put(config_file, config_file_remote)
    c.local(f'gzip {config_file}')
    run(f'rm -f {logfile}', pty=False)

    # generate dummy /index.html
    run(f'cd {docroot} && dd if=/dev/zero of=index.html bs=1024 count=1', pty=False)

    if htype == 'FreeBSD' or htype == 'Linux' or htype == 'Darwin':
        run(f'nginx -c {config_file_remote} ; sleep 0.1')
    elif htype == "CYGWIN":
        run(f'/usr/sbin/nginx -c {config_file_remote} ; sleep 0.1', pty=False)


    pid = run(f'cat {statedir}{pid_file}', pty=False)
    # currently we only download the access.log, but not the error.log
    bgproc.register_proc(c.host, 'nginx', counter, pid, logfile)

## Start nginx web server wrapper
#  @param counter Unique ID
#  @param file_prefix File prefix for log file
#  @param remote_dir Directory to create log file in
#  @param server Server host 
#  @param local_dir Directory to create log file in
#  @param local_dir Local directory to put files in
#  @param port Port to listen to
#  @param config_dir Directory that contains config file
#  @param config_in Config file template to use
#  @param docroot Document root on server
#  @param check If '0' don't check for nginx executable, if '1' check for 
#               nginx executable
#  @param wait Time to wait before process is started
def start_nginx_server(c,counter='1', file_prefix='', remote_dir='', local_dir='',
                      server='', port='', config_dir='', config_in='', docroot='',
                      check='1', wait=''):
    "Start nginx HTTP server"

    if server == '':
        raise ValueError('Must specify server')
    server, dummy = get_address_pair(server)
    _start_nginx_server(c,
        counter,
        file_prefix,
        remote_dir,
        local_dir,
        port,
        config_dir,
        config_in,
        docroot,
        check,
        hosts=[server])