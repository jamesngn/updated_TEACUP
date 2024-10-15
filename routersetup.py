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
## @package routersetup
# Router setup
#
# $Id: routersetup.py,v 3b086222a74b 2017/02/20 09:26:27 gja $

import config
from fabric.api import task as fabric_task, hosts, run, execute, abort, env, settings, sudo
from hostint import get_netint_cached, get_address_pair
from hosttype import get_type_cached

# Updated:
from fabric2 import Connection, Config, SerialGroup, task as fabric_v2_task
from hostint import get_netint_cached_v2, get_address_pair_v2
from hosttype import get_type_cached_v2


## Initialise single dummynet pipe
#  Same queue but different delay/loss emulation
#  @param counter Queue ID number 
#  @param source Source, can be an IP address or hostname or a subnet
#                (e.g. 192.168.1.0/24)
#  @param dest Destination, can be an IP address or hostname or a subnet
#              (e.g. 192.168.1.0/24)
#  @param rate Rate limit in bytes, e.g. 100000000 (100Mbps in bytes),
#              10kbit, 100mbit
#  @param delay Emulated delay in millieseconds
#  @param rtt Emulated rtt in millieseconds (needed only for determining 
#             queue size if not explicitly specified)
#  @param loss Loss rate
#  @param queue_size Queue size in slots (if a number) or bytes
#                    (e.g. specified as XKbytes, where X is a number)
#  @param queue_size_mult Multiply 'bdp' queue size with this factor
#                        (must be a floating point)
#  @param queue_disc Queueing discipline: fifo (default), red (RED)
#  @param queue_disc_params: If queue_disc=='red' this must be set to:
#                w_q/min_th/max_th/max_p  (see ipfw man page for details)
#  @param bidir If '0' pipe only in forward direction, if '1' two pipes (one 
#               in foward and one in backward direction)
def init_dummynet_pipe(counter='1', source='', dest='', rate='', delay='',
                       rtt='', loss='', queue_size='', queue_size_mult='1.0',
                       queue_disc='', queue_disc_params='', bidir='0'):

    queue_size = str(queue_size)
    if queue_size.lower() == 'bdp':
        # this only works if rate is specified as a number of bytes/second
        if rtt == '':
            rtt = str(2 * int(delay))
        queue_size = int(float(rate) * (float(rtt) / 1000.0) / 8)
        if queue_size < 2048:
            queue_size = 2048
        if queue_size_mult != '1.0':
            queue_size = int(float(queue_size) * float(queue_size_mult))
        queue_size = str(queue_size)

    if queue_disc != 'fifo' and queue_disc != 'red' and \
        queue_disc != 'codel' and queue_disc != 'pie' and \
        queue_disc != 'fq_codel' and queue_disc != 'fq_pie':
        abort("Only queuing disciplines for Dummynet are 'fifo'," \
            "'red', 'codel','pie', 'fq_codel' and 'fq_pie'")

    # ipfw rule number
    rule_no = str(int(counter) * 100)

    # configure pipe
    config_pipe_cmd = 'ipfw pipe %s config' % counter
    if rate != '':
        config_pipe_cmd += ' bw %sbits/s' % rate
    if delay != '':
        config_pipe_cmd += ' delay %sms' % delay
    if loss != "":
        config_pipe_cmd += ' plr %s' % loss
    if queue_size != "" and queue_disc != 'fq_codel' and \
        queue_disc != 'fq_pie':
        config_pipe_cmd += ' queue %s' % queue_size
    if queue_disc == 'red' or queue_disc == 'codel' or \
        queue_disc == 'pie':
        config_pipe_cmd += ' %s %s' % (queue_disc, queue_disc_params)
    run(config_pipe_cmd)

    # sched fq_codel/fq_pie
    if  queue_disc == 'fq_codel' or queue_disc == 'fq_pie':
        
        config_pipe_cmd = 'ipfw sched %s config pipe %s type %s limit %s %s ' % \
            (counter, counter, queue_disc, queue_size, queue_disc_params)
        run(config_pipe_cmd)
        
        config_pipe_cmd = 'ipfw queue %s config sched %s' % (counter,counter)
        run(config_pipe_cmd)
     
        create_pipe_cmd = 'ipfw add %s queue %s ip from %s to %s out' % (
            rule_no, counter, source, dest)
        run(create_pipe_cmd)
        
    else:      
        # create pipe rule
        create_pipe_cmd = 'ipfw add %s pipe %s ip from %s to %s out' % (
            rule_no, counter, source, dest)
        run(create_pipe_cmd)
        if bidir == '1':
            create_pipe_cmd = 'ipfw add %s pipe %s ip from %s to %s out' % (
                rule_no, counter, dest, source)
            run(create_pipe_cmd)

def init_dummynet_pipe_v2(c: Connection, counter='1', source='', dest='', rate='', delay='',
                          rtt='', loss='', queue_size='', queue_size_mult='1.0',
                            queue_disc='', queue_disc_params='', bidir='0'):
    """Initialise single dummynet pipe

    Args:
        c (Connection): Fabric Connection object
        counter (str, optional): Queue ID number. Defaults to '1'.
        source (str, optional): Source, can be an IP address or hostname or a subnet (e.g. 192.168.1.0/24). Defaults to ''.
        dest (str, optional): Destination, can be an IP address or hostname or a subnet (e.g. 192.168.1.0/24). Defaults to ''.
        rate (str, optional): Rate limit in bytes, e.g. 100000000 (100Mbps in bytes), 10kbit, 100mbit. Defaults to ''.
        delay (str, optional): Emulated delay in millieseconds. Defaults to ''.
        rtt (str, optional): Emulated rtt in millieseconds (needed only for determining queue size if not explicitly specified). Defaults to ''.
        loss (str, optional): Loss rate. Defaults to ''.
        queue_size (str, optional): Queue size in slots (if a number) or bytes (e.g. specified as XKbytes, where X is a number). Defaults to ''.
        queue_size_mult (str, optional): Multiply 'bdp' queue size with this factor (must be a floating point). Defaults to '1.0'.
        queue_disc (str, optional): Queueing discipline: fifo (default), red (RED). Defaults to ''.
        queue_disc_params (str, optional): If queue_disc=='red' this must be set to: w_q/min_th/max_th
        bidir (str, optional): If '0' pipe only in forward direction, if '1' two pipes (one in foward and one in backward direction). Defaults to '0'.

    Raises:
        RuntimeError: If queue_disc is not 'fifo', 'red', 'codel', 'pie', 'fq_codel' or 'fq_pie'
    """
    
    queue_size = str(queue_size)
    if queue_size.lower() == 'bdp':
        # this only works if rate is specified as a number of bytes/second
        if rtt == '':
            rtt = str(2 * int(delay))
        queue_size = int(float(rate) * (float(rtt) / 1000.0) / 8)
        if queue_size < 2048:
            queue_size = 2048
        if queue_size_mult != '1.0':
            queue_size = int(float(queue_size) * float(queue_size_mult))
        queue_size = str(queue_size)

    if queue_disc not in ['fifo', 'red', 'codel', 'pie', 'fq_codel', 'fq_pie']:
        raise RuntimeError("Only queuing disciplines for Dummynet are 'fifo', 'red', 'codel','pie', 'fq_codel' and 'fq_pie'")

    # ipfw rule number
    rule_no = str(int(counter) * 100)

    # configure pipe
    config_pipe_cmd = 'ipfw pipe %s config' % counter
    if rate != '':
        config_pipe_cmd += ' bw %sbits/s' % rate
    if delay != '':
        config_pipe_cmd += ' delay %sms' % delay
    if loss != "":
        config_pipe_cmd += ' plr %s' % loss
    if queue_size != "" and queue_disc not in ['fq_codel', 'fq_pie']:
        config_pipe_cmd += ' queue %s' % queue_size
    if queue_disc in ['red', 'codel', 'pie']:
        config_pipe_cmd += ' %s %s' % (queue_disc, queue_disc_params)
    
    # Run the command to configure the pipe
    c.run(config_pipe_cmd)

    # sched fq_codel/fq_pie
    if queue_disc in ['fq_codel', 'fq_pie']:
        config_pipe_cmd = 'ipfw sched %s config pipe %s type %s limit %s %s ' % \
                          (counter, counter, queue_disc, queue_size, queue_disc_params)
        c.run(config_pipe_cmd)
        
        config_pipe_cmd = 'ipfw queue %s config sched %s' % (counter, counter)
        c.run(config_pipe_cmd)
        
        create_pipe_cmd = 'ipfw add %s queue %s ip from %s to %s out' % (
            rule_no, counter, source, dest)
        c.run(create_pipe_cmd)
        
    else:
        # create pipe rule
        create_pipe_cmd = 'ipfw add %s pipe %s ip from %s to %s out' % (
            rule_no, counter, source, dest)
        c.run(create_pipe_cmd)
        
        if bidir == '1':
            create_pipe_cmd = 'ipfw add %s pipe %s ip from %s to %s out' % (
                rule_no, counter, dest, source)
            c.run(create_pipe_cmd)

    

## Initialse tc (Linux)
## setup a class (htb qdisc) for each interface with rate limits
## setup actual qdisc (e.g. codel) as leaf qdisc for class
## then redirect traffic to pseudo interface and apply netem to emulate
## delay and/or loss
#  @param counter Queue ID number
#  @param source Source, can be an IP address or hostname or a subnet
#                (e.g. 192.168.1.0/24)
#  @param dest Destination, can be an IP address or hostname or a subnet
#              (e.g. 192.168.1.0/24)
#  @param rate Rate limit in bytes, e.g. 100000000 (100Mbps in bytes), 10kbit, 100mbit
#  @param delay Emulated delay in millieseconds
#  @param rtt Emulated rtt in millieseconds (needed only for determining 
#            queue size if not explicitly specified)
#  @param loss Loss rate
#  @param queue_size Can be in packets or bytes depending on queue_disc; if in bytes
#                    can use units, e.g. 1kb
#  @param queue_size_mult Multiply 'bdp' queue size with this factor
#                         (must be a floating point)
#  @param queue_disc fifo (mapped to pfifo, FreeBSD compatibility), fq_codel, codel, red,
#                    choke, pfifo, pie (only as patch), ...
#  @param queue_disc_params Parameters for queing discipline, see man pages for queuing
#                           disciplines
#  @param bidir If '0' (pipe only in forward direction), 
#               if '1' (two pipes in both directions)
#  @param attach_to_queue Specify number of existing queue to use, but emulate
#                         different delay/loss
def init_tc_pipe(counter='1', source='', dest='', rate='', delay='', rtt='', loss='',
                 queue_size='', queue_size_mult='1.0', queue_disc='', 
                 queue_disc_params='', bidir='0', attach_to_queue=''):

    # compatibility with FreeBSD
    if queue_disc == 'fifo':
        # pfifo is the default for HTB classes
        queue_disc = 'pfifo'

    queue_size = str(queue_size)
    if queue_size.lower() == 'bdp':
        _rate = rate.replace('kbit', '000')
        _rate = _rate.replace('mbit', '000000')
        if rtt == '':
            rtt = str(2 * int(delay))
        if queue_disc == 'pfifo' or queue_disc == 'codel' or \
           queue_disc == 'fq_codel' or queue_disc == 'pie':
            # queue size in packets
            avg_packet = 600  # average packet size
            queue_size = int(
                float(_rate) * (float(rtt) / 1000.0) / 8 / avg_packet)
            if queue_size_mult != '1.0':
                queue_size = int(float(queue_size) * float(queue_size_mult))
            if queue_size < 1:
                queue_size = 1  # minimum 1 packet
            queue_size = str(queue_size)
        elif queue_disc == 'bfifo' or queue_disc == 'red':
            # queue size in bytes
            queue_size = int(float(_rate) * (float(rtt) / 1000.0) / 8)
            if queue_size_mult != '1.0':
                queue_size = int(float(queue_size) * float(queue_size_mult))
            if queue_size < 2048:
                queue_size = 2048  # minimum 2kB
            queue_size = str(queue_size)
        else:
            abort(
                'Can\'t specify \'bdp\' for queuing discipline %s' %
                queue_disc)

    # class/handle numbers
    class_no = str(int(counter) + 0)
    if attach_to_queue == '':
        queue_class_no = class_no
    else:
        # if attach_to_queue is set we attach this to existing (previously
        # configured pipe). this means packets will go through an existing htb
        # and leaf qdisc, but a separate netem.
        # so we can have different flows going through the same bottleneck
        # queue, but with different emulated delays or loss rates
        queue_class_no = attach_to_queue
    netem_class_no = class_no
    qdisc_no = str(int(counter) + 1000)
    netem_no = str(int(counter) + 1000)

    # disciplines: fq_codel, codel, red, choke, pfifo, pfifo_fast (standard
    # magic), pie (only as patch), ...
    if queue_disc == '':
        queue_disc = 'pfifo'
    # for pie we need to make sure the kernel module is loaded (for kernel pre
    # 3.14 only, for new kernels it happens automatically via tc use!)
    if queue_disc == 'pie':
        with settings(warn_only=True):
            sudo('modprobe pie')

    if rate == '':
        rate = '1000mbit'
    if queue_size == '':
        # set default queue size to 1000 packet (massive but default for e.g.
        # codel)
        queue_size = '1000'

    if loss != '':
        # convert to percentage
        loss = str(float(loss) * 100)

    interfaces = get_netint_cached(env.host_string, int_no=-1)

    # our approach works as follows:
    # - shaping, aqm and delay/loss emulation is done on egress interface
    #   (as usual)
    # - use htb qdisc for rate limiting with the aqm qdisc (e.g. pfifo, codel)
    #   as leave node
    # - after shaping and aqm, emulate loss and delay with netem
    # - for each "pipe" we setup a new class on all (two) interfaces
    # - if pipes are unidirectional a class is only used on one of the two ifaces;
    #   otherwise it is used on both interfaces (XXX could optimise the
    #   unidirectional case and omit unused pipes)
    # - traffic flow is as follows:
    #   1. packets are marked by iptables in mangle table POSTROUTING hook
    #      depending on defined source/dest (unique mark for each pipe)
    #   2. marked packets are classified into appropriate class (1-1 mapping
    #      between marks and classes) and redirected to pseudo interface
    #   3. pseudo interface does the shaping with htb and aqm (leaf qdisc)
    #   4. packets go back to actual interface
    #   5. actual interface does network emulation (delay/loss), here htb is set to
    # max rate (1Gbps) and pfifo is used (effectively no shaping or aqm here)

    # note that according to my information the htb has a build-in buffer of 1
    # packet as well (cannot be changed)

    cnt = 0
    for interface in interfaces:

        pseudo_interface = 'ifb' + str(cnt)

        # config rate limiting on pseudo interface
        config_tc_cmd = 'tc class add dev %s parent 1: classid 1:%s htb rate %s ceil %s' % \
            (pseudo_interface, queue_class_no, rate, rate)
        if attach_to_queue == '':
            sudo(config_tc_cmd)

        # config queuing discipline and buffer limit on pseudo interface
        config_tc_cmd = 'tc qdisc add dev %s parent 1:%s handle %s: %s limit %s %s' % \
            (pseudo_interface,
             queue_class_no,
             qdisc_no,
             queue_disc,
             queue_size,
             queue_disc_params)
        if attach_to_queue == '':
            sudo(config_tc_cmd)

        # configure filter to classify traffic based on mark on pseudo device
        config_tc_cmd = 'tc filter add dev %s protocol ip parent 1: ' \
                        'handle %s fw flowid 1:%s' % (
                            pseudo_interface, class_no, queue_class_no)
        sudo(config_tc_cmd)

        # configure class for actual interface with max rate
        config_tc_cmd = 'tc class add dev %s parent 1: classid 1:%s ' \
                        'htb rate 1000mbit ceil 1000mbit' % \
            (interface, netem_class_no)
        sudo(config_tc_cmd, warn_only=True)

        # config netem on actual interface
        config_tc_cmd = 'tc qdisc add dev %s parent 1:%s handle %s: ' \
                        'netem limit 1000' % (
                            interface, netem_class_no, netem_no)
        if delay != "":
            config_tc_cmd += " delay %sms" % delay
        if loss != "":
            config_tc_cmd += " loss %s%%" % loss
        sudo(config_tc_cmd, warn_only=True)

        # configure filter to redirect traffic to pseudo device first and also
        # classify traffic based on mark after leaving the pseudo interface traffic
        # will go back to actual interface
        config_tc_cmd = 'tc filter add dev %s protocol ip parent 1: handle %s ' \
                        'fw flowid 1:%s action mirred egress redirect dev %s' % \
            (interface, class_no, netem_class_no, pseudo_interface)
        sudo(config_tc_cmd)

        cnt += 1

    # filter on specific ips
    config_it_cmd = 'iptables -t mangle -A POSTROUTING -s %s -d %s -j MARK --set-mark %s' % \
        (source, dest, class_no)
    sudo(config_it_cmd)
    if bidir == '1':
        config_it_cmd = 'iptables -t mangle -A POSTROUTING -s %s -d %s -j MARK --set-mark %s' % \
            (dest, source, class_no)
        sudo(config_it_cmd)

def init_tc_pipe_v2(c: Connection, counter='1', source='', dest='', rate='', delay='', rtt='', loss='',
                 queue_size='', queue_size_mult='1.0', queue_disc='', 
                 queue_disc_params='', bidir='0', attach_to_queue=''):
    """
    Initialise Traffic Control (tc) on a Linux system.

    Sets up rate limits, queue disciplines, and network emulation (delay, loss)
    for traffic between specified source and destination using tc, htb, and netem.

    Args:
        counter (str): Queue ID number, used to identify the pipe.
        source (str): Source IP, hostname, or subnet (e.g. 192.168.1.0/24).
        dest (str): Destination IP, hostname, or subnet (e.g. 192.168.1.0/24).
        rate (str): Rate limit in bits per second, e.g. '100mbit', '10kbit'.
        delay (str): Emulated delay in milliseconds.
        rtt (str): Emulated round trip time in milliseconds (used for queue size calculation).
        loss (str): Loss rate as a percentage (e.g., '0.01' for 1% loss).
        queue_size (str): Queue size in packets or bytes depending on the queueing discipline.
        queue_size_mult (str): Multiply the calculated queue size by this factor (for BDP).
        queue_disc (str): Queuing discipline to use, e.g., 'fifo', 'fq_codel', 'red', 'pie', etc.
        queue_disc_params (str): Parameters specific to the chosen queueing discipline.
        bidir (str): If '0', pipe is unidirectional; if '1', bidirectional.
        attach_to_queue (str): Attach to an existing queue with different delay/loss emulation.
        host (str): The remote host on which to run the commands (default is 'localhost').

    Raises:
        ValueError: If an unsupported queuing discipline is specified.

    """
    
    # Compatibility with FreeBSD
    if queue_disc == 'fifo':
        # pfifo is the default for HTB classes
        queue_disc = 'pfifo'

    queue_size = str(queue_size)
    if queue_size.lower() == 'bdp':
        _rate = rate.replace('kbit', '000').replace('mbit', '000000')
        if rtt == '':
            rtt = str(2 * int(delay))
        avg_packet = 600  # average packet size

        if queue_disc in ['pfifo', 'codel', 'fq_codel', 'pie']:
            # Queue size in packets
            queue_size = int(float(_rate) * (float(rtt) / 1000.0) / 8 / avg_packet)
            if queue_size_mult != '1.0':
                queue_size = int(float(queue_size) * float(queue_size_mult))
            queue_size = max(queue_size, 1)  # Minimum 1 packet
        elif queue_disc in ['bfifo', 'red']:
            # Queue size in bytes
            queue_size = int(float(_rate) * (float(rtt) / 1000.0) / 8)
            if queue_size_mult != '1.0':
                queue_size = int(float(queue_size) * float(queue_size_mult))
            queue_size = max(queue_size, 2048)  # Minimum 2kB
        else:
            raise ValueError(f"Can't specify 'bdp' for queuing discipline {queue_disc}")

        queue_size = str(queue_size)

    class_no = str(int(counter))
    if attach_to_queue == '':
        queue_class_no = class_no
    else:
        # if attach_to_queue is set we attach this to existing (previously
        # configured pipe). this means packets will go through an existing htb
        # and leaf qdisc, but a separate netem.
        # so we can have different flows going through the same bottleneck
        # queue, but with different emulated delays or loss rates
        queue_class_no = attach_to_queue
    netem_class_no = class_no
    qdisc_no = str(int(counter) + 1000)
    netem_no = str(int(counter) + 1000)

    # disciplines: fq_codel, codel, red, choke, pfifo, pfifo_fast (standard
    # magic), pie (only as patch), ...
    if queue_disc == '':
        queue_disc = 'pfifo'
    
     # for pie we need to make sure the kernel module is loaded (for kernel pre
    # 3.14 only, for new kernels it happens automatically via tc use!)
    if queue_disc == 'pie':
        c.sudo('modprobe pie', warn=True)

    if rate == '':
        rate = '1000mbit'
    if queue_size == '':
        # set default queue size to 1000 packet (massive but default for e.g.
        # codel)
        queue_size = '1000'

    if loss != '':
        # convert to percentage
        loss = str(float(loss) * 100)

    interfaces = get_netint_cached(c.host, int_no=-1)
    
    # our approach works as follows:
    # - shaping, aqm and delay/loss emulation is done on egress interface
    #   (as usual)
    # - use htb qdisc for rate limiting with the aqm qdisc (e.g. pfifo, codel)
    #   as leave node
    # - after shaping and aqm, emulate loss and delay with netem
    # - for each "pipe" we setup a new class on all (two) interfaces
    # - if pipes are unidirectional a class is only used on one of the two ifaces;
    #   otherwise it is used on both interfaces (XXX could optimise the
    #   unidirectional case and omit unused pipes)
    # - traffic flow is as follows:
    #   1. packets are marked by iptables in mangle table POSTROUTING hook
    #      depending on defined source/dest (unique mark for each pipe)
    #   2. marked packets are classified into appropriate class (1-1 mapping
    #      between marks and classes) and redirected to pseudo interface
    #   3. pseudo interface does the shaping with htb and aqm (leaf qdisc)
    #   4. packets go back to actual interface
    #   5. actual interface does network emulation (delay/loss), here htb is set to
    # max rate (1Gbps) and pfifo is used (effectively no shaping or aqm here)

    # note that according to my information the htb has a build-in buffer of 1
    # packet as well (cannot be changed)

    # Main traffic control configuration loop for each interface
    cnt = 0
    for interface in interfaces:
        pseudo_interface = 'ifb' + str(cnt)

        # Configure rate limiting on pseudo interface
        config_tc_cmd = f'tc class add dev {pseudo_interface} parent 1: classid 1:{queue_class_no} htb rate {rate} ceil {rate}'
        if attach_to_queue == '':
            c.sudo(config_tc_cmd)

        # Configure queuing discipline and buffer limit on pseudo interface
        config_tc_cmd = f'tc qdisc add dev {pseudo_interface} parent 1:{queue_class_no} handle {qdisc_no}: {queue_disc} limit {queue_size} {queue_disc_params}'
        if attach_to_queue == '':
            c.sudo(config_tc_cmd)

        # Configure filter to classify traffic based on mark on pseudo device
        config_tc_cmd = f'tc filter add dev {pseudo_interface} protocol ip parent 1: handle {class_no} fw flowid 1:{queue_class_no}'
        c.sudo(config_tc_cmd)

        # Configure class for actual interface with max rate
        config_tc_cmd = f'tc class add dev {interface} parent 1: classid 1:{netem_class_no} htb rate 1000mbit ceil 1000mbit'
        c.sudo(config_tc_cmd, warn=True)

        # Configure netem on actual interface for delay/loss emulation
        config_tc_cmd = f'tc qdisc add dev {interface} parent 1:{netem_class_no} handle {netem_no}: netem limit 1000'
        if delay:
            config_tc_cmd += f' delay {delay}ms'
        if loss:
            config_tc_cmd += f' loss {loss}%'
        c.sudo(config_tc_cmd, warn=True)

        # configure filter to redirect traffic to pseudo device first and also
        # classify traffic based on mark after leaving the pseudo interface traffic
        # will go back to actual interface
        config_tc_cmd = f'tc filter add dev {interface} protocol ip parent 1: handle {class_no} fw flowid 1:{netem_class_no} action mirred egress redirect dev {pseudo_interface}'
        c.sudo(config_tc_cmd)

        cnt += 1

    # Set up iptables for traffic filtering based on source and destination IP
    config_it_cmd = f'iptables -t mangle -A POSTROUTING -s {source} -d {dest} -j MARK --set-mark {class_no}'
    c.sudo(config_it_cmd)
    
    if bidir == '1':
        config_it_cmd = f'iptables -t mangle -A POSTROUTING -s {dest} -d {source} -j MARK --set-mark {class_no}'
        c.sudo(config_it_cmd)

## Show dummynet pipes
def show_dummynet_pipes():
    run('ipfw -a list')
    run('ipfw -a pipe list')
    
def show_dummynet_pipes_v2(c: Connection):
    c.run('ipfw -a list')
    c.run('ipfw -a pipe list')


## Show tc setup
def show_tc_setup():

    interfaces = get_netint_cached(env.host_string, int_no=-1)

    run('tc -d -s qdisc show')
    cnt = 0
    for interface in interfaces:
        run('tc -d -s class show dev %s' % interface)
        run('tc -d -s filter show dev %s' % interface)
        pseudo_interface = 'ifb' + str(cnt)
        run('tc -d -s class show dev %s' % pseudo_interface)
        run('tc -d -s filter show dev %s' % pseudo_interface)
        cnt += 1
    sudo('iptables -t mangle -vL')

def show_tc_setup_v2(c: Connection):
    """Show tc setup

    Args:
        c (Connection): Fabric Connection object
    """
    interfaces = get_netint_cached_v2(c.host, int_no=-1)

    c.run('tc -d -s qdisc show')
    cnt = 0
    for interface in interfaces:
        c.run(f'tc -d -s class show dev {interface}')
        c.run(f'tc -d -s filter show dev {interface}')
        pseudo_interface = f'ifb{cnt}'
        c.run(f'tc -d -s class show dev {pseudo_interface}')
        c.run(f'tc -d -s filter show dev {pseudo_interface}')
        cnt += 1
    c.sudo('iptables -t mangle -vL')

## Show pipe setup
@fabric_task
def show_pipes():
    "Show pipe setup on router"

    # get type of current host
    htype = get_type_cached(env.host_string)

    if htype == 'FreeBSD':
        execute(show_dummynet_pipes)
    elif htype == 'Linux':
        execute(show_tc_setup)
    else:
        abort("Router must be running FreeBSD or Linux")

@fabric_v2_task
def show_pipes_v2(c: Connection):
    "Show pipe setup on router"

    # get type of current host
    htype = get_type_cached_v2(c.host)

    if htype == 'FreeBSD':
        show_dummynet_pipes_v2(c)
    elif htype == 'Linux':
        show_tc_setup_v2(c)
    else:
        raise RuntimeError("Router must be running FreeBSD or Linux")


## Configure a pipe on the router, encompassing rate shaping, AQM, 
## loss/delay emulation
## For parameter explanations see descriptions of init_dummynet_pipe() and init_tc_pipe()
## Note: attach_to_queue only works for Linux
@fabric_task
def init_pipe(counter='1', source='', dest='', rate='', delay='', rtt='', loss='',
              queue_size='', queue_size_mult='1.0', queue_disc='', 
              queue_disc_params='', bidir='0', attach_to_queue=''):
    "Configure pipe on router, including rate shaping, AQM, loss/delay emulation"

    # get internal addresses
    dummy, source_internal = get_address_pair(source)
    dummy, dest_internal = get_address_pair(dest)

    # get type of current host
    htype = get_type_cached(env.host_string)

    if htype == 'FreeBSD':
        execute(
            init_dummynet_pipe,
            counter,
            source_internal,
            dest_internal,
            rate,
            delay,
            rtt,
            loss,
            queue_size,
            queue_size_mult,
            queue_disc,
            queue_disc_params,
            bidir)
    elif htype == 'Linux':
        execute(
            init_tc_pipe,
            counter,
            source_internal,
            dest_internal,
            rate,
            delay,
            rtt,
            loss,
            queue_size,
            queue_size_mult,
            queue_disc,
            queue_disc_params,
            bidir,
            attach_to_queue)
    else:
        abort("Router must be running FreeBSD or Linux")


@fabric_v2_task
def init_pipe_v2(c: Connection, counter='1', source='', dest='', rate='', delay='', rtt='', loss='',
              queue_size='', queue_size_mult='1.0', queue_disc='', 
              queue_disc_params='', bidir='0', attach_to_queue=''):
    """
    
    Configure a pipe on the router, encompassing rate shaping, AQM, loss/delay emulation. Note: attach_to_queue only works for Linux

    Args:
        c (Connection): Fabric Connection object
        counter (str, optional): Queue ID number. Defaults to '1'.
        source (str, optional): Source, can be an IP address or hostname or a subnet (e.g.
        dest (str, optional): Destination, can be an IP address or hostname or a subnet (e.g.
        rate (str, optional): Rate limit in bytes, e.g. 100000000 (100Mbps in bytes), 10kbit, 100mbit. Defaults to ''.
        delay (str, optional): Emulated delay in millieseconds. Defaults to ''.
        rtt (str, optional): Emulated rtt in millieseconds (needed only for determining queue size if not explicitly specified). Defaults to ''.
        loss (str, optional): Loss rate. Defaults to ''.
        queue_size (str, optional): Queue size in slots (if a number) or bytes (e.g. specified as XKbytes, where X is a number). Defaults to ''.
        queue_size_mult (str, optional): Multiply 'bdp' queue size with this factor (must be a floating point). Defaults to '1.0'.
        queue_disc (str, optional): Queueing discipline: fifo (default), red (RED). Defaults to ''.
        queue_disc_params (str, optional): If queue_disc=='red' this must be set to: w_q/min_th/max_th. Defaults to ''.
        bidir (str, optional): If '0' pipe only in forward direction, if '1' two pipes (one in foward and one in backward direction). Defaults to '0'.
        attach_to_queue (str, optional): Specify number of existing queue to use, but emulate different delay/loss. Defaults to ''.
        
    Raises:
        RuntimeError: If router is not running FreeBSD or Linux
    """
    
    # get internal addresses
    dummy, source_internal = get_address_pair_v2(c, host=source)
    dummy, dest_internal = get_address_pair_v2(c, host=dest)
    
    # get type of current host
    htype = get_type_cached_v2(c.host)
    
    if htype == 'FreeBSD':
        init_dummynet_pipe_v2(c, counter, source_internal, dest_internal, rate, delay, rtt, loss, queue_size, queue_size_mult, queue_disc, queue_disc_params, bidir)
    elif htype == 'Linux':
        init_tc_pipe_v2(c, counter, source_internal, dest_internal, rate, delay, rtt, loss, queue_size, queue_size_mult, queue_disc, queue_disc_params, bidir, attach_to_queue)
    else:
        raise RuntimeError("Router must be running FreeBSD or Linux")
    
    