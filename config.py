# Simple experiment with two tcp flows with two hosts and one
# router
#
# $Id: config-scenario1.py,v 9528f837a557 2016/06/06 03:37:45 s_zander $

import sys
import datetime
from fabric.api import env

# Updated
from fabric2 import Connection, Config, SerialGroup, ThreadingGroup


#
# Fabric config
#

# User and password
env.user = "controlhost"

env.password = "password"

env.sudo_passwords = {
    "controlhost": "password",
    "host1": "password",
    "host2": "password",
}

# Set shell used to execute commands
env.shell = '/bin/sh -c'

#
# Testbed config
#

# Path to teacup scripts
TPCONF_script_path = '/home/controlhost/old_teacup/teacup-1.1'
# DO NOT remove the following line
sys.path.append(TPCONF_script_path)

# Set debugging level (0 = no debugging info output) 
TPCONF_debug_level = 0

# Host lists
TPCONF_router = ['controlhost', ]
TPCONF_hosts = [ 'host1', 'host2', ]

# Map external IPs to internal IPs
TPCONF_host_internal_ip = {
    'controlhost': ['192.168.10.1', '192.168.11.1'],
    'host1':  ['192.168.10.11'],
    'host2':  ['192.168.11.11'],
}

#
# Reboot configuration
#

#
# Experiment settings
#

TPCONF_linux_tcp_logger = 'web10g'

# Time offset measurement options
# Enable broadcast ping on external/control interfaces
TPCONF_bc_ping_enable = '1'
# Specify rate of pings in packets/second
TPCONF_bc_ping_rate = 1
# Specify multicast address to use (must be broadcast or multicast address)
# If this is not specified, by default the ping will be send to the subnet
# broadcast address.

##TPCONF_bc_ping_address = '224.0.1.199'

# Maximum allowed time difference between machines in seconds
# otherwise experiment will abort cause synchronisation problems
TPCONF_max_time_diff = 2

# Experiment name prefix used if not set on the command line
# The command line setting will overrule this config setting
now = datetime.datetime.today()
TPCONF_test_id = now.strftime("%Y%m%d-%H%M%S") + '_scenario1'

# Directory to store log files on remote host
TPCONF_remote_dir = '/tmp/'

TPCONF_force_reboot = '0'

# TPCONF_tftpboot_dir = '/tftpboot'

TPCONF_boot_timeout = 100

TPCONF_os_partition = {
	'CYGWIN':  '(hd0,0)',
	'Linux':   '(hd0,1)',
	'FreeBSD': '(hd0,2)',
}

TPCONF_host_os = {
    'controlhost': 'Linux',
    'host1': 'Linux',
    'host2': 'Linux',
}

TPCONF_linux_kern_router = '3.17.4-vanilla-10000hz'
TPCONF_linux_kern_hosts = '3.17.4-vanilla-web10g'

# Number of runs for each setting
TPCONF_runs = 1

#
# List of router queues/pipes
#

# Each entry is a tuple. The first value is the queue number and the second value
# is a comma separated list of parameters (see routersetup.py:init_pipe()).
# Queue numbers must be unique.

# Note that variable parameters must be either constants or or variable names
# defined by the experimenter. Variables are evaluated during runtime. Variable
# names must start with a 'V_'. Parameter names can only contain numbes, letter
# (upper and lower case), underscores (_), and hypen/minus (-).

# All variables must be defined in TPCONF_variable_list (see below).

# Note parameters must be configured appropriately for the router OS, e.g. there
# is no CoDel on FreeBSD; otherwise the experiment will abort witn an error.

TPCONF_router_queues = [
    # Set same delay for every host
    ('1', " source='192.168.10.0/24', dest='192.168.11.0/24', delay=V_delay, "
     " loss=V_loss, rate=V_up_rate, queue_disc=V_aqm, queue_size=V_bsize "),
    ('2', " source='192.168.11.0/24', dest='192.168.10.0/24', delay=V_delay, "
    " loss=V_loss, rate=V_down_rate, queue_disc=V_aqm, queue_size=V_bsize "),
]

#
# List of traffic generators
#

# Each entry is a 3-tuple. the first value of the tuple must be a float and is the
# time relative to the start of the experiment when tasks are excuted. If two tasks
# have the same start time their start order is arbitrary. The second entry of the
# tuple is the task number and  must be a unique integer (used as ID for the process).
# The last value of the tuple is a comma separated list of parameters (see the tasks
# defined in trafficgens.py); the first parameter of this list must be the
# task name.

# Client and server can be specified using the external/control IP addresses or host
# names. Then the actual interface used is the _first_ internal address (according to
# TPCONF_host_internal_ip). Alternativly, client and server can be specified as
# internal addresses, which allows to use any internal interfaces configured.

traffic_iperf = [
    # Specifying external addresses traffic will be created using the _first_
    # internal addresses (according to TPCONF_host_internal_ip)
    ('0.0', '1', " start_iperf, client='host1', server='controlhost', port=5000, "
     " duration=V_duration "),
    ('0.0', '2', " start_iperf, client='host1', server='controlhost', port=5001, "
     " duration=V_duration "),
    # Or using internal addresses
    #( '0.0', '1', " start_iperf, client='192.168.10.11', server='192.168.10.12', "
    #              " port=5000, duration=V_duration " ),
    #( '0.0', '2', " start_iperf, client='192.168.10.12', server='192.168.10.11', "
    #              " port=5001, duration=V_duration " ),
]

# THIS is the traffic generator setup we will use
TPCONF_traffic_gens = traffic_iperf

#
# Traffic parameters 
#

# Duration in seconds of traffic
TPCONF_duration = 30

# TCP congestion control algorithm used
# Possible algos are: default, host<N>, newreno, cubic, cdg, hd, htcp, compound, vegas
# Note that the algo support is OS specific, so must ensure the right OS is booted
# Windows: newreno (default), compound
# FreeBSD: newreno (default), cubic, hd, htcp, cdg, vegas
# Linux: newreno, cubic (default), htcp, vegas
# Mac: newreno
# If you specify 'default' the default algorithm depending on the OS will be used
# If you specify 'host<N>' where <N> is an integer starting from 0 to then the
# algorithm will be the N-th algorithm specified for the host in TPCONF_host_TCP_algos 
# (in case <N> is larger then the number of algorithms specified, it is set to 0
TPCONF_TCP_algos = ['newreno', 'cubic', ]

# Specify TCP congestion control algorithms used on each host
TPCONF_host_TCP_algos = {
}

# Specify TCP parameters for each host and each TCP congestion control algorithm
# Each parameter is of the form <sysctl name> = <value> where <value> can be a constant
# or a V_ variable
TPCONF_host_TCP_algo_params = {
}

# Specify arbitray commands that are executed on a host at the end of the host 
# intialisation (after general host setup, ecn and tcp setup). The commands are
# executed in the shell as written after any V_ variables have been replaced.
# LIMITATION: only one V_ variable per command
TPCONF_host_init_custom_cmds = {
}

# Emulated delays in ms
TPCONF_delays = [0, 25, 50]

# Emulated loss rates
TPCONF_loss_rates = [0]

# Emulated bandwidths (downstream, upstream)
TPCONF_bandwidths = [
    ("8", "1"),
    ("20", "1.4"),
]

# AQM
# Linux: fifo (mapped to pfifo), pfifo, bfifo, fq_codel, codel, pie, red, ...
#        (see tc man page for full list)
# FreeBSD: fifo, red
TPCONF_aqms = ['pfifo', ]

# Buffer size
# If router is Linux this is mostly in packets/slots, but it depends on AQM
# (e.g. for bfifo it's bytes)
# If router is FreeBSD this would be in slots by default, but we can specify byte sizes
# (e.g. we can specify 4Kbytes)
TPCONF_buffer_sizes = [100]

#
# List of all parameters that can be varied and default values
#

# The key of each item is the identifier that can be used in TPCONF_vary_parameters
# (see below).
# The value of each item is a 4-tuple. First, a list of variable names.
# Second, a list of short names uses for the file names.
# For each parameter varied a string '_<short_name>_<value>' is appended to the log
# file names (appended to chosen prefix). Note, short names should only be letters
# from a-z or A-Z. Do not use underscores or hyphens!
# Third, the list of parameters values. If there is more than one variable this must
# be a list of tuples, each tuple having the same number of items as teh number of
# variables. Fourth, an optional dictionary with additional variables, where the keys
# are the variable names and the values are the variable values.

TPCONF_parameter_list = {
#   Vary name		V_ variable	  file name	values			extra vars
    'delays' 	    :  (['V_delay'], 	  ['del'], 	TPCONF_delays, 		 {}),
    'loss'  	    :  (['V_loss'], 	  ['loss'], 	TPCONF_loss_rates, 	 {}),
    'tcpalgos' 	    :  (['V_tcp_cc_algo'],['tcp'], 	TPCONF_TCP_algos, 	 {}),
    'aqms'	    :  (['V_aqm'], 	  ['aqm'], 	TPCONF_aqms, 		 {}),
    'bsizes'	    :  (['V_bsize'], 	  ['bs'], 	TPCONF_buffer_sizes, 	 {}),
    'runs'	    :  (['V_runs'],       ['run'], 	range(TPCONF_runs), 	 {}),
    'bandwidths'    :  (['V_down_rate', 'V_up_rate'], ['down', 'up'], TPCONF_bandwidths, {}),
}

# Default setting for variables (used for variables if not varied)

# The key of each item is the parameter  name. The value of each item is the default
# parameter value used if the variable is not varied.

TPCONF_variable_defaults = {
#   V_ variable			value
    'V_duration'  	:	TPCONF_duration,
    'V_delay'  		:	TPCONF_delays[0],
    'V_loss'   		:	TPCONF_loss_rates[0],
    'V_tcp_cc_algo' 	:	TPCONF_TCP_algos[0],
    'V_down_rate'   	:	TPCONF_bandwidths[0][0],
    'V_up_rate'	    	:	TPCONF_bandwidths[0][1],
    'V_aqm'	    	:	TPCONF_aqms[0],
    'V_bsize'	    	:	TPCONF_buffer_sizes[0],
}

# Specify the parameters we vary through all values, all others will be fixed
# according to TPCONF_variable_defaults
TPCONF_vary_parameters = ['delays', 'bandwidths', 'aqms', 'runs',]


# New config for fabric 2.0
hostConfig = Config(overrides={
    "connect_kwargs": {
        "password": "password"
    },
    "sudo": {
        "password": "password",
        "prompt":"sudo :"
    },
    "run": {
        "echo": True,
        "warn": True,
    }
})

host_to_conn = {
    'controlhost': Connection('controlhost', config=hostConfig),
    'host1': Connection('host1', config=hostConfig),
    'host2': Connection('host2', config=hostConfig),
}

all_hosts = TPCONF_router + TPCONF_hosts