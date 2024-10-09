#
# Testbed hosts configuration
#
#
# $Id: config-scenario1a-nodes.py,v ac150f598540 2015/05/21 06:45:42 sebastian $

# Host lists
TPCONF_router = ['newtcprt3', ]
TPCONF_hosts = [ 'newtcp20', 'newtcp27', ]

# Map external IPs to internal IPs
TPCONF_host_internal_ip = {
    'newtcprt3': ['172.16.10.1', '172.16.11.1'],
    'newtcp20':  ['172.16.10.60'],
    'newtcp21':  ['172.16.11.67'],
}

