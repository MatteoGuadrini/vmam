#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
# vim: se ts=4 et syn=python:

# created by: matteo.guadrini
# vmam -- vmam
#
#     Copyright (C) 2019 Matteo Guadrini <matteo.guadrini@hotmail.it>
#
#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation, either version 3 of the License, or
#     (at your option) any later version.
#
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.
#
#     You should have received a copy of the GNU General Public License
#     along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
VLAN Mac-address Authentication Manager

vmam is a command line tool which allows the management and maintenance of the mac-addresses
that access the network under a specific domain and a specific VLAN, through LDAP authentication.
This is based on RFC-3579(https://tools.ietf.org/html/rfc3579#section-2.1).

Usage for command line:

    SYNOPSYS

.. code-block:: console

        vmam [action] [parameter] [options]

        config {action}: Configuration command for vmam environment

            --new/-n {parameter}: Instruction to create a new configuration file. By specifying a path, it creates the
            file in the indicated path. The default path is /etc/vmam/vmam.cfg

            $> vmam config --new
            Create a new configuration in a standard path: /etc/vmam/vmam.cfg

            --get-cmd/-g {parameter}: Instruction to obtain the appropriate commands to configure your network
            infrastructure and radius server around the created configuration file. By specifying a path, get
            the file in the indicated path. The default path is /etc/vmam/vmam.cfg

            $> vmam config --get-cmd
            It takes instructions to configure its own network and radius server structure,
            from standard path: /etc/vmam/vmam.cfg

        start {action}: Automatic action for vmam environment

            --config-file/-c {parameter}: Specify a configuration file in a custom path (optional)

            $> vmam start --config-file /home/arthur/vmam.cfg
            Start automatic process based on custom path configuration file: /home/arthur/vmam.cfg

            --daemon/-d {parameter}: If specified, the automatic process run in background

            $> vmam start --daemon
            Start automatic process in background based on standard path: /etc/vmam/vmam.cfg

        mac {action}: Manual action for adding, modifying, deleting and disabling of the mac-address users

            --add/-a {parameter}: Add a specific mac-address on LDAP with specific VLAN. See also --vlan-id/-i

            $> vmam mac --add 000018ff12dd --vlan-id 110
            Add new mac-address user with VLAN 110, based on standard configuration file: /etc/vmam/vmam.cfg

            $> vmam mac --add 000018ff12dd --vlan-id 111
            Modify new or existing mac-address user with VLAN 111, based on standard configuration
            file: /etc/vmam/vmam.cfg

            --description/-D {parameter}: Add description on created mac-address

            $> vmam mac --add 000018ff12dd --vlan-id 110 --description "My personal linux"
            Add new mac-address user with VLAN 110, based on standard configuration file: /etc/vmam/vmam.cfg

            --remove/-r {parameter}: Remove a mac-address user on LDAP

            $> vmam mac --remove 000018ff12dd
            Remove mac-address user 000018ff12dd, based on standard configuration file: /etc/vmam/vmam.cfg

            --disable/-d {parameter}: Disable a mac-address user on LDAP, without removing

            $> vmam mac --disable 000018ff12dd
            Disable mac-address user 000018ff12dd, based on standard configuration file: /etc/vmam/vmam.cfg

            --force/-f {parameter}: Force remove/disable action

            $> vmam mac --remove 000018ff12dd --force
            Force remove mac-address user 000018ff12dd, based on standard configuration file: /etc/vmam/vmam.cfg

            --vlan-id/-i {parameter}: Specify a specific VLAN-id

            $> vmam mac --add 000018ff12dd --vlan-id 100
            Add new mac-address user with VLAN 100, based on standard configuration file: /etc/vmam/vmam.cfg

            --config-file/-c {parameter}: Specify a configuration file in a custom path (optional)

            $> vmam mac --remove 000018ff12dd --config-file /opt/vlan-office/office.cfg
            Remove mac-address user 000018ff12dd, based on custom configuration file: /opt/vlan-office/office.cfg

        --version/-V {option}: Print version and exit

        --verbose/-v {option}: Print and log verbose information, for debugging

Usage like a module:

.. code-block:: python

    #!/usr/bin/env python3
    from vmam import *

    # activate debug
    debug = True

    # define log writer
    wt = logwriter('/tmp/log.log')

    # start script
    debugger(debug, wt, 'Start...')

    # connect to LDAP server
    conn = connect_ldap(['dc1.foo.bar'])
    bind = bind_ldap(conn, r'domain\\admin', 'password', tls=True)
    ldap_version = check_ldap_version(bind, 'dc=foo,dc=bar')

    for mac in get_mac_from_file('/tmp/mac_list.txt'):
        debugger(debug, wt, 'create mac address {}'.format(mac))
        # create mac address
        dn = 'cn={},ou=mac,dc=foo,dc=bar'.format(mac)
        attrs = {'givenname': 'mac-address',
                    'sn': mac,
                    'samaccountname': mac
                }
        # create mac-address user
        new_user(bind, dn, **attrs)
        # add mac user to vlan group
        add_to_group(bind, 'cn=vlan_group100,ou=groups,dc=foo,dc=bar', dn)
        # set password and password never expires
        set_user(bind, dn, pwdlastset=-1, useraccountcontrol=66048)
        set_user_password(bind, dn, mac, ldap_version=ldap_version)

AUTHOR

    Matteo Guadrini <matteo.guadrini@hotmail.it>

COPYRIGHT

    (c) Matteo Guadrini. All rights reserved.
"""
# region Import dependencies

import daemon
import ldap3
import winrm
import yaml

# endregion

# region Imports

import os
import sys
import time
import socket
import logging
import argparse
import datetime


# endregion

# region Function for check dependencies module are installed


def check_module(module):
    """
    This function checks if a module is installed.
    :param module: The name of the module you want to check
    :return: Boolean
    ---
    >>>check_module('os')
    True
    """
    return module in sys.modules


# endregion

# region Global variable
VERSION = '1.4.1'
__all__ = ['logwriter', 'debugger', 'confirm', 'read_config', 'get_platform', 'new_config', 'bind_ldap',
           'check_connection', 'check_config', 'connect_ldap', 'unbind_ldap', 'query_ldap', 'check_ldap_version',
           'new_user', 'set_user', 'delete_user', 'set_user_password', 'add_to_group', 'remove_to_group',
           'filetime_to_datetime', 'datetime_to_filetime', 'get_time_sync', 'string_to_datetime', 'format_mac',
           'connect_client', 'run_command', 'get_mac_address', 'get_client_user', 'check_vlan_attributes', 'VERSION',
           'get_mac_from_file', 'timestamp_to_datetime', 'datetime_to_timestamp']
bind_start = False


# endregion

# region Functions


def printv(*messages):
    """
    Print verbose information

    :param messages: List of messages
    :return: String print on stdout

    .. testcode::

        >>> printv('Test','printv')
    """
    print("DEBUG:", *messages)


def logwriter(logfile):
    """
    Logger object than write line in a log file

    :param logfile: Path of logfile(.log)
    :return: Logger object

    .. testcode::

        >>> wl = logwriter('test.log')
        >>> wl.info('This is a test')
    """
    # Create logging object
    _format = logging.Formatter('%(asctime)s %(levelname)-4s %(message)s')
    # Folder exists?
    leaf = os.path.split(logfile)
    if not os.path.exists(leaf[0]):
        try:
            os.makedirs(leaf[0])
        except Exception as err:
            print('ERROR: {0}'.format(err))
            exit(2)
    try:
        handler = logging.FileHandler(logfile)
        handler.setFormatter(_format)
        logger = logging.getLogger(os.path.basename(__file__))
        logger.setLevel(logging.DEBUG)
        if not len(logger.handlers):
            logger.addHandler(handler)
        return logger
    except Exception as err:
        print('ERROR: {0}'.format(err))
        exit(2)


def debugger(verbose, writer, message):
    """
    Debugger: write debug and print verbose message

    :param verbose: verbose status; boolean
    :param writer: Log writer object
    :param message: String message
    :return: String on stdout

    .. testcode::

        >>> wl = logwriter('test.log')
        >>> debugger(True, wl, 'Test debug')
    """
    if verbose:
        writer.debug(message)
        printv(message)


def confirm(message):
    """
    Confirm action

    :param message: Question that expects a 'yes' or 'no' answer
    :return: Boolean


    .. testcode::

        >>> if confirm('Please, respond'):
        ...    print('yep!')
    """
    # Question
    question = message + ' [Y/n]: '

    # Possible right answers
    yes = ['yes', 'y', 'ye', '']
    no = ['no', 'n']

    # Validate answer
    choice = input(question).lower()
    while True:
        if choice in yes:
            return True
        elif choice in no:
            return False
        # I do not understand
        print("Please, respond with 'yes' or 'no'")
        # Validate answer
        choice = input(question).lower()


def read_config(path):
    """
    Open YAML configuration file

    :param path: Path of configuration file
    :return: Python object

    .. testcode::

        >>> cfg = read_config('/tmp/vmam.yml')
        >>> print(cfg)
    """
    try:
        with open('{0}'.format(path)) as file:
            return yaml.full_load(file)
    except FileNotFoundError as err:
        print('ERROR: {0}'.format(err))
        exit(3)
    except OSError as err:
        print('ERROR: {0}'.format(err))
        exit(2)


def write_config(obj, path):
    """
    Write YAML configuration file

    :param obj: Python object that will be converted to YAML
    :param path: Path of configuration file
    :return: None

    .. testcode::

        >>> write_config(obj, '/tmp/vmam.yml')
    """
    with open('{0}'.format(path), 'w') as file:
        yaml.dump(obj, file)


def get_mac_from_file(path, mac_format='none'):
    """
    Get mac-address from file list

    :param path: Path of file list. Mac-address can write in any format.

        file example (/tmp/list.txt):

        112233445566\n
        # mac of my Linux\n
        11-22-33-44-55-66\n
        # this macs is\n
        # other pc of my office\n
        \n
        11:22:33:44:55:66\n
        1122.3344.5566\n

    :param mac_format: mac format are (default=none):

        none 	112233445566\n
        hypen 	11-22-33-44-55-66\n
        colon 	11:22:33:44:55:66\n
        dot	    1122.3344.5566\n

    :return: list

    .. testcode::

        >>> get_mac_from_file('/tmp/list')
    """
    macs = list()
    f = open(path)
    # Support empty line
    lines = [line.strip() for line in f if line.strip()]
    for line in lines:
        mac = line.strip()
        # Support comment line
        if not mac.startswith('#'):
            macs.append(format_mac(mac, mac_format))
    return macs


def get_platform():
    """
    Get a platform (OS info)

    :return: Platform info dictionary

    .. testcode::

        >>> p = get_platform()
        >>> print(p)
    """
    # Create os info object
    os_info = {'conf_default': '/etc/vmam/vmam.yml', 'log_default': '/var/log/vmam/vmam.log'}
    return os_info


def new_config(path=(get_platform()['conf_default'])):
    """
    Create a new vmam config file (YAML)

    :param path: Path of config file
    :return: None

    .. testcode::

        >>> new_config('/tmp/vmam.yml')
    """
    # Folder exists?
    leaf = os.path.split(path)
    if not os.path.exists(leaf[0]):
        try:
            os.makedirs(leaf[0])
        except Exception as err:
            print('ERROR: {0}'.format(err))
            exit(2)
    conf = {
        'LDAP': {
            'servers': ['dc1', 'dc2'],
            'domain': 'foo.bar',
            'ssl': 'true|false',
            'tls': 'true|false',
            'bind_user': 'vlan_user',
            'bind_pwd': 'secret',
            'user_base_dn': 'DC=foo,DC=bar',
            'computer_base_dn': 'DC=foo,DC=bar',
            'mac_user_base_dn': 'OU=mac-users,DC=foo,DC=bar',
            'mac_user_ttl': '365d',
            'time_computer_sync': '1m',
            'verify_attrib': ['memberof', 'cn'],
            'write_attrib': 'extensionattribute1',
            'match': 'like|exactly',
            'add_group_type': ['user', 'computer'],
            'other_group': ['second_grp', 'third_grp']
        },
        'VMAM': {
            'mac_format': 'none|hypen|colon|dot',
            'soft_deletion': 'true|false',
            'filter_exclude': ['list1', 'list2'],
            'log': get_platform()['log_default'],
            'automatic_process_wait': 3,
            'black_list': '',
            'remove_process': True,
            'user_match_id': {
                'value1': 100,
                'value2': 101
            },
            'vlan_group_id': {
                100: 'group1',
                101: 'group2'
            },
            'winrm_user': 'admin',
            'winrm_pwd': 'secret'
        }
    }
    write_config(conf, path)


def check_connection(ip, port, timeout=3):
    """
    Test connection of remote (ip) machine on (port)

    :param ip: ip address or hostname of machine
    :param port: tcp port
    :param timeout: set timeout of connection
    :return: Boolean

    .. testcode::

        >>> check_connection('localhost', 80)
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.connect((ip, port))
        s.shutdown(socket.SHUT_RDWR)
        return True
    except socket.error:
        return False


def check_config(path):
    """
    Check YAML configuration file

    :param path: Path of configuration file
    :return: Boolean

    .. testcode::

        >>> cfg = check_config('/tmp/vmam.yml')
    """
    # Check exists configuration file
    assert os.path.exists(path), 'Configuration file not exists: {0}'.format(path)
    # Read the config file
    config = read_config(path)
    # Check the two principal configuration: LDAP and VMAM
    assert 'LDAP' in config, 'Key "LDAP" is required!'
    assert 'VMAM' in config, 'Key "VMAM" is required!'
    assert len(config.keys()) == 2, 'The principal keys of configuration file are two: "LDAP" and "VMAM"!'
    # Now, check mandatory fields of LDAP section
    assert ('servers' in config['LDAP'] and len(config['LDAP']['servers']) > 0), 'Required LDAP:servers: field!'
    assert ('domain' in config['LDAP'] and config['LDAP']['domain']), 'Required LDAP:domain: field!'
    assert ('bind_user' in config['LDAP'] and config['LDAP']['bind_user']), 'Required LDAP:bind_user: field!'
    assert ('bind_pwd' in config['LDAP'] and config['LDAP']['bind_pwd']), 'Required LDAP:bind_pwd: field!'
    assert ('user_base_dn' in config['LDAP'] and config['LDAP']['user_base_dn']), 'Required LDAP:user_base_dn: field!'
    assert ('computer_base_dn' in config['LDAP'] and
            config['LDAP']['computer_base_dn']), 'Required LDAP:computer_base_dn: field!'
    assert ('mac_user_base_dn' in config['LDAP'] and
            config['LDAP']['mac_user_base_dn']), 'Required LDAP:mac_user_base_dn: field!'
    assert ('verify_attrib' in config['LDAP'] and
            len(config['LDAP']['verify_attrib']) > 0), 'Required LDAP:verify_attrib: field!'
    assert ('match' in config['LDAP'] and config['LDAP']['match']), 'Required LDAP:match: field!'
    assert ('add_group_type' in config['LDAP'] and
            len(config['LDAP']['add_group_type']) > 0), 'Required LDAP:add_group_type: field!'
    # Now, check mandatory fields of VMAM section
    assert ('mac_format' in config['VMAM'] and config['VMAM']['mac_format']), 'Required VMAM:mac_format: field!'
    assert ('soft_deletion' in config['VMAM'] and
            config['VMAM']['soft_deletion']), 'Required VMAM:soft_deletion: field!'
    assert ('automatic_process_wait' in config['VMAM'] and
            isinstance(config['VMAM']['automatic_process_wait'], int)), 'Required VMAM:automatic_process_wait: field!'
    assert ('user_match_id' in config['VMAM'] and
            len(config['VMAM']['user_match_id'].keys()) > 0), 'Required VMAM:user_match_id: field!'
    assert ('vlan_group_id' in config['VMAM'] and
            len(config['VMAM']['vlan_group_id'].keys()) > 0), 'Required VMAM:vlan_group_id: field!'
    # Check if value of user_match_id corresponding to keys of vlan_group_id
    for k, v in config['VMAM']['user_match_id'].items():
        assert config['VMAM']['vlan_group_id'].get(v), 'Theres is no correspondence between the key {0} ' \
                                                       'in vlan_group_id and the key {1} in user_match_id!'.format(v, k)
    assert ('winrm_user' in config['VMAM'] and config['VMAM']['winrm_user']), 'Required VMAM:winrm_user: field!'
    assert ('winrm_pwd' in config['VMAM'] and config['VMAM']['winrm_pwd']), 'Required VMAM:winrm_pwd: field!'
    # Now, return ok (True)
    return True


def connect_ldap(servers, *, ssl=False):
    """
    Connect to LDAP server (SYNC mode)

    :param servers: LDAP servers list
    :param ssl: If True, set port to 636 else 389
    :return: LDAP connection object

    .. testcode::

        >>> conn = connect_ldap(['dc1.foo.bar'], ssl=True)
        >>> print(conn)
    """
    # Check ssl connection
    port = 636 if ssl else 389
    # Create a server pool
    srvs = list()
    for server in servers:
        srvs.append(ldap3.Server(server, get_info=ldap3.ALL, port=port, use_ssl=ssl))
    # Start connection to LDAP server
    server_connection = ldap3.ServerPool(srvs, ldap3.ROUND_ROBIN, active=True, exhaust=True)
    return server_connection


def bind_ldap(server, user, password, *, tls=False):
    """
    Bind with user a LDAP connection

    :param server: LDAP connection object
    :param user: user used for bind
    :param password: password of user
    :param tls: if True, start tls connection
    :return: LDAP bind object

    .. testcode::

        >>> conn = connect_ldap(['dc1.foo.bar'])
        >>> bind = bind_ldap(conn, r'domain\\user', 'password', tls=True)
        >>> print(bind)
    """
    auto_bind = ldap3.AUTO_BIND_TLS_BEFORE_BIND if tls else ldap3.AUTO_BIND_NONE
    # Create a bind connection with user and password
    bind_connection = ldap3.Connection(server, user='{0}'.format(user), password='{0}'.format(password),
                                       auto_bind=auto_bind, raise_exceptions=True)
    # Check LDAP bind connection
    if bind_connection.bind():
        return bind_connection
    else:
        print('Error in bind:', bind_connection.result)


def unbind_ldap(bind_object):
    """
    Unbind LDAP connection

    :param bind_object: LDAP bind object
    :return: None

    .. testcode::

        >>> conn = connect_ldap(['dc1.foo.bar'])
        >>> bind = bind_ldap(conn, r'domain\\user', 'password', tls=True)
        >>> bind.unbind()
    """
    # Disconnect LDAP server
    bind_object.unbind()


def query_ldap(bind_object, base_search, attributes, comp='=', **filters):
    """
    Query LDAP

    :param bind_object: LDAP bind object
    :param base_search: distinguishedName of LDAP base search
    :param attributes: list of returning LDAP attributes
    :param comp: comparison operator. Default is '='. Accepted:

        Equality		    (attribute=abc)     =

        Negation		    (!attribute=abc)  	!

        Presence		    (attribute=*)       =*

        Greater than	    (attribute>=abc)    >=

        Less than		    (attribute<=abc)    <=

        Proximity		    (attribute~=abc)    ~=

    :param filters: dictionary of ldap query
    :return: query result list

    .. testcode::

        >>> conn = connect_ldap(['dc1.foo.bar'])
        >>> bind = bind_ldap(conn, r'domain\\user', 'password', tls=True)
        >>> ret = query_ldap(bind, 'dc=foo,dc=bar', ['sn', 'givenName'], objectClass='person', samAccountName='person1')
        >>> print(ret)
    """
    # Init query list
    allow_comp = ['=', '>=', '<=', '~=', '=*', '!']
    strict_comp = ['objectcategory', 'objectclass']
    assert comp in allow_comp, "Comparison operator {0} is not allowed in LDAP query".format(comp)
    query = ['(&']
    # Build query
    for key, value in filters.items():
        if comp == '!':
            query.append("(!{0}={1})".format(key, value))
        else:
            ncomp = '=' if key.lower() in strict_comp else comp
            query.append("({0}{1}{2})".format(key, ncomp, value))
    # Close query
    query.append(')')
    # Query!
    if bind_object.search(search_base=base_search, search_filter=''.join(query), attributes=attributes,
                          search_scope=ldap3.SUBTREE):
        return bind_object.response


def check_ldap_version(bind_object):
    """
    Determines the LDAP version

    :param bind_object: LDAP bind object
    :return: LDAP version code: MS-LDAP or N-LDAP or LDAP

    .. testcode::

        >>> conn = connect_ldap(['dc1.foo.bar'])
        >>> bind = bind_ldap(conn, r'domain\\user', 'password', tls=True)
        >>> ret = check_ldap_version(bind)
        >>> print(ret)
    """
    # Microsoft LDAP
    if 'MICROSOFT' in bind_object.server.info.supported_controls[0]:
        return 'MS-LDAP'
    # Novell LDAP
    elif 'eDirectory' in bind_object.server.info.vendor_version:
        return 'N-LDAP'
    # Standard LDAP
    else:
        return 'LDAP'


def new_user(bind_object, username, **attributes):
    """
    Create a new LDAP user

    :param bind_object: LDAP bind object
    :param username: distinguishedName of user
    :param attributes: Dictionary attributes
    :return: LDAP operation result

    .. testcode::

        >>> conn = connect_ldap(['dc1.foo.bar'])
        >>> bind = bind_ldap(conn, r'domain\\user', 'password', tls=True)
        >>> new_user(bind, 'CN=ex_user1,OU=User_ex,DC=foo,DC=bar', objectClass='user', givenName='User 1', sn='Example')
    """
    # Create user
    bind_object.add(
        username,
        attributes=attributes
    )
    return bind_object.result


def set_user(bind_object, username, **attributes):
    """
    Modify an exists LDAP user

    :param bind_object: LDAP bind object
    :param username: distinguishedName of user
    :param attributes: Dictionary attributes
    :return: LDAP operation result

    .. testcode::

        >>> conn = connect_ldap(['dc1.foo.bar'])
        >>> bind = bind_ldap(conn, r'domain\\user', 'password', tls=True)
        >>> set_user(bind, 'CN=ex_user1,OU=User_ex,DC=foo,DC=bar', givenName='User 1', sn='Example')
    """
    # Convert value to tuple
    for key, value in attributes.items():
        attributes[key] = (ldap3.MODIFY_REPLACE, value)
    # Modify user
    bind_object.modify(
        username,
        attributes
    )
    return bind_object.result


def delete_user(bind_object, username):
    """
    Modify an exists LDAP user

    :param bind_object: LDAP bind object
    :param username: distinguishedName of user
    :return: LDAP operation result

    .. testcode::

        >>> conn = connect_ldap(['dc1.foo.bar'])
        >>> bind = bind_ldap(conn, r'domain\\user', 'password', tls=True)
        >>> delete_user(bind, 'CN=ex_user1,OU=User_ex,DC=foo,DC=bar')
    """
    bind_object.delete(username)
    return bind_object.result


def set_user_password(bind_object, username, password, *, ldap_version='LDAP'):
    """
    Set password to LDAP user

    :param bind_object: LDAP bind object
    :param username: distinguishedName of user
    :param password: password to set of user
    :param ldap_version: LDAP version (LDAP or MS-LDAP)
    :return: None

    .. testcode::

        >>> conn = connect_ldap('dc1.foo.bar')
        >>> bind = bind_ldap(conn, r'domain\\user', 'password', tls=True)
        >>> new_user(bind, 'CN=ex_user1,OU=User_ex,DC=foo,DC=bar', givenName='User 1', sn='Example')
        >>> set_user_password(bind, 'CN=ex_user1,OU=User_ex,DC=foo,DC=bar', 'password', ldap_version='MS-LDAP')
        >>> set_user(bind, 'CN=ex_user1,CN=Users,DC=office,DC=bol', pwdLastSet=-1, userAccountControl=66048)
    """
    # Set password
    if ldap_version == 'LDAP':
        bind_object.extend.standard.modify_password(username, new_password=password,
                                                    old_password=None)
    elif ldap_version == 'MS-LDAP':
        bind_object.extend.microsoft.modify_password(username, new_password=password, old_password=None)
    elif ldap_version == 'N-LDAP':
        bind_object.extend.NovellExtendedOperations.set_universal_password(username, new_password=password,
                                                                           old_password=None)
    else:
        bind_object.extend.standard.modify_password(username, new_password=password,
                                                    old_password=None)


def add_to_group(bind_object, groupname, members):
    """
    Add a member of exists LDAP group

    :param bind_object: LDAP bind object
    :param groupname: distinguishedName of group
    :param members: List of a new members
    :return: LDAP operation result

    .. testcode::

        >>> conn = connect_ldap('dc1.foo.bar')
        >>> bind = bind_ldap(conn, r'domain\\user', 'password', tls=True)
        >>> add_to_group(bind, 'CN=ex_group1,OU=Groups,DC=foo,DC=bar', 'CN=ex_user1,CN=Users,DC=office,DC=bol')
    """
    # Modify group members
    bind_object.modify(
        groupname,
        {'member': (ldap3.MODIFY_ADD, members)}
    )
    return bind_object.result


def remove_to_group(bind_object, groupname, members):
    """
    Remove a member of exists LDAP group

    :param bind_object: LDAP bind object
    :param groupname: distinguishedName of group
    :param members: List of a removed members
    :return: LDAP operation result

    .. testcode::

        >>> conn = connect_ldap('dc1.foo.bar')
        >>> bind = bind_ldap(conn, r'domain\\user', 'password', tls=True)
        >>> remove_to_group(bind, 'CN=ex_group1,OU=Groups,DC=foo,DC=bar', 'CN=ex_user1,CN=Users,DC=office,DC=bol')
    """
    # Modify group members
    bind_object.modify(
        groupname,
        {'member': (ldap3.MODIFY_DELETE, members)}
    )
    return bind_object.result


def filetime_to_datetime(filetime):
    """
    Convert MS filetime LDAP to datetime

    :param filetime: filetime number (nanoseconds)
    :return: datetime object

    .. testcode::

        >>> dt = filetime_to_datetime(132130209369676516)
        >>> print(dt)
    """
    # January 1, 1970 as MS filetime
    epoch_as_filetime = 116444736000000000
    us = (filetime - epoch_as_filetime) // 10
    return datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=us)


def datetime_to_filetime(date_time):
    """
    Convert datetime to LDAP MS filetime

    :param date_time: datetime object
    :return: filetime number

    .. testcode::

        >>> ft = datetime_to_filetime(datetime.datetime(2001, 1, 1))
        >>> print(ft)
    """
    # January 1, 1970 as MS filetime
    epoch_as_filetime = 116444736000000000
    filetime = epoch_as_filetime + (int(date_time.timestamp())) * 10000000
    return filetime + (date_time.microsecond * 10)


def timestamp_to_datetime(timestamp):
    """
    Convert LDAP Kerberos timestamp LDAP to datetime

    :param timestamp: kerberos timestamp string
    :return: datetime object

    .. testcode::

        >>> dt = timestamp_to_datetime('20200903053604Z')
        >>> print(dt)
    """
    return datetime.datetime.strptime(timestamp, '%Y%m%d%H%M%S' + 'Z')


def datetime_to_timestamp(date_time):
    """
    Convert datetime to LDAP Kerberos timestamp

    :param date_time: datetime object
    :return: kerberos timestamp string

    .. testcode::

        >>> ft = datetime_to_timestamp(datetime.datetime(1986, 1, 25))
        >>> print(ft)
    """
    return date_time.strftime('%Y%m%d%H%M%S' + 'Z')


def get_time_sync(timedelta):
    """
    It takes the date for synchronization

    :param timedelta: Time difference to subtract (string: 1s, 2m, 3h, 4d, 5w)
    :return: datetime object

    .. testcode::

        >>> td = get_time_sync('1d')
        >>> print(td)
    """
    # Dictionary of units
    units = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}
    # Extract info of timedelta
    count = int(timedelta[:-1])
    unit = units[timedelta[-1]]
    delta = datetime.timedelta(**{unit: count})
    # Calculate timedelta
    return datetime.datetime.now() - delta


def string_to_datetime(string):
    """
    Convert string date to datetime

    :param string: Datetime in string format ('dd/mm/yyyy' or 'mm/dd/yyyy')
    :return: Datetime object

    .. testcode::

        >>> dt = string_to_datetime('28/2/2019')
        >>> print(dt)
    """
    # Try convert 'dd/mm/yyyy'
    try:
        date = datetime.datetime.strptime(string, '%d/%m/%Y')
        # return date object
        return date
    except ValueError:
        pass
    # Try convert 'mm/dd/yyyy'
    try:
        date = datetime.datetime.strptime(string, '%m/%d/%Y')
        # return date object
        return date
    except ValueError:
        return False


def format_mac(mac_address, mac_format='none'):
    """
    Format mac-address with the specified format

    :param mac_address: mac-address in any format
    :param mac_format: mac format are (default=none):

        none 	112233445566\n
        hypen 	11-22-33-44-55-66\n
        colon 	11:22:33:44:55:66\n
        dot	    1122.3344.5566\n

    :return: mac-address with the specified format

    .. testcode::

        >>> m = format_mac('1A2b3c4D5E6F', 'dot')
        >>> print(m)
    """
    # Set format
    form = {
        'none': lambda x: x.replace('.', '').replace('-', '').replace(':', '').lower(),
        'hypen': lambda x: '-'.join([x[i:i + 2] for i in range(0, len(x), 2)]
                                    ).replace('.', '').replace(':', '').lower(),
        'colon': lambda x: ':'.join([x[i:i + 2] for i in range(0, len(x), 2)]
                                    ).replace('.', '').replace('-', '').lower(),
        'dot': lambda x: '.'.join([x[i:i + 4] for i in range(0, len(x), 4)]
                                  ).replace(':', '').replace('-', '').lower()
    }
    mac = form.get('none')(mac_address)
    # Get format
    try:
        return form.get(mac_format)(mac)
    except TypeError:
        print('ERROR: "{0}" format not available. Available: "none", "hypen", "colon", "dot".'.format(mac_format))
        return mac


def connect_client(client, user, password):
    """
    Connect to client with WINRM protocol

    :param client: hostname or ip address
    :param user: username used for connection on client
    :param password: password of user
    :return: WINRM protocol object

    .. testcode::

        >>> cl = connect_client('host1', r'domain\\user', 'password')
        >>> print(cl)
    """
    # Create protocol object
    protocol = winrm.protocol.Protocol(
        endpoint='http://{0}:5985/wsman'.format(client),
        transport='ntlm',
        username='{0}'.format(user),
        password='{0}'.format(password),
        server_cert_validation='ignore'
    )
    return protocol


def run_command(protocol, command):
    """
    Run command to a WINRM client

    :param protocol: WINRM protocol object
    :param command: command to run on client
    :return: Output of command

    .. testcode::

        >>> cl = connect_client('host1', r'domain\\user', 'password')
        >>> cmd = run_command(cl, 'ipconfig /all')
        >>> print(cmd)
    """
    # Open shell
    shell = protocol.open_shell()
    # Run command
    command = protocol.run_command(shell, '{0}'.format(command))
    # Get a standard output, standard error and status code
    std_out, std_err, status_code = protocol.get_command_output(shell, command)
    # Clean a shell and close
    protocol.cleanup_command(shell, command)
    protocol.close_shell(shell)
    # return all
    return std_out, std_err, status_code


def get_mac_address(protocol, *exclude):
    """
    Get mac-addresses to remote client

    :param protocol: WINRM protocol object
    :return: list mac-address

    .. testcode::

        >>> cl = connect_client('host1', r'domain\\user', 'password')
        >>> m = get_mac_address(cl)
        >>> print(m)
    """
    # Get all mac-address on machine
    macs = list(run_command(protocol, 'getmac /fo csv /v'))
    # Skip the first line of output
    mac_list = macs[0].splitlines()[1:]
    # Process all mac-addresses
    if mac_list:
        ret = list()
        for mac in mac_list:
            mac = mac.decode('ascii')
            # Check exclusion
            for exc in exclude:
                exclusion = True if exc in mac else False
                if exclusion:
                    break
            else:
                ret.append(mac)
        ret = [r.split(',')[2].strip('"') for r in ret]
        # Return list of mac-address
        return ret


def get_client_user(protocol):
    """
    Get the last user who logged in to the machine

    :param protocol: WINRM protocol object
    :return: user string

    .. testcode::

        >>> cl = connect_client('host1', r'domain\\user', 'password')
        >>> u = get_client_user(cl)
        >>> print(u)
    """
    # Get the users connected
    users = list(run_command(protocol, 'quser'))
    # Skip the first line of output
    user_list = users[0].splitlines()[1:]
    if user_list:
        # Process all users
        ret = list()
        for user in user_list:
            user = user.decode('ascii').strip()
            ret.append(user.split())
        # Get last user: 0:USERNAME, 1:SESSIONNAME, 2:ID, 3:STATE, 4:IDLE TIME, 5:LOGON DATE, 6:LOGON TIME
        return ret


def check_vlan_attributes(value, method='like', *attributes):
    """
    Check VLAN attributes with like or match method

    :param value: value to check
    :param method: 'like' or 'match'
    :param attributes: list of attributes
    :return: boolean

    .. testcode::

        >>> conn = connect_ldap(['dc1.foo.bar'])
        >>> bind = bind_ldap(conn, r'domain\\user', 'password', tls=True)
        >>> user = query_ldap(bind, 'dc=foo,dc=bar', ['memberof', 'description', 'department'],
                             objectClass='person', samAccountName='person1')
        >>> ok = check_vlan_attributes('business', user[0].get('attributes').get('description'))
        >>> print(ok)
    """
    # if like...
    if method == 'like':
        for attr in attributes:
            if value in attr:
                return True
    # if match...
    elif method == 'match':
        for attr in attributes:
            if value == attr:
                return True
    # else...false
    else:
        return False


# endregion

# region Start process

if __name__ == '__main__':

    def parse_arguments():
        """
        Function that captures the parameters and the arguments in the command line

        :return: Parser object
        """
        # Create a common parser
        common_parser = argparse.ArgumentParser(add_help=False)
        common_parser.add_argument('--verbose', '-v', help='enable verbosity, for debugging process.',
                                   dest='verbose', action='store_true')
        # Create a principal parser
        parser_object = argparse.ArgumentParser(prog='vmam', description='VLAN Mac-address Authentication Manager',
                                                parents=[common_parser])
        parser_object.add_argument('--version', '-V', action='version', version='%(prog)s ' + VERSION)
        # Create sub_parser "action"
        action_parser = parser_object.add_subparsers(title='action', description='valid action',
                                                     help='available actions for vmam command', dest='action')
        # config session
        config_parser = action_parser.add_parser('config', help='vmam configuration options', parents=[common_parser])
        group_config = config_parser.add_argument_group(title='configuration')
        group_config_mutually = group_config.add_mutually_exclusive_group(required=True)
        group_config_mutually.add_argument('--new', '-n', help='generate new configuration file', dest='new_conf',
                                           action='store', nargs='?', const=(get_platform()['conf_default']),
                                           metavar='CONF_FILE')
        group_config_mutually.add_argument('--get-cmd', '-g',
                                           help='get information for a radius server and switch/router.',
                                           dest='get_conf', action='store', nargs='?',
                                           const=(get_platform()['conf_default']), metavar='CONF_FILE')
        # start session
        start_parser = action_parser.add_parser('start', help='vmam automatic process options', parents=[common_parser])
        group_start = start_parser.add_argument_group(title='automatic options')
        group_start.add_argument('--config-file', '-c', help='parse configuration file', dest='conf', action='store',
                                 nargs='?', default=get_platform()['conf_default'], metavar='CONF_FILE')
        group_start.add_argument('--daemon', '-d', help='start automatic process as a daemon', dest='daemon',
                                 action='store_true')
        # mac session
        mac_parser = action_parser.add_parser('mac', help='vmam manual process options', parents=[common_parser])
        group_mac = mac_parser.add_argument_group(title='manual options')
        group_mac_mutually = group_mac.add_mutually_exclusive_group(required=True)
        group_mac_mutually.add_argument('--add', '-a', help='add/modify mac-address to LDAP server', dest='add',
                                        action='store', nargs=1, metavar='MAC_ADDR')
        group_mac_mutually.add_argument('--remove', '-r', help='remove mac-address to LDAP server', dest='remove',
                                        action='store', nargs=1, metavar='MAC_ADDR')
        group_mac_mutually.add_argument('--disable', '-d', help='disable mac-address to LDAP server', dest='disable',
                                        action='store', nargs=1, metavar='MAC_ADDR')
        group_mac.add_argument('--config-file', '-c', help='parse configuration file', dest='conf', action='store',
                               nargs='?', default=get_platform()['conf_default'], metavar='CONF_FILE')
        group_mac.add_argument('--force', '-f', help='force action', dest='force', action='store_true')
        group_mac.add_argument('--vlan-id', '-i', help='vlan-id number', dest='vlanid', action='store',
                               nargs=1, metavar='VLAN_ID', type=int, required=('--add' in sys.argv or '-a' in sys.argv))
        group_mac.add_argument('--description', '-D', help='description field', dest='description', action='store',
                               metavar='description')
        # Return parser object
        return parser_object


    def cli_check_module():
        """
        CLI function: Check if dependencies modules is installed

        :return: Boolean
        """
        # List of dependencies modules
        mods = ['daemon', 'ldap3', 'winrm', 'yaml']
        # Check import dependencies
        for mod in mods:
            assert check_module(mod), 'Install "{0}" module with pip install.'.format(mod)


    def cli_check_list(mac, mac_list):
        """
        Check list if contains one mac-address

        :param mac: mac-address searched in the file
        :param mac_list: list of mac-addresses
        :return: boolean
        """
        # Check if mac-address in a list
        if mac in mac_list:
            return True
        else:
            return False


    def cli_select_action(action):
        """
        Select action

        :param action: Sub-parser action
        :return: action function
        """
        # Define action dictionary
        actions = {
            'config': cli_config,
            'mac': cli_mac,
            'start': cli_start
        }
        return actions.get(action, 'No action available')


    def cli_new_mac(config, bind, mac, vgroup, logger, arguments, description=None):
        """
        Create or modify mac-address LDAP user

        :param config: YAML configuration
        :param bind: LDAP bind object
        :param mac: mac-address in any format
        :param vgroup: vlan-id than represent the LDAP group
        :param logger: logging object
        :param arguments: parser object arguments
        :param description: description string value for LDAP user
        :return: None
        """
        mac = format_mac(mac, config['VMAM']['mac_format'])
        print('Add mac-address {0} on LDAP servers {1} in {2} VLAN group'.format(
            mac, ','.join(config['LDAP']['servers']), vgroup))
        debugger(arguments.verbose, logger, 'Add mac-address {0} on LDAP servers {1} in {2} VLAN group'.format(
            mac, ','.join(config['LDAP']['servers']), vgroup))
        ldap_v = check_ldap_version(bind)
        ids = 'cn' if ldap_v == 'MS-LDAP' else 'uid'
        dn = '{0}={1},{2}'.format(ids, mac, config['LDAP']['mac_user_base_dn'])
        # Query: check if mac-address exist
        debugger(arguments.verbose, logger, 'Exist mac-address {0} on LDAP servers {1}?'.format(
            mac, ','.join(config['LDAP']['servers'])))
        # Create the attribute dictionary
        if ldap_v == 'MS-LDAP':
            login_attr = 'samaccountname'
            user_class = 'user'
            group_class = 'group'
            group_name = 'name'
            u_search_attributes = ['memberof']
            g_search_attributes = ['member', 'distinguishedname']
            attrs = {'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
                     'givenname': 'mac-address',
                     'sn': mac,
                     login_attr: mac,
                     'userprincipalname': '{0}@{1}'.format(mac, config['LDAP']['domain']),
                     'description': description}
        else:
            # Get uidNumber and gidNumber
            ug = query_ldap(bind, config['LDAP']['mac_user_base_dn'], ['uidNumber'], uidNumber='*')
            if ug:
                uid = ug[-1]['attributes']['uidNumber'] + 1
                gid = uid + 1
            else:
                uid = 1
                gid = 2
            login_attr = 'uid'
            user_class = 'inetorgperson'
            group_class = 'posixgroup'
            group_name = 'cn'
            u_search_attributes = ['memberof']
            g_search_attributes = ['member', 'dn']
            attrs = {'objectClass': ['top', 'person', 'organizationalPerson', 'inetOrgPerson',
                                     'posixAccount', 'krbPrincipalAux'],
                     'givenname': 'mac-address',
                     'sn': mac,
                     login_attr: mac,
                     'cn': mac,
                     'homeDirectory': '/tmp/{0}'.format(mac),
                     'gidNumber': gid,
                     'uidNumber': uid,
                     'krbPrincipalname': '{0}@{1}'.format(mac, config['LDAP']['domain']),
                     'description': description}
        ret = query_ldap(bind, config['LDAP']['mac_user_base_dn'], [login_attr, 'description'],
                         **{login_attr: mac})
        if not ret or not ret[0].get('dn'):
            debugger(arguments.verbose, logger, 'Mac-address {0} not exists on LDAP servers {1}'.format(
                mac, ','.join(config['LDAP']['servers'])))
            # Check write_attrib on configuration file
            vflag = 'VMAM_MANUAL {0}'.format(VERSION) if arguments.action == 'mac' else 'VMAM_AUTO {0}'.format(VERSION)
            if config['LDAP']['write_attrib']:
                attrs[config['LDAP']['write_attrib']] = vflag
            else:
                attrs['employeetype'] = vflag
            # Create mac-address user
            try:
                new_user(bind, dn, **attrs)
                print('Mac-address {0} created on LDAP servers {1} in {2} VLAN group'.format(
                    dn, ','.join(config['LDAP']['servers']), vgroup))
            except Exception as err:
                print('ERROR:', err)
                logger.error(err)
                exit(8)
            logger.info('Add mac-address {0} on LDAP servers {1} in {2} VLAN group.'.format(
                dn, ','.join(config['LDAP']['servers']), vgroup))
            exist = False
        else:
            debugger(arguments.verbose, logger, 'Mac-address {0} exists on LDAP servers {1}'.format(
                ret[0].get('dn'), ','.join(config['LDAP']['servers'])))
            print('Mac address {0} already exists on LDAP servers {1}'.format(
                ret[0].get('dn'), ','.join(config['LDAP']['servers'])))
            # Modify description
            if description not in ret[0]['attributes'].get('description'):
                set_user(bind, dn, description=description)
            # Re-enable user if has been disabled
            if ldap_v == 'MS-LDAP':
                set_user(bind, dn, pwdLastSet=-1, userAccountControl=66048)
            else:
                set_user(bind, dn, nsaccountlock='False')
            exist = True
        # Add VLAN and custom LDAP group
        # VLAN-ID group
        try:
            debugger(arguments.verbose, logger, 'Verify VLAN group {0} to user {1}'.format(
                vgroup, dn))
            for key, value in config['VMAM']['vlan_group_id'].items():
                # Check exist VLAN-ID in configuration file
                if vgroup == key:
                    g = query_ldap(bind, config['LDAP']['user_base_dn'], g_search_attributes,
                                   **{'objectclass': group_class, group_name: value})
                    u = query_ldap(bind, config['LDAP']['mac_user_base_dn'], u_search_attributes,
                                   **{'objectclass': user_class, login_attr: mac})
                    gdn = g[0]['dn'] if g else None
                    umember = u[0]['attributes']['memberof'] if u else []
                    # Add VLAN LDAP group to user mac address
                    if gdn not in umember:
                        if gdn:
                            add_to_group(bind, gdn, dn)
                            print('Add VLAN group {0} to user {1}'.format(gdn, dn))
                            logger.info('Add VLAN group {0} to user {1}'.format(gdn, dn))
                    else:
                        debugger(arguments.verbose, logger, 'VLAN group {0} already added to user {1}'.format(
                            config['VMAM']['vlan_group_id'][vgroup], dn))
                    break
            else:
                print('VLAN-ID group {0} does not exist. See the configuration file {1}'.format(
                    vgroup, arguments.conf))
                exit(4)
        except Exception as err:
            print('ERROR:', err)
            logger.error(err)
            exit(16)
        # Custom group
        try:
            if config['LDAP']['other_group']:
                debugger(arguments.verbose, logger, 'Verify custom groups {0} to user {1}'.format(
                    ','.join(config['LDAP']['other_group']), dn))
                for group in config['LDAP']['other_group']:
                    g = query_ldap(bind, config['LDAP']['user_base_dn'], g_search_attributes,
                                   **{'objectclass': group_class, group_name: group})
                    u = query_ldap(bind, config['LDAP']['mac_user_base_dn'], u_search_attributes,
                                   **{'objectclass': user_class, login_attr: mac})
                    gdn = g[0]['dn'] if g else None
                    umember = u[0]['attributes']['memberof'] if u else []
                    # Add VLAN LDAP group to user mac address
                    if gdn not in umember:
                        if gdn:
                            add_to_group(bind, gdn, dn)
                            print('Add custom groups {0} to user {1}'.format(gdn, dn))
                            logger.info('Add custom groups {0} to user {1}'.format(gdn, dn))
                    else:
                        debugger(arguments.verbose, logger, 'Custom groups {0} already added to user {1}'.format(
                            ','.join(config['LDAP']['other_group']), dn))
                    break
        except Exception as err:
            print('ERROR:', err)
            logger.error(err)
            exit(17)
        # Check if other VLAN groups are assigned to the user
        debugger(arguments.verbose, logger, 'Verify if other VLAN groups are assigned to the user {0}'.format(dn))
        try:
            # Get all VLAN group from user
            for key, value in config['VMAM']['vlan_group_id'].items():
                # Check if VLAN-ID isn't equal
                if vgroup != key:
                    g = query_ldap(bind, config['LDAP']['user_base_dn'], g_search_attributes,
                                   **{'objectclass': group_class, group_name: value})
                    u = query_ldap(bind, config['LDAP']['mac_user_base_dn'], u_search_attributes,
                                   **{'objectclass': user_class, login_attr: mac})
                    gdn = g[0]['dn'] if g else None
                    umember = u[0]['attributes']['memberof'] if u else []
                    # Remove member of group
                    if gdn in umember:
                        if gdn:
                            remove_to_group(bind, gdn, dn)
                            print('Remove VLAN group {0} to user {1}'.format(gdn, dn))
                            logger.info('Remove VLAN group {0} to user {1}'.format(gdn, dn))
        except Exception as err:
            print('ERROR:', err)
            logger.error(err)
            exit(18)
        # Set password
        try:
            if not exist:
                debugger(arguments.verbose, logger, 'Set password to user {0}'.format(dn))
                set_user_password(bind, dn, mac, ldap_version=ldap_v)
                if ldap_v == 'MS-LDAP':
                    # Enable user
                    try:
                        debugger(arguments.verbose, logger, 'Enable user {0}'.format(dn))
                        set_user(bind, dn, pwdlastset=-1, useraccountcontrol=66048)
                    except Exception as err:
                        print('ERROR:', err)
                        logger.error(err)
                        exit(10)
        except Exception as err:
            print('ERROR:', err)
            logger.error(err)
            exit(9)
        if not exist:
            print('Mac-address user {0} successfully created'.format(mac))
            logger.info('Mac-address user {0} successfully created'.format(mac))


    def cli_disable_mac(config, bind, mac, logger, arguments, description=None):
        """
        Disable mac-address LDAP user

        :param config: YAML configuration
        :param bind: LDAP bind object
        :param mac: mac-address in any format
        :param logger: logging object
        :param arguments: parser object arguments
        :param description: description string value for LDAP user
        :return: None
        """
        mac = format_mac(mac, config['VMAM']['mac_format'])
        print('Disable mac-address {0} on LDAP servers {1}'.format(mac, ','.join(config['LDAP']['servers'])))
        debugger(arguments.verbose, logger, 'Disable mac-address {0} on LDAP servers {1}'.format(
            mac, ','.join(config['LDAP']['servers'])))
        ldap_v = check_ldap_version(bind)
        ids = 'cn' if ldap_v == 'MS-LDAP' else 'uid'
        dn = '{0}={1},{2}'.format(ids, mac, config['LDAP']['mac_user_base_dn'])
        # Query: check if mac-address exist
        debugger(arguments.verbose, logger, 'Exist mac-address {0} on LDAP servers {1}?'.format(
            mac, ','.join(config['LDAP']['servers'])))
        if ldap_v == 'MS-LDAP':
            login_attr = 'samaccountname'
            u_search_attributes = ['samaccountname', 'description', 'useraccountcontrol']
        else:
            login_attr = 'uid'
            u_search_attributes = ['uid', 'description', 'nsaccountlock']
        ret = query_ldap(bind, config['LDAP']['mac_user_base_dn'], u_search_attributes, **{login_attr: mac})
        if ret and ret[0].get('dn'):
            force = confirm('Do you want to disable {0} '
                            'mac-address?'.format(mac)) if 'force' not in arguments or not arguments.force else True
            if force:
                try:
                    if ldap_v == 'MS-LDAP':
                        if ret[0].get('attributes').get('useraccountcontrol') != 514:
                            set_user(bind, dn, useraccountcontrol=514)
                            # Modify description
                            if description not in ret[0].get('attributes').get('description'):
                                set_user(bind, dn, description=description)
                            print('Mac-address {0} successfully disabled'.format(mac))
                            logger.info('Mac-address {0} successfully disabled'.format(mac))
                        else:
                            print('Mac-address {0} is already disabled'.format(mac))
                    else:
                        if 'True' not in ret[0].get('attributes').get('nsaccountlock'):
                            set_user(bind, dn, nsaccountlock='True')
                            # Modify description
                            if description not in ret[0].get('attributes').get('description'):
                                set_user(bind, dn, description=description)
                            print('Mac-address {0} successfully disabled'.format(mac))
                            logger.info('Mac-address {0} successfully disabled'.format(mac))
                        else:
                            print('Mac-address {0} is already disabled'.format(mac))
                except Exception as err:
                    print('ERROR:', err)
                    logger.error(err)
                    exit(11)
        else:
            print('ERROR: Mac-address {0} does not exists'.format(mac))
            exit(8)


    def cli_delete_mac(config, bind, mac, logger, arguments):
        """
        Delete mac-address LDAP user

        :param config: YAML configuration
        :param bind: LDAP bind object
        :param mac: mac-address in any format
        :param logger: logging object
        :param arguments: parser object arguments
        :return: None
        """
        mac = format_mac(mac, config['VMAM']['mac_format'])
        print('Delete mac-address {0} on LDAP servers {1}'.format(mac, ','.join(config['LDAP']['servers'])))
        debugger(arguments.verbose, logger, 'Delete mac-address {0} on LDAP servers {1}'.format(
            mac, ','.join(config['LDAP']['servers'])))
        ldap_v = check_ldap_version(bind)
        ids = 'cn' if ldap_v == 'MS-LDAP' else 'uid'
        dn = '{0}={1},{2}'.format(ids, mac, config['LDAP']['mac_user_base_dn'])
        # Query: check if mac-address exist
        debugger(arguments.verbose, logger, 'Exist mac-address {0} on LDAP servers {1}?'.format(
            mac, ','.join(config['LDAP']['servers'])))
        login_attr = 'samaccountname' if ldap_v == 'MS-LDAP' else 'uid'
        u_search_attributes = ['samaccountname'] if ldap_v == 'MS-LDAP' else ['uid']
        ret = query_ldap(bind, config['LDAP']['mac_user_base_dn'], u_search_attributes, **{login_attr: mac})
        if ret and ret[0].get('dn'):
            force = confirm('Do you want to delete {0} '
                            'mac-address?'.format(mac)) if 'force' not in arguments or not arguments.force else True
            if force:
                try:
                    delete_user(bind, dn)
                except Exception as err:
                    print('ERROR:', err)
                    logger.error(err)
                    exit(12)
                print('Mac-address {0} successfully deleted'.format(mac))
                logger.info('Mac-address {0} successfully deleted'.format(mac))
        else:
            print('ERROR: Mac-address {0} does not exists'.format(mac))
            exit(8)


    def cli_config(arguments):
        """
        Configuration process

        :param arguments: Arguments list
        :return: None
        """
        # Select new or get
        if arguments.new_conf:
            # Create a new configuration file
            if not os.path.exists(arguments.new_conf):
                try:
                    new_config(arguments.new_conf)
                except FileNotFoundError as err:
                    print('ERROR: I was unable to write the file: {0}'.format(err))
                    exit(2)
            else:
                print('Configuration file exists: {0}.'.format(arguments.new_conf))
                # Exists? Overwrite?
                if confirm('Overwrite with a new one?'):
                    try:
                        os.remove(arguments.new_conf)
                        new_config(arguments.new_conf)
                    except OSError as err:
                        print('ERROR: I was unable to overwrite the file: {0}'.format(err))
                        exit(2)
        elif arguments.get_conf:
            # Read configuration file
            if os.path.exists(arguments.get_conf):
                try:
                    cfg = read_config(arguments.get_conf)
                    print("""
                    NETWORK ARCHITECTURE

                    +--------------------------+Spend credential+--------------------------+
                    |                          +--------------->+                          |
                    |          radius          |                |          ldap            |
                    |                          +<---------------+                          |
                    +--------------------------+ Return VLAN-ID +--------------------------+
                               ^     |
                        Send   |     |  Received
                        MAC    |     |  VLAN-ID
                               |     |
                               |     v
                    +--------------------------+
                    |                          |
                    |       switch/router      |
                    |                          |
                    +--------------------------+
                               ^     |
                      Send     |     |  Received
                      request  |     |  VLAN
                               |     v
                            +-----------+
                            |           |
                            |           |
                            |   client  |
                            |           |
                            |           |
                            +-----------+

                    LEGEND

                    client: Windows/Linux/MacOSX/other
                    switch/router: network appliance
                    radius: freeradius/Microsoft radius
                    ldap: Active Directory/389/FreeIPA/eDirectory/other LDAP server
                    
                    CONFIGURATION
                    
                    1) Configure your switch/router to send RADIUS Access-Request with this VLAN-ID: {0}
                    2) Configure your rasius server with the policy that allows you to access the network.
                       The LDAP groups to be placed in the policy networks are as follows: {1}
                    3) Create the following groups on your LDAP server: {2} {3}
                    4) Start using vmam! 
                                """.format(list(cfg['VMAM']['vlan_group_id'].keys()), cfg['VMAM']['vlan_group_id'],
                                           list(cfg['VMAM']['vlan_group_id'].values()),
                                           cfg['LDAP']['other_group']))
                except FileNotFoundError as err:
                    print('ERROR: I was unable to read the file: {0}'.format(err))
                    exit(2)
            else:
                print('ERROR: Configuration file not exists: {0}. See "vmam config --new" option.'.format(
                    arguments.get_conf))
                exit(3)


    def cli_mac(arguments):
        """
        Manual mac-address process

        :param arguments: Arguments list
        :return: None
        """
        # Read the configuration file
        cfg = read_config(arguments.conf)
        # Create log writer
        wt = logwriter(cfg['VMAM']['log'])
        debugger(arguments.verbose, wt, 'Start in manual mode')
        # Check mandatory entry on configuration file
        debugger(arguments.verbose, wt, 'Check mandatory fields on configuration file {0}'.format(arguments.conf))
        check_config(arguments.conf)
        # Connect LDAP servers
        debugger(arguments.verbose, wt,
                 'Connect to LDAP servers {0}'.format(','.join(cfg['LDAP']['servers'])))
        srv = connect_ldap(cfg['LDAP']['servers'], ssl=cfg['LDAP']['ssl'])
        # Bind LDAP server
        debugger(arguments.verbose, wt, 'Bind on LDAP servers {0} with user {1}'.format(
            ','.join(cfg['LDAP']['servers']), cfg['LDAP']['bind_user']))
        bind = bind_ldap(srv, cfg['LDAP']['bind_user'], cfg['LDAP']['bind_pwd'], tls=cfg['LDAP']['tls'])
        # Check actions
        if arguments.add:
            # Check blacklist
            if cfg.get('VMAM').get('black_list'):
                debugger(arguments.verbose, wt, 'Check black list file {0}'.format(cfg.get('VMAM').get('black_list')))
                # Verify if black list file exists
                if os.path.exists(cfg['VMAM']['black_list']):
                    # Transform file in a list
                    mac_list = get_mac_from_file(cfg['VMAM']['black_list'], cfg['VMAM']['mac_format'])
                    # Now, check if mac is blacklisted
                    if cli_check_list(''.join(arguments.add), mac_list):
                        print('WARNING: The mac-address {0} is blacklisted. See black list file: {1}'.format(
                            ''.join(arguments.add), cfg['VMAM']['black_list']
                        ))
                        wt.warning('The mac-address {0} is blacklisted. See black list file: {1}'.format(
                            ''.join(arguments.add), cfg['VMAM']['black_list']
                        ))
                        exit(13)
                else:
                    print('ERROR: The file {0} does not exist.'.format(cfg['VMAM']['black_list']))
                    wt.error('The file {0} does not exist.'.format(cfg['VMAM']['black_list']))
                    exit(3)
            vlanid = arguments.vlanid[0]
            desc = arguments.description if arguments.description else ''.join(arguments.add)
            cli_new_mac(cfg, bind, ''.join(arguments.add), vlanid, wt, arguments, description=desc)
        elif arguments.disable:
            desc = arguments.description if arguments.description else ''.join(arguments.disable)
            cli_disable_mac(cfg, bind, ''.join(arguments.disable), wt, arguments, description=desc)
        elif arguments.remove:
            cli_delete_mac(cfg, bind, ''.join(arguments.remove), wt, arguments)
        # Unbind LDAP connection
        debugger(arguments.verbose, wt, 'Unbind on LDAP servers {0}'.format(','.join(cfg['LDAP']['servers'])))
        unbind_ldap(bind)


    def cli_start(arguments):
        """
        Automatic mac-address process

        :param arguments: Arguments list
        :return: None
        """
        global bind_start
        # Read the configuration file
        cfg = read_config(arguments.conf)
        # Create log writer
        wt = logwriter(cfg['VMAM']['log'])
        debugger(arguments.verbose, wt, 'Start in automatic mode')
        # Check mandatory entry on configuration file
        debugger(arguments.verbose, wt, 'Check mandatory fields on configuration file {0}'.format(arguments.conf))
        check_config(arguments.conf)
        # Connect LDAP servers
        debugger(arguments.verbose, wt, 'Connect to LDAP servers {0}'.format(','.join(cfg['LDAP']['servers'])))
        srv = connect_ldap(cfg['LDAP']['servers'], ssl=cfg['LDAP']['ssl'])
        # Bind LDAP server
        if bind_start:
            debugger(arguments.verbose, wt, 'The binding has already been defined. Bind:{0} User:{1}'.format(
                bind_start.bound, cfg['LDAP']['bind_user']))
        else:
            debugger(arguments.verbose, wt, 'Bind on LDAP servers {0} with user {1}'.format(
                ','.join(cfg['LDAP']['servers']), cfg['LDAP']['bind_user']))
            bind_start = bind_ldap(srv, cfg['LDAP']['bind_user'], cfg['LDAP']['bind_pwd'], tls=cfg['LDAP']['tls'])
        # Chek LDAP version
        ldap_v = check_ldap_version(bind_start)
        td = get_time_sync(cfg['LDAP']['time_computer_sync'])
        if ldap_v == 'MS-LDAP':
            debugger(arguments.verbose, wt,
                     'Convert datetime format to filetime format for computer query: {0} ago'.format(
                         cfg['LDAP']['time_computer_sync']))
            ft = datetime_to_filetime(td)
            host_search_attributes = {'objectcategory': 'computer', 'lastlogon': ft}
            host_get_attributes = ['dNSHostName', 'lastlogon']
            hostname_attr = 'dNSHostName'
            user_get_attributes = ['samaccountname']
            user_class_attr = 'person'
            user_login_attr = 'samaccountname'
            group_get_attributes = ['member']
            group_class_attr = 'group'
            group_login_attr = 'name'
        else:
            debugger(arguments.verbose, wt,
                     'Convert datetime format to timestamp format for computer query: {0} ago'.format(
                         cfg['LDAP']['time_computer_sync']))
            ts = datetime_to_timestamp(td)
            host_search_attributes = {'objectClass': 'nshost', 'krbLastPwdChange': ts}
            host_get_attributes = ['fqdn', 'krbLastPwdChange']
            hostname_attr = 'fqdn'
            user_get_attributes = ['uid']
            user_class_attr = 'inetorgperson'
            user_login_attr = 'uid'
            group_get_attributes = ['member']
            group_class_attr = 'posixgroup'
            group_login_attr = 'cn'
        # Query LDAP to take all computer accounts
        computers = query_ldap(bind_start, cfg['LDAP']['computer_base_dn'], host_get_attributes, comp='>=',
                               **host_search_attributes)
        # Check if there are updated computers
        if computers:
            for c_attribute in computers:
                # Connection to the client via WINRM protocol
                if isinstance(c_attribute['attributes'][hostname_attr], list):
                    hostname = c_attribute['attributes'][hostname_attr][0]
                else:
                    hostname = c_attribute['attributes'][hostname_attr]
                debugger(arguments.verbose, wt, 'Try connect to {0} via WINRM'.format(hostname))
                if check_connection(hostname, 5985):
                    try:
                        debugger(arguments.verbose, wt, 'Connected successful to {0} via WINRM'.format(
                            hostname))
                        client = connect_client(hostname, cfg['VMAM']['winrm_user'],
                                                cfg['VMAM']['winrm_pwd'])
                        # Run the commands
                        try:
                            debugger(arguments.verbose, wt, 'Get mac-address of {0}'.format(hostname))
                            # Get all mac-addresses of the computer
                            if cfg['VMAM']['filter_exclude']:
                                macs = get_mac_address(client, *cfg['VMAM']['filter_exclude'])
                            else:
                                macs = get_mac_address(client)
                            # Check mac list
                            if not macs:
                                print('WARNING: There are no mac-addresses present on {0} computer'.format(
                                    hostname))
                                wt.warning('There are no mac-addresses present on {0} computer'.format(
                                    hostname))
                            # Get the last user of the computer
                            debugger(arguments.verbose, wt, 'Get logged in users of {0}'.format(
                                hostname))
                            users = get_client_user(client)
                            # Check user list
                            if not users:
                                print('WARNING: There are no logged in users on {0} computer'.format(
                                    hostname))
                                wt.warning('There are no logged in users on {0} computer'.format(
                                    hostname))
                                continue
                            # Search user on LDAP server
                            try:
                                debugger(arguments.verbose, wt, 'Search user {0} on LDAP'.format(users[0][0]))
                                user = query_ldap(bind_start, cfg['LDAP']['user_base_dn'],
                                                  cfg['LDAP']['verify_attrib'],
                                                  **{'objectclass': user_class_attr, user_login_attr: users[0][0]})
                                # Check the match of the attributes for the creation of the mac-address
                                if user and user[0].get('attributes'):
                                    debugger(arguments.verbose, wt, 'Check the match of the attributes for the '
                                                                    'creation of the mac-address')
                                    # Cycle all match values per user on configuration file
                                    for kid, vid in cfg['VMAM']['user_match_id'].items():
                                        # Cycle all values returned by the user query
                                        for kad, vad in user[0].get('attributes').items():
                                            # Verify if value of user is a string or list
                                            if isinstance(vad, str):
                                                ok = check_vlan_attributes(kid, cfg['LDAP']['match'], vad)
                                            else:
                                                ok = check_vlan_attributes(kid, cfg['LDAP']['match'], *vad)
                                            # Check if the match has taken place
                                            if ok:
                                                for mac in macs:
                                                    # Create mac-address user and assign to VLAN groups
                                                    if 'user' in cfg['LDAP']['add_group_type']:
                                                        desc = 'User: {0}, Computer: {1}'.format(
                                                            users[0][0], c_attribute['attributes'][hostname_attr])
                                                        # Check blacklist
                                                        if cfg.get('VMAM').get('black_list'):
                                                            debugger(arguments.verbose, wt,
                                                                     'Check black list file {0}'.format(
                                                                         cfg.get('VMAM').get('black_list')
                                                                     ))
                                                            # Verify if black list file exists
                                                            if os.path.exists(cfg['VMAM']['black_list']):
                                                                # Transform file in a list
                                                                mac_list = get_mac_from_file(cfg['VMAM']['black_list'],
                                                                                             cfg['VMAM']['mac_format'])
                                                                ret = query_ldap(bind_start,
                                                                                 cfg['LDAP']['mac_user_base_dn'],
                                                                                 user_get_attributes,
                                                                                 **{user_login_attr: mac})
                                                                # Now, check if mac is blacklisted
                                                                if cli_check_list(mac, mac_list):
                                                                    print(
                                                                        'WARNING: The mac-address {0} is blacklisted. '
                                                                        'See black list file: {1}'.format(
                                                                            ''.join(arguments.add),
                                                                            cfg['VMAM']['black_list']
                                                                        ))
                                                                    wt.warning(
                                                                        'The mac-address {0} is blacklisted. '
                                                                        'See black list file: {1}'.format(
                                                                            ''.join(arguments.add),
                                                                            cfg['VMAM']['black_list']
                                                                        ))
                                                                    if ret and ret[0].get('dn'):
                                                                        desc = 'Blacklisted mac-address.'
                                                                        cli_disable_mac(cfg, bind_start,
                                                                                        mac.get('attributes').get(
                                                                                            user_login_attr), wt,
                                                                                        arguments,
                                                                                        description=desc)
                                                                    continue
                                                            else:
                                                                print('ERROR: The file {0} does not exist.'.format(
                                                                    cfg['VMAM']['black_list']))
                                                                wt.error('The file {0} does not exist.'.format(
                                                                    cfg['VMAM']['black_list']))
                                                                exit(3)
                                                        cli_new_mac(cfg, bind_start, mac, vid, wt, arguments,
                                                                    description=desc)
                                                    else:
                                                        debugger(arguments.verbose, wt,
                                                                 'No "user" in configuration file: LDAP->add_group_type'
                                                                 )
                                                # Assign computer to VLAN groups
                                                if 'computer' in cfg['LDAP']['add_group_type']:
                                                    g = query_ldap(bind_start, cfg['LDAP']['user_base_dn'],
                                                                   group_get_attributes,
                                                                   **{'objectclass': group_class_attr,
                                                                      group_login_attr:
                                                                          cfg['VMAM']['vlan_group_id'][vid]})
                                                    gdn = g[0].get('dn')
                                                    cdn = c_attribute.get('dn')
                                                    # Add VLAN LDAP group to computer account
                                                    if cdn not in g[0]['attributes']['member']:
                                                        add_to_group(bind_start, gdn, cdn)
                                                        print('Add VLAN group {0} to computer {1}'.format(gdn,
                                                                                                          cdn))
                                                        wt.info(
                                                            'Add VLAN group {0} to computer {1}'.format(gdn,
                                                                                                        cdn))
                                                    else:
                                                        debugger(arguments.verbose, wt,
                                                                 'VLAN group {0} already added to '
                                                                 'computer {1}'.format(
                                                                     cfg['VMAM']['vlan_group_id'][vid], cdn))
                                                    # Add description to computer account
                                                    set_user(bind_start, c_attribute.get('dn'),
                                                             description='User: {0} Mac: {1}'.format(
                                                                 users[0][0],
                                                                 ' '.join(
                                                                     [format_mac(mac, cfg['VMAM']['mac_format'])
                                                                      for mac in macs]
                                                                 )
                                                             ))
                                                    # Remove other VLAN LDAP group
                                                    for vgkey, vgvalue in cfg['VMAM']['vlan_group_id'].items():
                                                        # Check if VLAN-ID isn't equal
                                                        if vgkey != vid:
                                                            g = query_ldap(bind_start,
                                                                           cfg['LDAP']['user_base_dn'],
                                                                           group_get_attributes,
                                                                           **{'objectclass': group_class_attr,
                                                                              group_login_attr: vgvalue})
                                                            gdn = g[0]['dn']
                                                            gmember = g[0]['attributes']['member']
                                                            # Remove member of group
                                                            if cdn in gmember:
                                                                remove_to_group(bind_start, gdn, cdn)
                                                                print(
                                                                    'Remove VLAN group {0} to computer {1}'.format(
                                                                        gdn, cdn))
                                                                wt.info(
                                                                    'Remove VLAN group {0} to computer {1}'.format(
                                                                        gdn, cdn))
                                                else:
                                                    debugger(arguments.verbose, wt,
                                                             'No "computer" in configuration file: '
                                                             'LDAP->add_group_type'
                                                             )
                                            else:
                                                continue
                            except Exception as err:
                                print('ERROR:', err)
                                wt.error(err)
                                continue
                        except Exception as err:
                            print('ERROR:', err)
                            wt.error(err)
                            continue
                    except Exception as err:
                        print('ERROR:', err)
                        wt.error(err)
                        continue
                else:
                    debugger(arguments.verbose, wt, 'WINRM is not running on the computer {0}'.format(hostname))
        # Disable/Delete process
        if cfg['VMAM'].get('remove_process'):
            debugger(arguments.verbose, wt, 'Start disable/delete process')
            # Get old mac-address user
            td = get_time_sync(cfg['LDAP']['mac_user_ttl'])
            write_attrib = cfg['LDAP']['write_attrib'] if cfg['LDAP']['write_attrib'] else 'employeetype'
            if ldap_v == 'MS-LDAP':
                debugger(arguments.verbose, wt,
                         'Convert datetime format to filetime format for mac-address user query. '
                         'mac ttl: {0} ago'.format(
                             cfg['LDAP']['mac_user_ttl']
                         ))
                ts = datetime_to_filetime(td)
                mac_get_attributes = ['name', write_attrib, 'samaccountname', 'distinguishedname', 'whencreated',
                                      'description', 'lastlogontimestamp']
                mac_filter = {'objectClass': 'user', 'lastlogontimestamp': ts}
                mac_created_attr = 'whencreated'
                mac_lastlogon_attr = 'lastlogontimestamp'
                mac_login_attr = 'samaccountname'
            else:
                debugger(arguments.verbose, wt,
                         'Convert datetime format to timestamp format for mac-address user query. '
                         'mac ttl: {0} ago'.format(cfg['LDAP']['mac_user_ttl']))
                ts = datetime_to_timestamp(td)
                mac_get_attributes = ['cn', write_attrib, 'uid', 'createTimestamp', 'description',
                                      'krbLastSuccessfulAuth']
                mac_filter = {'objectClass': 'posixAccount', 'krbLastSuccessfulAuth': ts}
                mac_created_attr = 'createTimestamp'
                mac_lastlogon_attr = 'krbLastSuccessfulAuth'
                mac_login_attr = 'uid'
            # Get value for soft deletion
            soft_deletion = cfg['VMAM']['soft_deletion']
            macaddresses = query_ldap(bind_start, cfg['LDAP']['mac_user_base_dn'],
                                      mac_get_attributes, comp='<=', **mac_filter)
            if macaddresses and macaddresses[0].get('dn'):
                for mac in macaddresses:
                    # Check if mac-address user don't live in time-to-live period
                    wc = datetime_to_filetime(mac.get('attributes').get(mac_created_attr))
                    if ts > wc:
                        if soft_deletion:
                            # Modify description
                            last_access = mac.get('attributes').get(mac_lastlogon_attr)
                            desc = 'Disabled on {0}. Last access on {1}. Description: {2}'.format(
                                str(datetime.date.today()), str(last_access.date()),
                                mac.get('attributes').get('description')[0]
                            )
                            # Disable mac-address
                            cli_disable_mac(cfg, bind_start, mac.get('attributes').get(mac_login_attr), wt, arguments,
                                            description=desc)
                        else:
                            # Remove mac-address
                            cli_delete_mac(cfg, bind_start, mac.get('attributes').get(mac_login_attr), wt, arguments)


    def cli_daemon(func, wait=1, *args):
        """
        Run vmam as a daemon

        :param func: function passed
        :param wait: wait seconds of the infinite loop
        :param args: arguments passed to function
        :return: None
        """
        with daemon.DaemonContext():
            # Run endlessly
            while True:
                func(*args)
                time.sleep(wait)


    def main():
        """
        Command line main process

        :return: None
        """
        # Check required modules
        cli_check_module()
        # Parse arguments
        option = parse_arguments()
        args = option.parse_args()
        # Check command line arguments
        if not args.action:
            option.print_help()
            exit(1)
        # Get action
        cli = cli_select_action(args.action)
        # Daemon?
        if 'daemon' in args and args.daemon:
            print('Start vmam daemon...')
            # Add force argument for disable/remove process
            args.force = True
            # Read the configuration file
            cfg = read_config(args.conf)
            cli_daemon(cli, cfg.get('VMAM').get('automatic_process_wait'), args)
        else:
            cli(args)


    main()

# endregion
