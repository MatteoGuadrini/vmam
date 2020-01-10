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

    SYNOPSYS

        vmam [action] [parameter] [options]

    USAGE

        config {action}: Configuration command for vmam environment

            --new/-n {parameter}: Instruction to create a new configuration file. By specifying a path, it creates the
            file in the indicated path. The default path is /etc/vmam/vmam.cfg

            $> vmam config --new
            Create a new configuration in a standard path: /etc/vmam/vmam.cfg

            --get-cmd/-g {parameter}: Instruction to obtain the appropriate commands to configure your network
            infrastructure and radius server around the created configuration file. By specifying a path, it creates
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

            --add/-a {parameter}: Add a specific mac-address on LDAP with specific VLAN. See also --vlan-id/-v

            $> vmam mac --add 000018ff12dd --vlan-id 110
            Add new mac-address user with VLAN 110, based on standard configuration file: /etc/vmam/vmam.cfg

            --remove/-r {parameter}: Remove a mac-address user on LDAP

            $> vmam mac --remove 000018ff12dd
            Remove mac-address user 000018ff12dd, based on standard configuration file: /etc/vmam/vmam.cfg

            --disable/-d {parameter}: Disable a mac-address user on LDAP, without removing

            $> vmam mac --disable 000018ff12dd
            Disable mac-address user 000018ff12dd, based on standard configuration file: /etc/vmam/vmam.cfg

            --force/-f {parameter}: Force add/remove/disable action

            $> vmam mac --remove 000018ff12dd --force
            Force remove mac-address user 000018ff12dd, based on standard configuration file: /etc/vmam/vmam.cfg

            $> vmam mac --add 000018ff12dd --vlan-id 111 --force
            Modify new or existing mac-address user with VLAN 111, based on standard configuration
            file: /etc/vmam/vmam.cfg

            --vlan-id/-v {parameter}: Specify a specific VLAN-id

            $> vmam mac --add 000018ff12dd --vlan-id 100
            Add new mac-address user with VLAN 100, based on standard configuration file: /etc/vmam/vmam.cfg

            --config-file/-c {parameter}: Specify a configuration file in a custom path (optional)

            $> vmam mac --remove 000018ff12dd --config-file /opt/vlan-office/office.cfg
            Remove mac-address user 000018ff12dd, based on custom configuration file: /opt/vlan-office/office.cfg

    AUTHOR

        Matteo Guadrini <matteo.guadrini@hotmail.it>

    COPYRIGHT

        (c) Matteo Guadrini. All rights reserved.
"""
# region Import dependencies


import daemon
import ldap3
import winrm

# endregion

# region Imports

import os
import sys
import yaml
import socket
import logging
import argparse
import platform
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
VERSION = '0.1.0'
# endregion

# region Functions


def printv(*messages):
    """
    Print verbose information
    :param messages: List of messages
    :return: String print on stdout
    ---
    >>>printv('Test','printv')
    """
    print("DEBUG:", *messages)


def logwriter(logfile):
    """
    Logger object than write line in a log file
    :param logfile: Path of logfile(.log)
    :return: Logger object
    ---
    >>>wl = logwriter('test.log')
    >>>wl.info('This is a test')
    """
    # Create logging object
    _format = logging.Formatter('%(asctime)s %(levelname)-4s %(message)s')
    handler = logging.FileHandler(logfile)
    handler.setFormatter(_format)
    logger = logging.getLogger(os.path.basename(__file__))
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    return logger


def debugger(verbose, writer, message):
    """
    Debugger: write debug and print verbose message
    :param verbose: verbose status; boolean
    :param writer: Log writer object
    :param message: String message
    :return: String on stdout
    """
    if verbose:
        writer.debug(message)
        printv(message)


def confirm(message):
    """
    Confirm action
    :param message: Question that expects a 'yes' or 'no' answer
    :return: Boolean
    ---
    >>>if confirm('Please, respond'):
    >>>    print('yep!')
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
    ---
    >>>cfg = read_config('/tmp/vmam.yml')
    >>>print(cfg)
    """
    with open('{0}'.format(path)) as file:
        return yaml.full_load(file)


def write_config(obj, path):
    """
    Write YAML configuration file
    :param obj: Python object that will be converted to YAML
    :param path: Path of configuration file
    :return: None
    ---
    >>>write_config(obj, '/tmp/vmam.yml')
    """
    with open('{0}'.format(path), 'w') as file:
        yaml.dump(obj, file)


def get_platform():
    """
    Get a platform (OS info)
    :return: Platform info dictionary
    ---
    >>>p = get_platform()
    >>>print(p)
    """
    # Create os info object
    os_info = {}
    # Check os
    if platform.system() == "Windows":
        os_info['conf_default'] = os.path.expandvars(r'%PROGRAMFILES%\vmam\vmam.yml')
        os_info['log_default'] = os.path.expandvars(r'%WINDIR%\Logs\vmam\vmam.log')
        os_info['ping_opt'] = '-n 2 -w 20000 2>&1 >NUL'
    else:
        os_info['conf_default'] = '/etc/vmam/vmam.yml'
        os_info['log_default'] = '/var/log/vmam/vmam.log'
        os_info['ping_opt'] = '-c 2 -w 20000 2>&1 >/dev/null'
    return os_info


def new_config(path=(get_platform()['conf_default'])):
    """
    Create a new vmam config file (YAML)
    :param path: Path of config file
    :return: None
    ---
    >>>new_config('/tmp/vmam.yml')
    """
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
            'max_computer_sync': 0,
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


def check_connection(ip, port):
    """
    Test connection of remote (ip) machine on (port)
    :param ip: ip address or hostname of machine
    :param port: tcp port
    :return: Boolean
    ---
    >>>check_connection('localhost', 80)
    True
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
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
    ---
    >>>cfg = check_config('/tmp/vmam.yml')
    True
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
    ---
    >>>conn = connect_ldap(['dc1.foo.bar'], ssl=True)
    >>>print(conn)
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
    ---
    >>>conn = connect_ldap(['dc1.foo.bar'])
    >>>bind = bind_ldap(conn, r'domain\\user', 'password', tls=True)
    >>>print(bind)
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
    ---
    >>>conn = connect_ldap(['dc1.foo.bar'])
    >>>bind = bind_ldap(conn, r'domain\\user', 'password', tls=True)
    >>>bind.unbind()
    """
    # Disconnect LDAP server
    bind_object.unbind()


def query_ldap(bind_object, base_search, attributes, **filters):
    """
    :param bind_object: LDAP bind object
    :param base_search: distinguishedName of LDAP base search
    :param attributes: list of returning LDAP attributes
    :param filters: dictionary of ldap query
    :return: query result list
    ---
    >>>conn = connect_ldap(['dc1.foo.bar'])
    >>>bind = bind_ldap(conn, r'domain\\user', 'password', tls=True)
    >>>ret = query_ldap(bind, 'dc=foo,dc=bar', ['sn', 'givenName'], objectClass='person', samAccountName='person1')
    >>>print(ret)
    """
    # Init query list
    query = ['(&']
    # Build query
    for key, value in filters.items():
        query.append("({0}={1})".format(key, value))
    # Close query
    query.append(')')
    # Query!
    if bind_object.search(search_base=base_search, search_filter=''.join(query), attributes=attributes,
                          search_scope=ldap3.SUBTREE):
        return bind_object.response


def check_ldap_version(bind_object, base_search):
    """
    Determines the LDAP version
    :param bind_object: LDAP bind object
    :param base_search: distinguishedName of LDAP base search
    :return: LDAP version
    ---
    >>>conn = connect_ldap(['dc1.foo.bar'])
    >>>bind = bind_ldap(conn, r'domain\\user', 'password', tls=True)
    >>>ret = check_ldap_version(bind, 'dc=foo,dc=bar')
    >>>print(ret)
    """
    # Query!
    try:
        # MS-LDAP query
        query = '(&(&(&(&(samAccountType=805306369)(primaryGroupId=516))(objectCategory=computer)(operatingSystem=*))))'
        bind_object.search(search_base=base_search, search_filter=query, search_scope=ldap3.SUBTREE)
        return 'MS-LDAP'
    except ldap3.core.exceptions.LDAPObjectClassError:
        try:
            # Novell-LDAP query
            query = '(objectClass=ncpServer)'
            bind_object.search(search_base=base_search, search_filter=query, search_scope=ldap3.SUBTREE)
            return 'N-LDAP'
        except ldap3.core.exceptions.LDAPObjectClassError:
            return 'LDAP'


def new_user(bind_object, username, **attributes):
    """
    Create a new LDAP user
    :param bind_object: LDAP bind object
    :param username: distinguishedName of user
    :param attributes: Dictionary attributes
    :return: LDAP operation result
    ---
    >>>conn = connect_ldap(['dc1.foo.bar'])
    >>>bind = bind_ldap(conn, r'domain\\user', 'password', tls=True)
    >>>new_user(bind, 'CN=ex_user1,OU=User_ex,DC=foo,DC=bar', givenName='User 1', sn='Example')
    """
    # Create user
    bind_object.add(
        username,
        ['top', 'person', 'organizationalPerson', 'user'],
        attributes
    )
    return bind_object.result


def set_user(bind_object, username, **attributes):
    """
    Modify an exists LDAP user
    :param bind_object: LDAP bind object
    :param username: distinguishedName of user
    :param attributes: Dictionary attributes
    :return: LDAP operation result
    ---
    >>>conn = connect_ldap(['dc1.foo.bar'])
    >>>bind = bind_ldap(conn, r'domain\\user', 'password', tls=True)
    >>>set_user(bind, 'CN=ex_user1,OU=User_ex,DC=foo,DC=bar', givenName='User 1', sn='Example')
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
    ---
    >>>conn = connect_ldap(['dc1.foo.bar'])
    >>>bind = bind_ldap(conn, r'domain\\user', 'password', tls=True)
    >>>delete_user(bind, 'CN=ex_user1,OU=User_ex,DC=foo,DC=bar')
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
    >>>conn = connect_ldap('dc1.foo.bar')
    >>>bind = bind_ldap(conn, r'domain\\user', 'password', tls=True)
    >>>new_user(bind, 'CN=ex_user1,OU=User_ex,DC=foo,DC=bar', givenName='User 1', sn='Example')
    >>>set_user_password(bind, 'CN=ex_user1,OU=User_ex,DC=foo,DC=bar', 'password', ldap_version='MS-LDAP')
    >>>set_user(bind, 'CN=ex_user1,CN=Users,DC=office,DC=bol', pwdLastSet=-1, userAccountControl=66048)
    """
    # Set password
    if ldap_version == 'LDAP':
        bind_object.extend.StandardExtendedOperations.modify_password(username, new_password=password,
                                                                      old_password=None)
    elif ldap_version == 'MS-LDAP':
        bind_object.extend.microsoft.modify_password(username, new_password=password, old_password=None)
    elif ldap_version == 'N-LDAP':
        bind_object.extend.NovellExtendedOperations.set_universal_password(username, new_password=password,
                                                                           old_password=None)
    else:
        bind_object.extend.StandardExtendedOperations.modify_password(username, new_password=password,
                                                                      old_password=None)


def add_to_group(bind_object, groupname, members):
    """
    Add a member of exists LDAP group
    :param bind_object: LDAP bind object
    :param groupname: distinguishedName of group
    :param members: List of a new members
    :return: LDAP operation result
    ---
    >>>conn = connect_ldap('dc1.foo.bar')
    >>>bind = bind_ldap(conn, r'domain\\user', 'password', tls=True)
    >>>add_to_group(bind, 'CN=ex_group1,OU=Groups,DC=foo,DC=bar', 'CN=ex_user1,CN=Users,DC=office,DC=bol')
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
    ---
    >>>conn = connect_ldap('dc1.foo.bar')
    >>>bind = bind_ldap(conn, r'domain\\user', 'password', tls=True)
    >>>remove_to_group(bind, 'CN=ex_group1,OU=Groups,DC=foo,DC=bar', 'CN=ex_user1,CN=Users,DC=office,DC=bol')
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
    ---
    >>>dt = filetime_to_datetime(132130209369676516)
    >>>print(dt)
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
    ---
    >>>ft = datetime_to_filetime(datetime.datetime(2001, 1, 1))
    >>>print(ft)
    """
    # January 1, 1970 as MS filetime
    epoch_as_filetime = 116444736000000000
    filetime = epoch_as_filetime + (int(date_time.timestamp())) * 10000000
    return filetime + (date_time.microsecond * 10)


def get_time_sync(timedelta):
    """
    It takes the date for synchronization
    :param timedelta: Time difference to subtract (string: 1s, 2m, 3h, 4d, 5w, 6M, 7y)
    :return: datetime object
    ---
    >>>td = get_time_sync('1d')
    >>>print(td)
    """
    # Dictionary of units
    units = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks", "M": "months", "y": "years"}
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
    ---
    >>>dt = string_to_datetime('28/2/2019')
    >>>print(dt)
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


def mac_format(mac_address, format_mac):
    """
    Format mac-address with the specified format
    :param mac_address: mac-address in any format
    :param format_mac: mac format are (default=none):
        -none 	112233445566
        -hypen 	11-22-33-44-55-66
        -colon 	11:22:33:44:55:66
        -dot	1122.3344.5566
    :return: mac-address with the specified format
    ---
    >>>mac = mac_format('1A2b3c4D5E6F', 'dot')
    >>>print(mac)
    """
    # Set format
    form = {
        'none': lambda x: x.replace('.', '').replace('-', '').replace(':', '').lower(),
        'hypen': lambda x: '-'.join([x[i:i+2] for i in range(0, len(x), 2)]).replace('.', '').replace(':', '').lower(),
        'colon': lambda x: ':'.join([x[i:i+2] for i in range(0, len(x), 2)]).replace('.', '').replace('-', '').lower(),
        'dot': lambda x: '.'.join([x[i:i+4] for i in range(0, len(x), 4)]).replace(':', '').replace('-', '').lower()
    }
    # Get format
    try:
        return form.get(format_mac)(mac_address)
    except TypeError:
        print('ERROR: "{0}" format not available. Available: none, hypen, colon, dot.'.format(format_mac))
        return form.get('none')(mac_address)


def connect_client(client, user, password):
    """
    Connect to client with WINRM protocol
    :param client: hostname or ip address
    :param user: username used for connection on client
    :param password: password of user
    :return: WINRM protocol object
    ---
    >>>cl = connect_client('host1', r'domain\\user', 'password')
    >>>print(cl)
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
    Run command to client
    :param protocol: WINRM protocol object
    :param command: command to run on client
    :return: Output of command
    ---
    >>>cl = connect_client('host1', r'domain\\user', 'password')
    >>>cmd = run_command(cl, 'ipconfig /all')
    >>>print(cmd)
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


# endregion


# region Start process

if __name__ == '__main__':

    def parse_arguments():
        """
        Function that captures the parameters and the arguments in the command line
        :return: Parser object
        ---
        >>>option = parse_arguments()
        >>>print(option.parse_args())
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
                                        action='store',
                                        nargs=1, metavar='MAC_ADDR')
        group_mac_mutually.add_argument('--remove', '-r', help='remove mac-address to LDAP server', dest='remove',
                                        action='store', nargs=1, metavar='MAC_ADDR')
        group_mac_mutually.add_argument('--disable', '-d', help='disable mac-address to LDAP server', dest='disable',
                                        action='store', nargs=1, metavar='MAC_ADDR')
        group_mac.add_argument('--config-file', '-c', help='parse configuration file', dest='conf', action='store',
                               nargs='?', default=get_platform()['conf_default'], metavar='CONF_FILE')
        group_mac.add_argument('--force', '-f', help='force action', dest='force', action='store_true')
        group_mac.add_argument('--vlan-id', '-i', help='vlan-id number', dest='vlanid', action='store',
                               nargs=1, metavar='VLAN_ID', type=int, required=('--add' in sys.argv or '-a' in sys.argv))
        # Return parser object
        return parser_object


    def cli_check_module():
        """
        CLI function: Check if dependencies modules is installed
        :return: Boolean
        """
        # List of dependencies modules
        mods = ['daemon', 'ldap3', 'winrm']
        # Check import dependencies
        for mod in mods:
            assert check_module(mod), 'Install "{0}" module with pip install.'.format(mod)


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
            'start': 'Automatic action'
        }
        return actions.get(action, 'No action available')


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
        debugger(arguments.verbose, wt, 'Start in manual mode.')
        # Check mandatory entry on configuration file
        debugger(arguments.verbose, wt, 'Check mandatory fields on configuration file {0}'.format(arguments.conf))
        check_config(arguments.conf)
        # Check actions
        if arguments.add:
            mac = mac_format(''.join(arguments.add), cfg['VMAM']['mac_format'])
            vlanid = arguments.vlanid[0]
            print('Add mac-address {0} on LDAP servers {1} in {2} VLAN group'.format(
                mac, ','.join(cfg['LDAP']['servers']), vlanid))
            debugger(arguments.verbose, wt, 'Add mac-address {0} on LDAP servers {1} in {2} VLAN group'.format(
                mac, ','.join(cfg['LDAP']['servers']), vlanid))
            # Connect LDAP servers
            debugger(arguments.verbose, wt, 'Connect to LDAP servers {0}'.format(','.join(cfg['LDAP']['servers'])))
            srv = connect_ldap(cfg['LDAP']['servers'], ssl=cfg['LDAP']['ssl'])
            # Bind LDAP server
            debugger(arguments.verbose, wt, 'Bind on LDAP servers {0} with user {1}'.format(
                ','.join(cfg['LDAP']['servers']), cfg['LDAP']['bind_user']))
            bind = bind_ldap(srv, cfg['LDAP']['bind_user'], cfg['LDAP']['bind_pwd'], tls=cfg['LDAP']['tls'])
            ldap_v = check_ldap_version(bind, cfg['LDAP']['user_base_dn'])
            ids = 'cn' if ldap_v == 'MS-LDAP' else 'uid'
            dn = '{0}={1},{2}'.format(ids, mac, cfg['LDAP']['mac_user_base_dn'])
            # Query: check if mac-address exist
            debugger(arguments.verbose, wt, 'Exist mac-address {0} on LDAP servers {1}?'.format(
                mac, ','.join(cfg['LDAP']['servers'])))
            ret = query_ldap(bind, cfg['LDAP']['user_base_dn'], ['samaccountname'], samaccountname=mac)
            if not ret[0].get('dn'):
                debugger(arguments.verbose, wt, 'Mac-address {0} not exists on LDAP servers {1}'.format(
                    mac, ','.join(cfg['LDAP']['servers'])))
                # Add mac-address to LDAP
                attrs = {'givenname': 'mac-address',
                         'sn': mac,
                         'samaccountname': mac,
                         'userprincipalname': '{0}@{1}'.format(mac, cfg['LDAP']['domain']),
                         'description': mac}
                # Check write_attrib on configuration file
                if cfg['LDAP']['write_attrib']:
                    attrs[cfg['LDAP']['write_attrib']] = 'VMAM_MANUAL'
                else:
                    attrs['employeetype'] = 'VMAM_MANUAL'
                # Create mac-address user
                try:
                    new_user(bind, dn, **attrs)
                    print('Mac-address {0} created on LDAP servers {1} in {2} VLAN group'.format(
                        dn, ','.join(cfg['LDAP']['servers']), vlanid))
                except Exception as err:
                    print('ERROR:', err)
                    wt.error(err)
                    exit(8)
                wt.info('Add mac-address {0} on LDAP servers {1} in {2} VLAN group.'.format(
                    dn, ','.join(cfg['LDAP']['servers']), vlanid))
            else:
                debugger(arguments.verbose, wt, 'Mac-address {0} exists on LDAP servers {1}'.format(
                    ret[0].get('dn'), ','.join(cfg['LDAP']['servers'])))
                print('Mac address {0} already exists on LDAP servers {1}'.format(
                    ret[0].get('dn'), ','.join(cfg['LDAP']['servers'])))
            # Add VLAN and custom LDAP group
            # VLAN-ID group
            try:
                debugger(arguments.verbose, wt, 'Verify VLAN group {0} to user {1}'.format(
                    vlanid, dn))
                for key, value in cfg['VMAM']['vlan_group_id'].items():
                    # Check exist VLAN-ID in configuration file
                    if vlanid == key:
                        g = query_ldap(bind, cfg['LDAP']['user_base_dn'], ['member', 'distinguishedname'],
                                       objectclass='group', name=value)
                        u = query_ldap(bind, cfg['LDAP']['user_base_dn'], ['memberof'],
                                       objectclass='user', name=mac)
                        gdn = g[0]['dn']
                        umember = u[0]['attributes']['memberof']
                        # Add VLAN LDAP group to user mac address
                        if gdn not in umember:
                            add_to_group(bind, gdn, dn)
                            print('Add VLAN group {0} to user {1}'.format(gdn, dn))
                            wt.info('Add VLAN group {0} to user {1}'.format(gdn, dn))
                        else:
                            debugger(arguments.verbose, wt, 'VLAN group {0} already added to user {1}'.format(
                                cfg['VMAM']['vlan_group_id'][vlanid], dn))
                        break
                else:
                    print('VLAN-ID group {0} does not exist. See the configuration file {1}'.format(
                        vlanid, arguments.conf))
                    exit(4)
            except Exception as err:
                print('ERROR:', err)
                wt.error(err)
                exit(16)
            # Custom group
            try:
                debugger(arguments.verbose, wt, 'Verify custom groups {0} to user {1}'.format(
                    ','.join(cfg['LDAP']['other_group']), dn))
                for group in cfg['LDAP']['other_group']:
                    g = query_ldap(bind, cfg['LDAP']['user_base_dn'], ['member', 'distinguishedname'],
                                   objectclass='group', name=group)
                    u = query_ldap(bind, cfg['LDAP']['user_base_dn'], ['memberof'],
                                   objectclass='user', name=mac)
                    gdn = g[0]['dn']
                    umember = u[0]['attributes']['memberof']
                    # Add VLAN LDAP group to user mac address
                    if gdn not in umember:
                        add_to_group(bind, gdn, dn)
                        print('Add custom groups {0} to user {1}'.format(gdn, dn))
                        wt.info('Add custom groups {0} to user {1}'.format(gdn, dn))
                    else:
                        debugger(arguments.verbose, wt, 'Custom groups {0} already added to user {1}'.format(
                            ','.join(cfg['LDAP']['other_group']), dn))
                    break
            except Exception as err:
                print('ERROR:', err)
                wt.error(err)
                exit(17)
            # Check if other VLAN groups are assigned to the user
            debugger(arguments.verbose, wt, 'Verify if other VLAN groups are assigned to the user {0}'.format(dn))
            try:
                # Get all VLAN group from user
                for key, value in cfg['VMAM']['vlan_group_id'].items():
                    # Check if VLAN-ID isn't equal
                    if vlanid != key:
                        g = query_ldap(bind, cfg['LDAP']['user_base_dn'], ['member', 'distinguishedname'],
                                       objectclass='group', name=value)
                        u = query_ldap(bind, cfg['LDAP']['user_base_dn'], ['memberof'],
                                       objectclass='user', name=mac)
                        gdn = g[0]['dn']
                        umember = u[0]['attributes']['memberof']
                        # Remove member of group
                        if gdn in umember:
                            remove_to_group(bind, gdn, dn)
                            print('Remove VLAN group {0} to user {1}'.format(gdn, dn))
                            wt.info('Remove VLAN group {0} to user {1}'.format(gdn, dn))
            except Exception as err:
                print('ERROR:', err)
                wt.error(err)
                exit(18)
            # Set password
            try:
                debugger(arguments.verbose, wt, 'Set password to user {0}'.format(dn))
                set_user_password(bind, dn, mac, ldap_version=ldap_v)
                if ldap_v == 'MS-LDAP':
                    # Enable user
                    try:
                        debugger(arguments.verbose, wt, 'Enable user {0}'.format(dn))
                        set_user(bind, dn, pwdlastset=-1, useraccountcontrol=66048)
                    except Exception as err:
                        print('ERROR:', err)
                        wt.error(err)
                        exit(10)
            except Exception as err:
                print('ERROR:', err)
                wt.error(err)
                exit(9)
            print('Mac-address user {0} successfully created'.format(mac))
            wt.info('Mac-address user {0} successfully created'.format(mac))
            # Unbind LDAP connection
            unbind_ldap(bind)
        elif arguments.disable:
            mac = mac_format(''.join(arguments.disable), cfg['VMAM']['mac_format'])
            print('Disable mac-address {0} on LDAP servers {1}'.format(mac, ','.join(cfg['LDAP']['servers'])))
            debugger(arguments.verbose, wt, 'Disable mac-address {0} on LDAP servers {1}'.format(
                mac, ','.join(cfg['LDAP']['servers'])))
            # Connect LDAP servers
            debugger(arguments.verbose, wt, 'Connect to LDAP servers {0}'.format(','.join(cfg['LDAP']['servers'])))
            srv = connect_ldap(cfg['LDAP']['servers'], ssl=cfg['LDAP']['ssl'])
            # Bind LDAP server
            debugger(arguments.verbose, wt, 'Bind on LDAP servers {0} with user {1}'.format(
                ','.join(cfg['LDAP']['servers']), cfg['LDAP']['bind_user']))
            bind = bind_ldap(srv, cfg['LDAP']['bind_user'], cfg['LDAP']['bind_pwd'], tls=cfg['LDAP']['tls'])
            ldap_v = check_ldap_version(bind, cfg['LDAP']['user_base_dn'])
            ids = 'cn' if ldap_v == 'MS-LDAP' else 'uid'
            dn = '{0}={1},{2}'.format(ids, mac, cfg['LDAP']['mac_user_base_dn'])
            # Query: check if mac-address exist
            debugger(arguments.verbose, wt, 'Exist mac-address {0} on LDAP servers {1}?'.format(
                mac, ','.join(cfg['LDAP']['servers'])))
            ret = query_ldap(bind, cfg['LDAP']['user_base_dn'], ['samaccountname'], samaccountname=mac)
            if ret[0].get('dn'):
                force = confirm('Do you want to disable {0} mac-address?'.format(mac)) if not arguments.force else True
                if force:
                    try:
                        if ldap_v == 'MS-LDAP':
                            set_user(bind, dn, useraccountcontrol=514)
                        else:
                            set_user(bind, dn, nsaccountlock='True')
                    except Exception as err:
                        print('ERROR:', err)
                        wt.error(err)
                        exit(11)
                    print('Mac-address {0} successfully disabled'.format(mac))
                    wt.info('Mac-address {0} successfully disabled'.format(mac))
            else:
                print('ERROR: Mac-address {0} does not exists'.format(mac))
                exit(8)
            # Unbind LDAP connection
            unbind_ldap(bind)
        elif arguments.remove:
            ...


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
        cli(args)


    main()

# endregion
