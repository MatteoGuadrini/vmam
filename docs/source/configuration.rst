Configuration File
##################

.. toctree::
   :maxdepth: 2
   :caption: Contents:

Config Mode
***********

To generate an empty configuration file, type at the command line (or through its function, see the `*vmam* module <vmam.html>`_):

.. code-block:: console

    #> vmam config --new <path-to-configuration>.yml

If you don't specify the file path, it will create a configuration file in a default path: ``/etc/vmam/vmam.yml``


The configuration file is in `YAML <https://yaml.org/>`_ format.

.. code-block:: YAML

    LDAP:                                       # LDAP section
      add_group_type:                           # LDAP objects that will receive the VLAN groups (user - computer)
      - user
      - computer
      bind_pwd: password                        # LDAP password of "bind_user"
      bind_user: test\administrator             # LDAP user with write privileges (admin)
      computer_base_dn: OU=PCs,DC=test,DC=local # LDAP base search of computer object
      domain: test.local                        # LDAP domain in dot format
      mac_user_base_dn: OU=mac,DC=test,DC=local # LDAP base search of mac-address user object
      match: like                               # Matching operator used for "verify_attrib" (like - match)
      mac_user_ttl: 30d                         # LDAP mac-address user time-to-live
      other_group:                              # Additional LDAP groups, in addition to those representing VLAN-IDs
      - all_vlans
      servers:                                  # LDAP servers (ip-address, hostname or FQDN)
      - dc1
      - dc2
      ssl: false                                # LDAP ssl connection (TCP port 636)
      time_computer_sync: 1m                    # Computers that have logged on to the domain N time ago
      tls: true                                 # LDAP start-tls
      user_base_dn: OU=user,DC=test,DC=bol      # LDAP base search of user object
      verify_attrib:                            # Verification attributes for considering a user of a certain VLAN
      - memberof
      write_attrib:                             # Vmam attribute used to write internal value
    VMAM:                                       # VMAM section
      filter_exclude:                           # Mac-address filters to be excluded
      - TAP
      - disconnect
      log: /tmp/vmam.log                        # Path of vmam log
      remove_process: true                      # Enable vmam remove or disabling process; disabling depend of "soft_deletion"
      automatic_process_wait: 3                 # Integer represent seconds of wait for automatic process
      mac_format: none                          # Mac-address format (none - dot - hypens - colon)
      black_list: /etc/vmam/black.list          # File containing blacklisted mac-addresses
      soft_deletion: true                       # If this is true, the mac-addresses are disabled and not deleted
      user_match_id:                            # Based on the attribute specified in "verify_attrib". The key is the value to be matched while the value is the VLAN id
        OU=IT: 100
        OU=Sales: 101
        OU=HR: 102
      vlan_group_id:                            # The key is the group VLAN id. The value is the name of the LDAP group
        100: it_vlan
        101: sales_vlan
        102: hr_vlan
      winrm_pwd: password                       # WINRM password of "winrm_user"
      winrm_user: test\remoteadmin              # WINRM user with admin privileges

Keys and Values
***************

Below are the key-value references for each reference and section of the configuration file.

LDAP section
============

This is the LDAP section

==================      ========================================
**Key**                 **Value**
==================      ========================================
add_group_type          "user" or "computer" [list]
bind_user               LDAP user with write privileges [string]
bind_pwd                Password of "bind_user" [string]
computer_base_dn        LDAP base search of computer object [string]
domain                  LDAP domain in dot format [string]
mac_user_base_dn        LDAP base search of mac-address user object [string]
match                   "like" or "match" [string]
mac_user_ttl            NumberString - Ns - 1s, 2m, 3h, 4d, 5w [string]
other_group             Additional LDAP groups [list]
servers                 LDAP Server list [list]
ssl                     If "true", protocol is ldaps:// and port is 636 [boolean]
time_computer_sync      NumberString - Ns - 1s, 2m, 3h, 4d, 5w [string]
tls                     If "true", starttls (if you have set "ssl", tls will not be considered) [boolean]
user_base_dn            LDAP base search of user object [string]
verify_attrib           Verification attributes for considering a user of a certain VLAN [string]
write_attrib            Vmam attribute used to write internal value (if empty, employeeType is set) [string]
==================      ========================================

VMAM section
============

This is the VMAM section

======================= ========================================
**Key**                 **Value**
======================= ========================================
filter_exclude          Mac-address filters to be excluded (See output of command ``getmac /fo csv /v``) [list]
log                     Path of vmam log [string]
remove_process          Enable vmam remove or disabling process; disabling depend of "soft_deletion" [boolean]
mac_format              "none", "dot", "hypens" or "colon" [string]
black_list              File containing blacklisted mac-addresses. The file can contains mac in any format and comment ("#comment") [string]
automatic_process_wait  Integer represent seconds of wait for automatic process [int]
soft_deletion           If this is "true", the mac-addresses are disabled and not deleted [boolean]
user_match_id           Based on the attribute specified in "verify_attrib". The key is the value to be matched while the value is the VLAN id [dictionary]
vlan_group_id           The key is the group VLAN id. The value is the name of the LDAP group [dictionary]
winrm_user              WINRM user with admin privileges [string]
winrm_pwd               WINRM password of "winrm_user" [string]
======================= ========================================


Get prerequisites configuration
===============================

Once you have compiled the configuration file with your values, to get the prerequisites scheme, just run this command:

.. code-block:: console

    vmam config --get-cmd <path-to-configuration>.yml

If you don't specify the file path, it will create a configuration file in a default path: ``/etc/vmam/vmam.yml``