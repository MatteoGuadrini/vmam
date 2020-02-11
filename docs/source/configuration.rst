Configuration File
##################

.. toctree::
   :maxdepth: 2
   :caption: Contents:


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
      mac_format: none                          # Mac-address format (none - dot - hypens - colon)
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
Key                     Value
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