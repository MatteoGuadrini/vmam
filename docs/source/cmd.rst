Command Line
############

.. toctree::
   :maxdepth: 2
   :caption: Contents:

vmam can be run in manual or automatic mode.

.. code-block:: console

    $> vmam [action] [parameter] [options]

Manual Mode
***********

``mac {action}``: Manual action for adding, modifying, deleting and disabling of the mac-address users

In manual mode, you can do these operations:

- Creation
- Disabling
- Deletion

Creation
========

The process of creating a mac-address user involves these steps:

1. Creation of an LDAP user representing the mac-address
2. Insertion in the VLAN group according to the parameters of the configuration file
3. Insertion in the custom group based on the parameters of the configuration file
4. Check if other VLAN groups are assigned to the user
5. Set password equals as a mac-address

**Parameter**

``--add/-a {parameter}``: Add a specific mac-address on LDAP with specific VLAN. See also --vlan-id/-i

``--vlan-id/-i {parameter}``: Specify a specific VLAN-id

``--description/-D {parameter}``: Description field

.. code-block:: console

    $> vmam mac --add <mac-address> --vlan-id <vlan-id> --description <description>


Disabling
=========

The disabling process involves only one step; disabling the user.

**Parameter**

``--disable/-d {parameter}``: Disable a mac-address user on LDAP, without removing

``--force/-f {parameter}``: Force remove/disable action, without prompt confirmation (optional)

.. code-block:: console

    $> vmam mac --disable <mac-address>

Deletion
========

The deletion process involves only one step; delete the user.

**Parameter**

``--remove/-r {parameter}``: Remove a mac-address user on LDAP

``--force/-f {parameter}``: Force remove/disable action, without prompt confirmation (optional)

.. code-block:: console

    $> vmam mac --remove <mac-address>

**Common Parameter**

``--config-file/-c {parameter}``: Specify a configuration file in a custom path (optional)

.. note::

    If you don't specify the file path, it will create a configuration file in a default path: ``/etc/vmam/vmam.yml``


Automatic Mode
**************

``start {action}``: Automatic action for vmam environment

The automatic process can be launched in two ways: *finite* or *system daemon*.

Both have the same process:

1. Check if there are updated computers
2. Connection to the client via WINRM protocol
3. Run the commands: ``getmac /FO csv /v`` and ``quser``
4. Search the last user on LDAP server
5. Check the match of the attributes for the creation of the mac-address
6. Creation of an LDAP user representing the mac-address
7. Insertion in the VLAN group according to the parameters of the configuration file
8. Insertion in the custom group based on the parameters of the configuration file
9. Check if other VLAN groups are assigned to the user
10. Set password equals as a mac-address
11. Assign computer to VLAN groups
12. Add VLAN LDAP group to computer account
13. Add description to computer account
14. Get old mac-address user based on *"mac_user_ttl"*
15. Disable/Remove mac-address based on *"soft_deletion"*

Finite
======

The process in finished mode, involves above steps, after which, exit with code 0.

.. code-block:: console

    $> vmam start

Daemon
======

The process in daemon mode, involves the same previous steps,
with the only difference that the process is launched in the background as a systemd daemon (see here).
If something goes wrong, the process does not exit but writes error lines to the log file and will proceed in its course.

.. code-block:: console

    $> vmam start --daemon

**Parameter**

``--daemon/-d {parameter}``: If specified, the automatic process run in background

**Common Parameter**

``--config-file/-c {parameter}``: Specify a configuration file in a custom path (optional)

.. note::

    If you don't specify the file path, it will create a configuration file in a default path: ``/etc/vmam/vmam.yml``

Service
-------

You can create a systemd service to make vmam operational by booting the operating system.
In addition, this allows you to do all systemd operations (stop, start, restart etc.).
Let's create this file ``/etc/systemd/system/vmamd.service`` with this content:

.. code-block:: cfg

    # systemd unit file for the vmam daemon

    [Unit]
    # Human readable name of the unit
    Description=vmam Service

    [Service]
    # Command to execute when the service is started (add -v for debug)
    ExecStart=vmam start -d
    # Disable Python's buffering of STDOUT and STDERR, so that output from the
    # service shows up immediately in systemd's logs
    Environment=PYTHONUNBUFFERED=1
    # Automatically restart the service if it crashes
    Restart=on-failure

    [Install]
    # Tell systemd to automatically start this service when the system boots
    # (assuming the service is enabled)
    WantedBy=default.target

Now we can enable and start it:

.. code-block:: console

    $> systemctl enable vmamd
    $> systemctl start vmamd

Common Parameter
****************

``--version/-V {parameter}``: Print version and exit

``--verbose/-v {parameter}``: Print and log verbose information, for debugging