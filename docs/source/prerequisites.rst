Prerequisites
#############

.. toctree::
   :maxdepth: 2
   :caption: Contents:

vmam Server
***********

The server hosting *vmam* must be unix-like and with systemd installed.

Python
======

*vmam* is written in python3 (3.3 and higher).
It also uses three third-party python libraries, necessary for the correct functioning of the tool:

- `pywinrm <https://github.com/diyan/pywinrm>`_
- `ldap3 <https://github.com/cannatag/ldap3>`_
- `daemon <https://pagure.io/python-daemon>`_
- `pyyaml <https://pyyaml.org/>`_

Client on the network
*********************
If you use an automatic mode, the clients on the network managed by *vmam* must be Windows machines, with `WINRM <https://en.wikipedia.org/wiki/Windows_Remote_Management>`_ enabled.
To enable it, run ``winrm quickconfig``.
On the other hand, if you use the manual process, the clients can be anything (linux, MacOSX, BSD, printers, router, etc.)


Directory Server
****************

*vmam* allows the management of mac-addresses thanks to operations on a directory server through the LDAP protocol.
The directory server (`Active Directory <https://en.wikipedia.org/wiki/Active_Directory>`_ or `FreeIPA <https://en.wikipedia.org/wiki/FreeIPA>`_)
must be installed before configuring *vmam*.

LDAP Protocol
=============

Through the `LDAP Protocol <https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol>`_,
*vmam* creates, searches, deletes, disables and authenticates all the mac-addresses to manage.

LDAP Users
----------

*vmam*, creates mac-addresses in the directory server that represent the physical cards of the machines that access the network.
These mac-addresses are for all intents and purposes of LDAP users.

LDAP Computers
--------------

*vmam* uses computer accounts linked to the domain for remote contact (via WINRM),
in order to take the necessary information to understand which mac-address is used by which user.

LDAP Groups
-----------

*vmam* uses LDAP security groups to directly represent VLAN-IDs. These groups will be configured in the radius server policies.
Then create the LDAP groups based on the VLAN ids you need to manage.

LDAP Organizational Unit
------------------------

*vmam* uses organizational units (OU) as a search base for the three types of LDAP objects: users, computers and groups.
In the *vmam* configuration file, you will find three LDAP object search bases.
Nobody forbids all three to coincide, but it's best to keep them separate in different OUs for proper functionality.


Radius Server
*************

To accept the authentication of the various mac-addresses and *"release"* a VLAN, a `Radius Server <https://en.wikipedia.org/wiki/RADIUS>`_ is required.
If you have an Active Directory server, it is better to install `NPS <https://en.wikipedia.org/wiki/Network_Policy_Server>`_.
Otherwise you can choose to install `Free Radius <https://en.wikipedia.org/wiki/FreeRADIUS>`_.

Radius Policy
=============

The radius policies must be configured so that if the mac-address users belongs to a specific LDAP group representing the VLAN-ID, that VLAN is released on the client port.

Network Appliance
*****************

Based on your network devices, you will need to configure *"ldap mac-address authentication"* (`IEEE 802.1x <https://en.wikipedia.org/wiki/IEEE_802.1X>`_).

.. note::
    BEST PRACTICE: MAC-based authentication is not as secure as agent access or agentless access authentication.
    MAC addresses are not generally guarded as secrets, so an attacker can spoof a MAC address and impersonate a device to gain network access.
    To reduce risk of an exploit, create a special VLAN for each device type.

Configure Network Device
========================

To configure your network devices, you need to follow and search the manuals for the following steps:

1. Create VLANs and configure the VLANs allowed by interfaces so that packets can be forwarded.
2. Create and configure a RADIUS server template, an AAA authentication scheme, and an authentication domain.
3. Enable MAC authentication.
4. Configure the post-authentication domain.

Installation
############

The installation of *vmam* is very simple. With *pip*:

.. code-block:: console

    pip install vmam

Or just run these commands:

.. code-block:: console

    git clone https://github.com/MatteoGuadrini/vmam.git
    cd vmam
    sudo python3 setup.py install