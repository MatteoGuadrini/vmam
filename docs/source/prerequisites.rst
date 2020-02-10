Prerequisites
#############

.. toctree::
   :maxdepth: 2
   :caption: Contents:

Directory Server
****************

*vmam* allows the management of mac-addresses thanks to operations on a directory server through the LDAP protocol.
The directory server (`Active Directory <https://en.wikipedia.org/wiki/Active_Directory>`_ or `FreeIPA <https://en.wikipedia.org/wiki/FreeIPA>`_)
must be installed before configuring *vmam*.

LDAP Protocol
=============

Through the `LDAP Protocol <https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol>`_,
*vmam* creates, searches, deletes, disables and authenticates all the mac-addresses to manage.

Radius Server
*************

To accept the authentication of the various mac-addresses and *"release"* a VLAN, a `Radius Server <https://en.wikipedia.org/wiki/RADIUS>`_ is required.
If you have an Active Directory server, it is better to install `NPS <https://en.wikipedia.org/wiki/Network_Policy_Server>`_.
Otherwise you can choose to install `Free Radius <https://en.wikipedia.org/wiki/FreeRADIUS>`_.

Network Appliance
*****************

Based on your network devices, you will need to configure *"mac-address authentication"* (`IEEE 802.1x <https://en.wikipedia.org/wiki/IEEE_802.1X>`_).

Configure Network Device
========================

To configure your network devices, you need to follow and search the manuals for the following steps:

1. Create VLANs and configure the VLANs allowed by interfaces so that packets can be forwarded.
2. Create and configure a RADIUS server template, an AAA authentication scheme, and an authentication domain.
3. Enable MAC authentication.
4. Configure the post-authentication domain.