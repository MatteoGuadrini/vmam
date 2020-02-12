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

``--add/-a {parameter}``: Add a specific mac-address on LDAP with specific VLAN. See also --vlan-id/-v

``--vlan-id/-v {parameter}``: Specify a specific VLAN-id

.. code-block:: console

    $> vmam mac --add <mac-address> --vlan-id <vlan-id>