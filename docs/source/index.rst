.. vmam documentation master file, created by
   sphinx-quickstart on Fri Feb  7 08:06:39 2020.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to vmam's documentation!
################################

*vmam* is a Unix server-side application, which allows you to manage LDAP users representing the physical cards present on a given network.
Network cards are represented and interpreted by *vmam* as LDAP user,
with specific attributes. *vmam* also manages computer accounts, in case your radius policies provide for authentication from computer accounts.
All this is possible thanks to a simple configuration file.

*vmam* can be used in two ways. One, using its command line CLI, or as a python module.
Using it as a python module, you can create your own environment without using the configuration file. See the next section for more information.

RFC
***

*vmam* is based on various RFC. See this:
`IEEE 802.1X <https://en.wikipedia.org/wiki/IEEE_802.1X>`_, `RFC 3580 <https://tools.ietf.org/html/rfc3580>`_, `RFC 4014 <https://tools.ietf.org/html/rfc4014>`_,
`RFC 2865 <https://tools.ietf.org/html/rfc2865>`_, `RFC 3579 <https://tools.ietf.org/html/rfc3579>`_.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   prerequisites
   configuration
   cmd
   modules
   support



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
