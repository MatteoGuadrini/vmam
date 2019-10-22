# vmam: VLAN Mac-address Authentication Manager

`vmam` is a command line tool which allows the management and maintenance of the mac-addresses 
that access the network under a specific domain and a specific VLAN, through LDAP authentication.
This is based on [RFC 3580](https://tools.ietf.org/html/rfc3580).

> ATTENTION: This is a project under development!

## Python modules needed

- [x] [pywinrm](https://github.com/diyan/pywinrm)
- [x] [ldap3](https://github.com/cannatag/ldap3)