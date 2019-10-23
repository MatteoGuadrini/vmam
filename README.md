# vmam: VLAN Mac-address Authentication Manager

`vmam` is a command line tool which allows the management and maintenance of the mac-addresses 
that access the network under a specific domain and a specific VLAN, through LDAP authentication.
This is based on [RFC 3580](https://tools.ietf.org/html/rfc3580).

> ATTENTION: This is a project under development!

## Python modules needed

- [x] [pywinrm](https://github.com/diyan/pywinrm)
- [x] [ldap3](https://github.com/cannatag/ldap3)
- [x] [deamon](https://pagure.io/python-daemon/)

## What's vmam?

**vmam** is a command line tool, which manages, manually or automatically, 
access to the network based on the configurations of its network equipment through LDAP (or Active Directory), 
based on [RFC 3580](https://tools.ietf.org/html/rfc3580).

## How do you do it?

**vmam** is installed as a server. 

### Manual mode

In manual mode, mac-addresses are managed from the command line using the `vmam mac` command.
The **mac** command has options to add, remove and disable the mac-addresses that can access the network.
For more details, see the docs.

### Automatic mode

In automatic mode, mac-addresses are managed by contacting LDAP server and taking the last machines (variable in the configuration file) 
that contacted the LDAP server from N seconds, minutes, hour or days, depending on the needs and policies decided. 

This mode is activated by launching `vmam start` on the command line. 
Without any parameter, it reads the configuration file (if not specified, the default one), 
contacts ldap, takes the last machines that contact the LDAP server, contacts them via WinRM, 
takes the information of the last connected user and the tabs of active network, LDAP check to see which VLAN-ID (LDAP group)
assign to the mac-address and then exit.

If you were to specify the `--deamon/-d` argument then the process would continue until a manual interrupt(<kbd>CTRL</kbd>+<kbd>C</kbd>).