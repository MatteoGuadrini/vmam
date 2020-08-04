# vmam: VLAN Mac-address Authentication Manager

<img src="https://raw.githubusercontent.com/MatteoGuadrini/vmam/master/img/vmam.png" alt="vmam" title="vmam" width="210" height="210" />
<br>
<br>

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/7fc47024f17f4dffa3be08a7a5ab31bd)](https://app.codacy.com/app/MatteoGuadrini/vmam?utm_source=github.com&utm_medium=referral&utm_content=MatteoGuadrini/vmam&utm_campaign=Badge_Grade_Dashboard)
[![CircleCI](https://circleci.com/gh/MatteoGuadrini/vmam.svg?style=svg)](https://circleci.com/gh/MatteoGuadrini/vmam)

`vmam` is a Free and Open Source network access control (NAC) solution. 
that access the network under a specific domain and a specific VLAN, through LDAP authentication and RADIUS server.
This is based on [RFC 3579](https://tools.ietf.org/html/rfc3579#section-2.1).

## Python module dependencies

- [x] [pywinrm](https://github.com/diyan/pywinrm)
- [x] [ldap3](https://github.com/cannatag/ldap3)
- [x] [deamon](https://pagure.io/python-daemon/)
- [x] [pyyaml](https://pyyaml.org/)

## What's vmam?

**vmam** is a Free and Open Source command line tool written in python, which manages, manually or automatically, 
access to the network based on the configurations of its network equipment through LDAP server (Active Directory, FreeIPA, etc.) and 
RADIUS server (Microsoft Radius or Free Radius) see [IEEE 802.1X](https://en.wikipedia.org/wiki/IEEE_802.1X), 
based on [RFC 3580](https://tools.ietf.org/html/rfc3580), [RFC 4014](https://tools.ietf.org/html/rfc4014),
[RFC 2865](https://tools.ietf.org/html/rfc2865), [RFC 3579](https://tools.ietf.org/html/rfc3579).

### vmam architecture

_vmam_ is a server-side application. Work with an open source LDAP server or Active Directory. 
Basically it creates mac-address users that represent the network card of a machine and associates these users with LDAP groups 
that represent the various VLANs specified created on their own network architecture (wi-fi, switches, routers, firewalls, etc.), 
centralized wired and wireless management, with 802.1X support.
In addition, based on its configuration, it can also associate computer accounts with this group to allow access to the network 
by spending the credentials of the computer account.

_vmam_ can be installed on a Unix base server. The computer accounts linked to the domain, for only automatic mode must be Microsoft Windows.
Manual mode work with only mac-address user and therefore the operating system is indifferent.

## How do you do it?

**vmam** is installed as a server. 


## Installation

The installation of *vmam* is very simple. With *pip*:

```bash
pip install vmam
```

Or just run these commands:

```bash
git clone https://github.com/MatteoGuadrini/vmam.git
cd vmam
sudo python3 setup.py install
```

### Manual mode

In manual mode, mac-addresses are managed from the command line using the `vmam mac` command.
The *mac* command has options to add, remove and disable the mac-addresses that can access the network.
For more details, see the docs.

### Automatic mode

In automatic mode, mac-addresses are managed by contacting LDAP server and taking the last machines (variable in the configuration file) 
that contacted the LDAP server from N seconds, minutes, hour or days, depending on the needs and policies decided.

> Attention: Clients must have WINRM active. See the `winrm quickconfig` command. 

This mode is activated by launching `vmam start` on the command line. 
Without any parameter, it reads the configuration file (if not specified, the default one), 
contacts ldap, takes the last machines that contact the LDAP server, contacts them via WinRM, 
takes the information of the last connected user and the tabs of active network, LDAP check to see which VLAN-ID (LDAP group)
assign to the mac-address and then exit.

If you were to specify the `--daemon/-d` argument then the process would continue until a manual interrupt (kill the process).


## How to start

Let's start with our network architecture.

### Configure network architecture and radius server

Before starting to use `vmam`, you need to know your network architecture and configure it correctly.
Read these RFCs carefully ([RFC 3580](https://tools.ietf.org/html/rfc3580), [RFC 4014](https://tools.ietf.org/html/rfc4014),
[RFC 2865](https://tools.ietf.org/html/rfc2865), [RFC 3579](https://tools.ietf.org/html/rfc3579)) and choose a radius server based on your architecture 
([freeradius](https://freeradius.org/) or [Microsoft Radius](https://docs.microsoft.com/it-it/windows-server/networking/technologies/nps/nps-top)).

Once the network equipment and radius server have been configured, create ldap groups corresponding to the VLAN that you want to manage. 

e.g .: *VLAN_ID 100 on switch to group LDAP VLAN100.*

This VLAN100 group must be configured on the VLAN ID in the radius server corresponding to the VLAN100 group.

### Get configuration by vmam

You can configure _vmam_ before configuring your network architecture.

You can start creating a default file by typing: `vmam config --new`

This will create a standard configuration file under `/etc/vmam/vmam.conf`.

Now it will be enough, edit and customize the configuration file following the documentation as guidelines. Once done, type `vmam config --get-cmd`

This command will return the guide to correctly configure LDAP and the radius server based on the configuration file.

## Documentation
The official documentation for more details of configuration and implementations, is here: [docs](https://vmam.readthedocs.io/en/latest/)

## Open source
_vmam_ is a open source project. Any contribute, It's welcome.

**A great thanks**.

For donations, press this

For me

[![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.me/guos)

For [Telethon](http://www.telethon.it/)

The Telethon Foundation is a non-profit organization recognized by the Ministry of University and Scientific and Technological Research.
They were born in 1990 to respond to the appeal of patients suffering from rare diseases.
Come today, we are organized to dare to listen to them and answers, every day of the year.

<a href="https://www.telethon.it/sostienici/dona-ora"> <img src="https://www.telethon.it/dev/_nuxt/img/c6d474e.svg" alt="Telethon" title="Telethon" width="200" height="104" /> </a>

[Adopt the future](https://www.ioadottoilfuturo.it/)


## Acknowledgments

Thanks Alexey Diyan for pywinrm module; thanks Giovanni Cannata for ldap3 module; thanks Ben Finney for python-daemon module; thanks to all yaml team.

Thanks to Mark Lutz for writing the _Learning Python_ and _Programming Python_ books that make up my python foundation.

Special thanks go to my wife, who understood the hours of absence for this development. 
Thanks to my children, for the daily inspiration they give me and to make me realize, that life must be simple.

Thanks Python!