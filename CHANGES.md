# Release notes

## 1.4.0
Sep 5, 2020

### Improvements command line

- Added support for FreeIpa server. 
- Fix user creation and re-enabled user.

## 1.3.0
Apr 25, 2020

### Improvements command line

- Add description parameter for manually mac-address creation

### Improvements module

- Add black list file to configuration
- Add black list part on manual process
- Add black list part on automatic process
- Add get_mac_from_file function
- Add cli_check_list function
- Add try/except to read_config
- Add version on label on write_attribute configuration
- Add description to start and mac disabling process
- Add check for description in mac exists
- Add try/except for create directory on new_config function
- Add timeout on check_connection function
- Add LDAP Server group configuration
- Fix set password process
- Fix get_platform function for only use on Linux platform
- Fix add/disable function
- Fix setup.py
- Rebase mac_format function to format_mac

## 1.2.0
Mar 21, 2020

### Improvements command line

- Add automatic_process_wait in vmam configuration file
- Remove other VLAN LDAP group on computer object
- Complete description of vmam

### Improvements module

- Rewrite check_ldap_version

## 1.1.0
Mar 09, 2020

### Improvements command line

- add one LDAP bind for automatic process
- fix manually disable and remove process

### Improvements module

- removed redundant code

## 1.0.0
Mar 01, 2020

_vmam_ was born.

### Features

- Command line options
- _config_ command line parser
- _mac_ command line parser
- _start_ command line parser
- Use like a python module