#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
# vim: se ts=4 et syn=python:

# created by: matteo.guadrini
# vmam -- vmam
#
#     Copyright (C) 2019 Matteo Guadrini <matteo.guadrini@hotmail.it>
#
#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation, either version 3 of the License, or
#     (at your option) any later version.
#
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.
#
#     You should have received a copy of the GNU General Public License
#     along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
Welcome to doc of vmam: VLAN Mac-address Authentication Manager

    SYNOPSYS

        vmam [action] [parameter] [options]

    USAGE

        config {action}: Configuration command for vmam environment

            --new/-n {parameter}: Instruction to create a new configuration file. By specifying a path, it creates the
            file in the indicated path. The default path is /etc/vmam/vmam.cfg

            $> vmam config --new
            Create a new configuration in a standard path: /etc/vmam/vmam.cfg

            --get-cmd/-g {parameter}: Instruction to obtain the appropriate commands to configure your network
            infrastructure and radius server around the created configuration file. By specifying a path, it creates
            the file in the indicated path. The default path is /etc/vmam/vmam.cfg

            $> vmam config --get-cmd
            It takes instructions to configure its own network and radius server structure,
            from standard path: /etc/vmam/vmam.cfg
"""