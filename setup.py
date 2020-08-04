#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
# vim: se ts=4 et syn=python:

# created by: matteo.guadrini
# setup -- vmam
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

import os
import shutil
from os import path

from setuptools import setup

VERSION = '1.3.3'

if not os.path.exists('bin'):
    os.makedirs('bin')
shutil.copyfile('vmam.py', 'bin/vmam')

this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='vmam',
    version=VERSION,
    py_modules=['vmam'],
    url='https://github.com/matteoguadrini/vmam',
    license='GNU General Public License v3.0',
    author='Matteo Guadrini',
    author_email='matteo.guadrini@hotmail.it',
    description='VLAN Mac-address Authentication Manager',
    install_requires=[
        'python-daemon',
        'ldap3',
        'pywinrm',
        'pyyaml'
    ],
    long_description=long_description,
    long_description_content_type='text/markdown',
    data_files=[('/usr/share/man/man1', ['vmam.1'])],
    scripts=['bin/vmam']
)
