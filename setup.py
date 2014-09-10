#!/usr/bin/python
#
# IM - Infrastructure Manager
# Copyright (C) 2011 - GRyCAP - Universitat Politecnica de Valencia
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from IM import __version__ as version
from setuptools import setup
setup(  name="IM", version=version, 
        author='GRyCAP - Universitat Politecnica de Valencia',
        author_email='micafer1@upv.es',
        url='http://www.grycap.upv.es/im',
	packages=['','IM', 'IM.radl','connectors'],
	package_dir = {'':'.'},
        scripts=["service.py","im"],
        exclude_package_data={ "" : ["LICENSE", "INSTALL", "NOTICE", "changelog" ]},
        license="GPL version 3, http://www.gnu.org/licenses/gpl-3.0.txt",
        long_description="IM is a tool that ease the access and the usability of IaaS clouds by automating the VMI selection, deployment, configuration, software installation, monitoring and update of Virtual Appliances. It supports APIs from a large number of virtual platforms, making user applications cloud-agnostic. In addition it integrates a contextualization system to enable the installation and configuration of all the user required applications providing the user with a fully functional infrastructure.",
        description="IM is a tool to manage virtual infrastructures on Cloud deployments",
        platforms=["any"],
	install_requires=["Ansible >= 1.4","paramiko","PyYAML","SOAPpy","ply"]
)
