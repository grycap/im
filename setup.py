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
import os
import sys

if not hasattr(sys, 'version_info') or sys.version_info < (2, 6):
    raise SystemExit("IM requires Python version 2.6 or above.")

suds_pkg = "suds"
sqlite_pkg = "pysqlite"
if sys.version_info > (3, 0):
    suds_pkg = "suds-py3"
    sqlite_pkg = ""

if 'bdist_wheel' in sys.argv:
    raise RuntimeError("This setup.py does not support wheels")

# Add contextualization dir files
install_path = '/usr/share/im'
datafiles = [(os.path.join(install_path, root), [os.path.join(root, f) for f in files])
             for root, dirs, files in os.walk("contextualization")]
# Add other special files
datafiles.append(('/etc/init.d', ['scripts/im']))
datafiles.append(('/etc/systemd/system', ['scripts/im.service']))
datafiles.append(('/etc/im', ['etc/im.cfg']))
datafiles.append(('/etc/im', ['etc/logging.conf']))
# force the im_service.py file to be allways in this path
datafiles.append(('/usr/bin', ['im_service.py']))

setup(name="IM", version=version,
      author='GRyCAP - Universitat Politecnica de Valencia',
      author_email='micafer1@upv.es',
      url='http://www.grycap.upv.es/im',
      include_package_data=True,
      packages=['IM', 'IM.ansible_utils', 'IM.connectors', 'IM.tosca', 'IM.openid', 'IM.tts'],
      scripts=["im_service.py"],
      data_files=datafiles,
      license="GPL version 3, http://www.gnu.org/licenses/gpl-3.0.txt",
      long_description=("IM is a tool that ease the access and the usability of IaaS clouds by automating the VMI "
                        "selection, deployment, configuration, software installation, monitoring and update of "
                        "Virtual Appliances. It supports APIs from a large number of virtual platforms, making "
                        "user applications cloud-agnostic. In addition it integrates a contextualization system to "
                        "enable the installation and configuration of all the user required applications providing "
                        "the user with a fully functional infrastructure."),
      description="IM is a tool to manage virtual infrastructures on Cloud deployments",
      platforms=["any"],
      install_requires=["ansible >= 2.0", "paramiko >= 1.14", "PyYAML", suds_pkg, sqlite_pkg, "cheroot",
                        "boto >= 2.29", "apache-libcloud >= 2.3.0", "RADL >= 1.1.1", "bottle", "netaddr",
                        "requests", "scp", "tosca-parser"]
      )
