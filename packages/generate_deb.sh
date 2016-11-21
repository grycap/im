#!/bin/bash

apt update
apt install -y python-stdeb
# remove the ansible requirement as it makes to generate an incorrect dependency python-ansible
sed -i '/install_requires/c\      install_requires=["paramiko >= 1.14", "PyYAML", "SOAPpy",' setup.py
python setup.py --command-packages=stdeb.command sdist_dsc --depends "python-radl, python-mysqldb, python-sqlite, ansible, python-paramiko, python-yaml, python-soappy, python-boto, python-libcloud, python-bottle, python-netaddr, python-scp, python-cherrypy3" bdist_deb
mkdir dist_pkg
cp deb_dist/*.deb dist_pkg