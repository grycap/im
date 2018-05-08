#!/bin/bash

apt update
apt install -y python-stdeb
# remove the ansible requirement as it makes to generate an incorrect dependency python-ansible
# also remove the pysqlite requirement as it makes to generate an incorrect dependency python-pysqlite1.1
sed -i '/install_requires/c\      install_requires=["paramiko >= 1.14", "PyYAML", suds_pkg,' setup.py
python setup.py --command-packages=stdeb.command sdist_dsc --depends "python-radl, python-mysqldb, python-pysqlite2, ansible, python-paramiko, python-yaml, python-suds, python-boto, python-libcloud, python-bottle, python-netaddr, python-scp, python-cherrypy3, python-requests, python-tosca-parser" bdist_deb
mkdir dist_pkg
cp deb_dist/*.deb dist_pkg


