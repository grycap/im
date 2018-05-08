#!/bin/bash

yum -y install rpm-build python-setuptools
echo "%_unpackaged_files_terminate_build 0" > ~/.rpmmacros
python setup.py bdist_rpm --release="$1" --requires="which, MySQL-python, python-sqlite3dbm, RADL, ansible, python-paramiko, PyYAML, python-suds, python-boto >= 2.29, python-libcloud, python-bottle, python-netaddr, python-scp, python-cherrypy, python-requests, python-xmltodict, tosca-parser"
mkdir dist_pkg
cp dist/*.noarch.rpm dist_pkg
