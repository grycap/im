#!/bin/bash

yum -y install rpm-build python-setuptools
echo "%_unpackaged_files_terminate_build 0" > ~/.rpmmacros
python setup.py bdist_rpm --release="$1" --requires="which, tosca-parser, RADL, ansible, python-paramiko, PyYAML, SOAPpy, python-boto >= 2.29, python-libcloud, python-bottle, python-netaddr, python-scp"
mkdir dist_pkg
cp dist/*.noarch.rpm dist_pkg
