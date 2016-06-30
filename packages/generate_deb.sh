#!/bin/bash

apt update
apt install -y python-stdeb
python setup.py --command-packages=stdeb.command sdist_dsc --depends "python-tosca-parser, python-radl, ansible, python-paramiko, python-yaml, python-soappy, python-boto, python-libcloud, python-bottle, python-netaddr, python-scp" bdist_deb
mkdir dist_pkg
cp deb_dist/*.deb dist_pkg