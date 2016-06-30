#!/bin/bash

apt update
apt install -y dh-make python-stdeb fakeroot python-all python-setuptools
python setup.py --command-packages=stdeb.command sdist_dsc --depends "python-radl, ansible, python-paramiko, python-yaml, python-soappy, python-boto, python-libcloud, python-bottle, python-netaddr, python-scp" bdist_deb
mkdir dist_pkg
cp deb_dist/*.deb dist_pkg