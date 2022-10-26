# IM - Infrastructure Manager

[![PyPI](https://img.shields.io/pypi/v/im.svg)](https://pypi.org/project/im)
[![Build Status](https://jenkins.i3m.upv.es/buildStatus/icon?job=grycap/im-unit-master)](https://jenkins.i3m.upv.es/job/grycap/job/im-unit-master/)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/582a0d6e763f44bdade11133e5191439)](https://www.codacy.com/gh/grycap/im/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=grycap/im&amp;utm_campaign=Badge_Grade)
[![Codacy Badge](https://app.codacy.com/project/badge/Coverage/582a0d6e763f44bdade11133e5191439)](https://www.codacy.com/gh/grycap/im/dashboard?utm_source=github.com&utm_medium=referral&utm_content=grycap/im&utm_campaign=Badge_Coverage)
[![License](https://img.shields.io/badge/license-GPL%20v3.0-brightgreen.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-brightgreen.svg)](https://imdocs.readthedocs.io/en/latest/)

IM is a tool that deploys complex and customized virtual infrastructures on
IaaS Cloud deployments (such as AWS, OpenStack, etc.). It eases the access and
the usability of IaaS clouds by automating the VMI (Virtual Machine Image)
selection, deployment, configuration, software installation, monitoring and
update of the virtual infrastructure. It supports APIs from a large number of
virtual platforms, making user applications cloud-agnostic. In addition it
integrates a contextualization system to enable the installation and
configuration of all the user required applications providing the user with a
fully functional infrastructure.

Read the documentation and more at <http://www.grycap.upv.es/im>.

There is also an Infrastructure Manager YouTube reproduction list with a set of
videos with demos of the functionality of the platform: <https://www.youtube.com/playlist?list=PLgPH186Qwh_37AMhEruhVKZSfoYpHkrUp>.

Please acknowledge the use of this software in your scientific publications by
including the following reference:

Miguel Caballer, Ignacio Blanquer, German Molto, and Carlos de Alfonso.
"[Dynamic management of virtual infrastructures](https://link.springer.com/article/10.1007/s10723-014-9296-5)".
Journal of Grid Computing, Volume 13, Issue 1, Pages 53-70, 2015, ISSN
1570-7873, DOI: 10.1007/s10723-014-9296-5.

## 1 DOCKER IMAGE (Recommended Option)

The recommended option to use the Infrastructure Manager service is using the
available docker image. A Docker image named `grycap/im` has been created to
make easier the deployment of an IM service using the default configuration.
Information about this image can be found here: <https://hub.docker.com/r/grycap/im/>.
It is also available in Github Container registry `ghcr.io/grycap/im`:
<https://github.com/grycap/im/pkgs/container/im>.

How to launch the IM service using docker::

```sh
sudo docker run -d -p 8899:8899 -p 8800:8800 --name im grycap/im
```

To make the IM data persistent you also have to specify a persistent location
for the IM database using the IM_DATA_DB environment variable and adding a
volume::

```sh
sudo docker run -d -p 8899:8899 -p 8800:8800 -v "/some_local_path/db:/db" \
                -e IM_DATA_DB=/db/inf.dat --name im grycap/im
```

You can also specify an external MySQL server to store IM data using the
IM_DATA_DB environment variable::

```sh
sudo docker run -d -p 8899:8899 -p 8800:8800 \
                -e IM_DATA_DB=mysql://username:password@server/db_name \
                --name im grycap/im
```

Or you can also add a volume with all the IM configuration::

```sh
sudo docker run -d -p 8899:8899 -p 8800:8800 \
                -v "/some_local_path/im.cfg:/etc/im/im.cfg"
                --name im grycap/im
```

## 2 Kubernetes Helm Chart

The IM service and web interface can be installed on top of [Kubernetes](https://kubernetes.io/)
using [Helm](https://helm.sh/).

How to install the IM chart:

First add the GRyCAP repo:

```sh
helm repo add grycap https://grycap.github.io/helm-charts/
```

Then install the IM chart (with Helm v2):

```sh
helm install --namespace=im --name=im  grycap/IM
```

Then install the IM chart (with Helm v3):

```sh
helm install --namespace=im --create-namespace im  grycap/IM
```

All the information about this chart is available at the [IM chart README](https://github.com/grycap/helm-charts/blob/master/IM/README.md).

## 3 INSTALLATION

### 3.1 REQUISITES

IM is based on Python, so Python 2.7 or higher (Python 3.6 or higher
recommended) runtime and standard library must be installed in the system.

If you use pip to install the IM, all the requisites will be installed.
However, if you install IM from sources you should install:

* The RADL parser (<https://github.com/grycap/radl>), available in pip
  as the ``RADL`` package.
* The paramiko ssh2 protocol library for python version 1.14 or later
  (<http://www.lag.net/paramiko/>), typically available as the
  ``python-paramiko`` package.
* The YAML library for Python, typically available as the ``python-yaml`` or
  ``PyYAML`` package.
* The suds library for Python, typically available as the ``python-suds``
  package.
* The Netaddr library for Python, typically available as the ``python-netaddr``
  package.
* The Requests library for Python, typically available as the
  ``python-requests`` package.
* TOSCA parser library for Python, available as the ``tosca-parser`` package in
  pip.
* Ansible (<http://www.ansibleworks.com/>) to configure nodes in the
  infrastructures.
   In particular, Ansible 2.4+ must be installed.
   To ensure the functionality the following values must be set in the
   ansible.cfg file (usually found in /etc/ansible/):

```yml
[defaults]
transport  = smart
host_key_checking = False
nocolor = 1

become_user      = root
become_method    = sudo

[paramiko_connection]

record_host_keys=False

[ssh_connection]

# Only in systems with OpenSSH support to ControlPersist
ssh_args = -o ControlMaster=auto -o ControlPersist=900s -o UserKnownHostsFile=/dev/null
# In systems with older versions of OpenSSH (RHEL 6, CentOS 6, SLES 10 or SLES 11)
#ssh_args = -o UserKnownHostsFile=/dev/null
pipelining = True
```

### 3.2 OPTIONAL PACKAGES

The Bottle framework (<http://bottlepy.org/>) is used for the REST API.
It is typically available as the ``python-bottle`` system package or ``bottle``
pip package.

The CherryPy Web framework (<http://www.cherrypy.org/>), is needed for the REST
API. It is typically available as the ``python-cherrypy`` or
``python-cherrypy3`` system package or ``CherryPy`` pip package.
In newer versions (9.0 and later) the functionality has been moved to the
``cheroot`` library (<https://github.com/cherrypy/cheroot>) it can be
installed using pip.

Apache-libcloud (<http://libcloud.apache.org/>) 3.0 or later is used in the
LibCloud, OpenStack and GCE connectors. It is typically available as the
``python-libcloud`` system package or ``apache-libcloud`` pip package.

Boto (<http://boto.readthedocs.org>) 2.29.0 or later is used as interface to
Amazon EC2. It is available as package named ``python-boto`` in Debian based
distributions or ``boto`` pip package. It can also be downloaded from boto
GitHub repository (<https://github.com/boto/boto>).
Download the file and copy the boto subdirectory into the IM install path.

In case of using the a MySQL DB as the backend to store IM data. The Python
interface to MySQL must be installed, typically available as the package
``python-mysqldb`` or ``MySQL-python`` package. In case of using Python 3 use
the PyMySQL package, available as the package ``python3-pymysql`` on
debian systems or ``PyMySQL`` package in pip.

In case of using the a MongoDB as the backend to store IM data. The Python
interface to MongoDB must be installed, typically available as the package
``python-pymongo``package in most distributions or ``pymongo`` pip package.

In case of using the SSL secured version of the REST API pyOpenSSL
(<https://pyopenssl.org/>) must be installed. available as ``pyOpenSSL``
package in pip.

Azure python SDK (<https://azure.microsoft.com/es-es/develop/python/>) is used
to connect with the Microsoft Azure platform. The easiest way is to install all
the required packages with pip:

```sh
pip install msrest msrestazure azure-common azure-mgmt-storage \
            azure-mgmt-compute azure-mgmt-network azure-mgmt-resource \
            azure-mgmt-dns azure-identity
```

The VMware vSphere API Python Bindings (<https://github.com/vmware/pyvmomi/>)
are needed by the vSphere connector. It is available as the package ``pyvmomi``
at the pip repository.

### 3.3 INSTALLING

#### 3.3.1 From PIP

First you need to install pip tool and some packages needed to compile some of
the IM requirements. To install them in Debian and Ubuntu based distributions,
do::

```sh
apt update
apt install -y gcc python3-dev libffi-dev libssl-dev python3-pip sshpass \
               default-libmysqlclient-dev
```

In Red Hat based distributions (RHEL, CentOS, Amazon Linux, Oracle Linux,
Fedora, etc.), do:

```sh
yum install -y epel-release
yum install -y which gcc python3-devel libffi-devel openssl-devel \
               python3-pip sshpass
```

Then you only have to call the install command of the pip tool with the IM
package:

```sh
pip3 install IM
```

You can also install an specific branch of the Github repository:

```sh
pip install git+https://github.com/grycap/im.git@master
```

Pip will also install the, non installed, pre-requisites needed. So Ansible 2.4
or later will be installed in the system. Some of the optional packages are
also installed please check if some of IM features that you need requires to
install some of the packages of section OPTIONAL PACKAGES.

You must also remember to modify the ansible.cfg file setting as specified in
the REQUISITES section.

### 3.4 START IM ON BOOT

In case that you want the IM service to be started at boot time, you must
execute the next set of commands:

On Debian Systems:

```sh
chkconfig im on
```

Or for newer systems like ubuntu 14.04:

```sh
sysv-rc-conf im on
```

On RedHat Systems:

```sh
update-rc.d im start 99 2 3 4 5 . stop 05 0 1 6 .
```

Or you can do it manually:

```sh
ln -s /etc/init.d/im /etc/rc2.d/S99im
ln -s /etc/init.d/im /etc/rc3.d/S99im
ln -s /etc/init.d/im /etc/rc5.d/S99im
ln -s /etc/init.d/im /etc/rc1.d/K05im
ln -s /etc/init.d/im /etc/rc6.d/K05im
```

Adjust the installation path by setting the IMDAEMON variable at /etc/init.d/im
to the path where the IM im_service.py file is installed (e.g.
/usr/local/im/im_service.py), or set the name of the script file
(im_service.py) if the file is in the PATH (pip puts the im_service.py file in
the PATH as default).

### 4 CONFIGURATION

Check the parameters in $IM_PATH/etc/im.cfg or /etc/im/im.cfg.
See [IM Manual](https://imdocs.readthedocs.io/en/latest/manual.html#configuration)
to get a full reference of the configuration variables.

Please pay attention to the next configuration variables, as they are the most
important:

DATA_DB - must be set to the URL to access the database to store the IM data.
         Be careful if you have two different instances of the IM service
         running in the same machine!!.
         It can be a MySQL DB: `mysql://username:password@server/db_name`,
         SQLite: `sqlite:///etc/im/inf.dat` or MongoDB:
         `mongodb://username:password@server/db_name`,

#### 4.1 SECURITY

Security is disabled by default. Please notice that someone with local network
access can "sniff" the traffic and get the messages with the IM with the
authorisation data with the cloud providers.

Security can be activated both in the XMLRPC and REST APIs. Setting this
variables:

```sh
XMLRCP_SSL = True
```

or

```sh
REST_SSL = True
```

And then set the variables: XMLRCP_SSL_* or REST_SSL_* to your certificates
paths.
