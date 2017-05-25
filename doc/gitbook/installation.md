1. INSTALLATION
===============

1.1 REQUISITES
--------------

IM is based on Python, so Python 2.6 or higher runtime and standard library must
be installed in the system.

 + The RADL parser (https://github.com/grycap/radl), available in pip
   as the 'RADL' package. (Since IM version 1.5.3, it requires RADL version 1.1.0 or later).

 + The paramiko ssh2 protocol library for python version 1.14 or later
(http://www.lag.net/paramiko/), typically available as the 'python-paramiko' package.

 + The YAML library for Python, typically available as the 'python-yaml' or 'PyYAML' package.

 + The suds library for Python, typically available as the 'python-suds' package.
 
 + The Netaddr library for Python, typically available as the 'python-netaddr' package.

 + The Requests library for Python, typically available as the 'python-requests' package.

 + The TOSCA-Parser library for Python. Currently it must be used the INDIGO version located at
   https://github.com/indigo-dc/tosca-parser but we are working to improve the mainstream version
   to enable to use it with the IM.

 + The CherryPy Web framework (http://www.cherrypy.org/), is needed for the REST API. 
   It is typically available as the 'python-cherrypy' or 'python-cherrypy3' package.
   In newer versions (9.0 and later) the functionality has been moved to the 'cheroot' library
   (https://github.com/cherrypy/cheroot) it can be installed using pip.

 + Ansible (http://www.ansibleworks.com/) to configure nodes in the infrastructures.
   In particular, Ansible 1.4.2+ must be installed. The current recommended version is 1.9.4 untill the 2.X versions become stable.
   To ensure the functionality the following values must be set in the ansible.cfg file (usually found in /etc/ansible/):

```
[defaults]
transport  = smart
host_key_checking = False
# For old versions 1.X
sudo_user = root
sudo_exe = sudo

# For new versions 2.X
become_user      = root
become_method    = sudo

[paramiko_connection]

record_host_keys=False

[ssh_connection]

# Only in systems with OpenSSH support to ControlPersist
ssh_args = -o ControlMaster=auto -o ControlPersist=900s
# In systems with older versions of OpenSSH (RHEL 6, CentOS 6, SLES 10 or SLES 11)
#ssh_args =
pipelining = True
```

1.2 OPTIONAL PACKAGES
---------------------

The Bottle framework (http://bottlepy.org/) is used for the REST API. 
It is typically available as the 'python-bottle' package.

Apache-libcloud (http://libcloud.apache.org/) 0.17 or later is used in the
LibCloud, OpenStack and GCE connectors.

Boto (http://boto.readthedocs.org) 2.29.0 or later is used as interface to
Amazon EC2. It is available as package named ``python-boto`` in Debian based
distributions. It can also be downloaded from `boto GitHub repository (https://github.com/boto/boto).
Download the file and copy the boto subdirectory into the IM install path.

In case of using the a MySQL DB as the backend to store IM data. The Python interface to MySQL
must be installed, typically available as the package 'python-mysqldb' or 'MySQL-python' package.
In case of using Python 3 use the PyMySQL package, available as the package 'python3-pymysql' on 
debian systems or PyMySQL package in pip.

In case of using the SSL secured version of the REST API pyOpenSSL must be installed.

Azure python SDK (https://azure.microsoft.com/es-es/develop/python/) is used to connect with the 
Microsoft Azure platform.


1.3 INSTALLING
--------------

### 1.3.1 Using installer (Recommended option)

The IM provides a script to install the IM in one single step.
You only need to execute the following command:

```sh
$ wget -qO- https://raw.githubusercontent.com/grycap/im/master/install.sh | bash
```

It works for the most recent version of the main Linux distributions (RHEL/CentOS 7, Ubuntu 14/16).

### 1.3.2 FROM RPM

You must have the epel repository enabled:

```sh
$ yum install epel-release
```

Then you have to enable the INDIGO - DataCloud packages repositories. See full instructions
[here](https://indigo-dc.gitbooks.io/indigo-datacloud-releases/content/generic_installation_and_configuration_guide_1.html#id4). Briefly you have to download the repo file from [INDIGO SW Repository](http://repo.indigo-datacloud.eu/repos/1/indigo1.repo) in your /etc/yum.repos.d folder.

```sh
$ cd /etc/yum.repos.d
$ wget http://repo.indigo-datacloud.eu/repos/1/indigo1.repo
```

And then install the GPG key for the INDIGO repository:

```sh
$ rpm --import http://repo.indigo-datacloud.eu/repository/RPM-GPG-KEY-indigodc
```

Finally install the IM package.

```sh
$ yum install IM
```

### 1.3.3 FROM DEB

You have to enable the INDIGO - DataCloud packages repositories. See full instructions
[here](https://indigo-dc.gitbooks.io/indigo-datacloud-releases/content/generic_installation_and_configuration_guide_1.html#id4). Briefly you have to download the list file from [INDIGO SW Repository](http://repo.indigo-datacloud.eu/repos/1/indigo1-ubuntu14_04.list) in your /etc/apt/sources.list.d folder.

```sh
$ cd /etc/apt/sources.list.d
$ wget http://repo.indigo-datacloud.eu/repos/1/indigo1-ubuntu14_04.list
```

And then install the GPG key for INDIGO the repository:

```sh
$ wget -q -O - http://repo.indigo-datacloud.eu/repository/RPM-GPG-KEY-indigodc | sudo apt-key add -
```

Finally install the IM package.

```sh
$ apt update
$ apt install python-im
```

1.4 CONFIGURATION
-----------------

In case that you want the IM service to be started at boot time, you must
execute the next set of commands:

On Debian Systems:

```sh
$ chkconfig im on
```

Or for newer systems like ubuntu 14.04:

```sh
$ sysv-rc-conf im on
```

On RedHat Systems:

```sh
$ update-rc.d im start 99 2 3 4 5 . stop 05 0 1 6 .
```

Or you can do it manually:

```sh
$ ln -s /etc/init.d/im /etc/rc2.d/S99im
$ ln -s /etc/init.d/im /etc/rc3.d/S99im
$ ln -s /etc/init.d/im /etc/rc5.d/S99im
$ ln -s /etc/init.d/im /etc/rc1.d/K05im
$ ln -s /etc/init.d/im /etc/rc6.d/K05im
```

Adjust the installation path by setting the IMDAEMON variable at /etc/init.d/im
to the path where the IM im_service.py file is installed (e.g. /usr/local/im/im_service.py),
or set the name of the script file (im_service.py) if the file is in the PATH
(pip puts the im_service.py file in the PATH as default).

Check the parameters in $IM_PATH/etc/im.cfg or /etc/im/im.cfg. Please pay attention
to the next configuration variables, as they are the most important

```
DATA_DB - must be set to the URL to access the database to store the IM data. 
         Be careful if you have two different instances of the IM service running in the same machine!!.
         It can be a MySQL DB: 'mysql://username:password@server/db_name' or 
         a SQLite one: 'sqlite:///etc/im/inf.dat'.

CONTEXTUALIZATION_DIR - must be set to the full path where the IM contextualization files
		are located. In case of using pip installation the default value is correct
		(/usr/share/im/contextualization) in case of installing from sources set to
		$IM_PATH/contextualization (e.g. /usr/local/im/contextualization)
```

### 1.4.1 SECURITY

Security is disabled by default. Please notice that someone with local network access can "sniff" the traffic and
get the messages with the IM with the authorisation data with the cloud providers.

Security can be activated both in the XMLRPC and REST APIs. Setting this variables:

```
XMLRCP_SSL = True
```

or

```
REST_SSL = True
```

And then set the variables: XMLRCP_SSL_* or REST_SSL_* to your certificates paths.

### 1.4.2 SINGLE SITE

To configure the IM as the orchestrator of a single site you can use the SINGLE_SITE* 
configuration variables. This is an example for an OpenNebula based site assuming that
the hostname of the OpenNebula server is 'server.com':

```
SINGLE_SITE = True
SINGLE_SITE_TYPE = OpenNebula
SINGLE_SITE_AUTH_HOST = http://server.com:2633
SINGLE_SITE_IMAGE_URL_PREFIX = one://server.com
```

And this second example shows how to configure for an OpenStack based site assuming that
the hostname of the OpenStack keystone server is 'server.com':

```
SINGLE_SITE = True
SINGLE_SITE_TYPE = OpenStack
SINGLE_SITE_AUTH_HOST = https://server.com:5000
SINGLE_SITE_IMAGE_URL_PREFIX = ost://server.com
```

Using this kind of configuration combined with OIDC tokens the IM authentication is
simplified and an standard 'Bearer' authorization header can be using to interact with the IM service. 

### 1.4.3 OPENNEBULA TTS INTEGRATION

The IM service enables to configure a WaTTS - the INDIGO Token Translation Service (https://github.com/indigo-dc/tts)
to access OpenNebula sites. IM uses version 2 of the WaTTS API (https://indigo-dc.gitbooks.io/token-translation-service/content/api.html)

To configure it you must set the value of the TTS_URL in the OpenNebula section: 

```
TTS_URL = https://localhost:8443
```

In particular the WaTTS instance must be configured to include the hostname of the OpenNebula server
in the plugin configuration of the WaTTS service, for example like this:

```
service.onesite.description = server.com 
```

