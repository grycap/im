
IM Service Installation
=======================

Prerequisites
-------------

IM needs at least Python 2.6 to run, as well as the next libraries:

* `The RADL parser <https://github.com/grycap/radl>`_.
* `paramiko <http://www.lag.net/paramiko/>`_, ssh2 protocol library for python
  (version 1.14 or later).
* `PyYAML <http://pyyaml.org/>`_, a YAML parser.
* `SOAPpy <http://pywebsvcs.sourceforge.net/>`_, a full-featured SOAP library
  (we know it is not actively supported by upstream anymore).
* `Netaddr <http://pythonhosted.org/netaddr//>`_, A Python library for representing 
  and manipulating network addresses.

Also, IM uses `Ansible <http://www.ansible.com>`_ (1.4.2 or later) to configure the
infrastructure nodes. The current recommended version is 1.9.4 untill the 2.X versions become stable.
 
These components are usually available from the distribution repositories. To
install them in Debian and Ubuntu based distributions, do::

   $ apt-get install python-ply python-paramiko python-yaml python-soappy python-netaddr ansible

In Red Hat based distributions (RHEL, CentOS, Amazon Linux, Oracle Linux,
Fedora, etc.), do::

   $ yum install python-ply python-paramiko python-netaddr PyYAML SOAPpy ansible
   
**WARNING: In some GNU/Linux distributions (RHEL 6 or equivalents) you must NOT install
the packages 'python-paramiko' and 'python-crypto' with yum. You MUST use pip to install them**

Finally, check the next values in the Ansible configuration file
:file:`ansible.cfg`, (usually found in :file:`/etc/ansible`)::

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

Optional Packages
-----------------

* `apache-libcloud <http://libcloud.apache.org/>`_ 0.17 or later is used in the
  LibCloud, OpenStack and GCE connectors.
* `boto <http://boto.readthedocs.org>`_ 2.29.0 or later is used as interface to
  Amazon EC2. It is available as package named ``python-boto`` in Debian based
  distributions. It can also be downloaded from `boto GitHub repository <https://github.com/boto/boto>`_.
  Download the file and copy the boto subdirectory into the IM install path.
* `Spring Python <http://springpython.webfactional.com/>`_ framework is needed
  if the access to XML-RPC API is secured with SSL certificates (see
  :confval:`XMLRCP_SSL`).
  The Debian package is named ``python-springpython``.
* `Bottle <http://bottlepy.or>`_ is needed if needed to use the REST API
  (see :confval:`ACTIVATE_REST`). The Debian package is named ``python-bottle``.
* `CherryPy <http://cherrypy.org>`_ and pyOpenSSL are needed if needed to secure the REST API
  with SSL certificates (see :confval:`REST_SSL`).
  The Debian package for CherryPy is named ``python-cherrypy3``.
  pyOpenSSL can be installed using pip.

Installation
------------

Form Pip
^^^^^^^^

**WARNING: The SOAPpy distributed with pip does not work correctly so you must install
the packages 'python-soappy' or 'SOAPpy' before installing the IM with pip.**

**WARNING: In some linux distributions (REL 6 or equivalents) you must unistall
the packages python-paramiko and python-crypto before installing the IM with pip.**

You only have to call the install command of the pip tool with the IM package::

   $ pip install IM

Pip will install all the pre-requisites needed. So Ansible  1.4.2 or later will 
be installed in the system. Yo will also need to install the sshpass command 
('sshpass' package in main distributions). In some cases it will need to have installed  
the GCC compiler and the python developer libraries ('python-dev' or 'python-devel' 
packages in main distributions).

You must also remember to modify the ansible.cfg file setting as specified in the 
REQUISITES section.

Form Source
^^^^^^^^^^^

Once the dependences are installed, just download the tarball of *IM Service*
from `Download <https://github.com/grycap/im>`_, extract the 
content and move the extracted directory to the installation path (for instance
:file:`/usr/local` or :file:`/opt`)::

   $ tar xvzf IM-0.1.tar.gz
   $ sudo chown -R root:root IM-0.1.tar.gz
   $ sudo mv IM-0.1 /usr/local

Finally you must copy (or link) $IM_PATH/scripts/im file to /etc/init.d directory::

   $ sudo ln -s /usr/local/IM-0.1/scripts/im /etc/init.d

Configuration
-------------

If you want the IM Service to be started at boot time, do

1. Update the value of the variable ``IMDAEMON`` in :file:`/etc/init.d/im` file
   to the path where the IM im_service.py file is installed (e.g. /usr/local/im/im_service.py),
   or set the name of the script file (im_service.py) if the file is in the PATH
   (pip puts the im_service.py file in the PATH as default)::

   $ sudo sed -i 's/`IMDAEMON=.*/`IMDAEMON=/usr/local/IM-0.1/im_service.py'/etc/init.d/im

2. Register the service.

To do the last step on a Debian based distributions, execute::

   $ sudo sysv-rc-conf im on

if the package 'sysv-rc-conf' is not available in your distribution, execute::

   $ sudo update-rc.d im start 99 2 3 4 5 . stop 05 0 1 6 .

For Red Hat based distributions::

   $ sudo chkconfig im on

Alternatively, it can be done manually::

   $ ln -s /etc/init.d/im /etc/rc2.d/S99im
   $ ln -s /etc/init.d/im /etc/rc3.d/S99im
   $ ln -s /etc/init.d/im /etc/rc5.d/S99im
   $ ln -s /etc/init.d/im /etc/rc1.d/K05im
   $ ln -s /etc/init.d/im /etc/rc6.d/K05im

IM reads the configuration from :file:`$IM_PATH/etc/im.cfg`, and if it is not
available, does from ``/etc/im/im.cfg``. There is a template of :file:`im.cfg`
at the directory :file:`etc` on the tarball. The IM reads the values of the ``im``
section. The options are explained next.

.. _options-basic:

Basic Options
^^^^^^^^^^^^^

.. confval:: DATA_FILE

   Full path to the data file.
   The default value is :file:`/etc/im/inf.dat`.
   
.. confval:: DATA_DB

   Save IM data into a MySQL DB instead of a file.
   Using this format: 'mysql://username:password@server/db_name'
   The default value is None.
   
.. confval:: USER_DB

   Full path to the IM user DB json file.
   To restrict the users that can access the IM service.
   Comment it or set a blank value to disable user check.
   The default value is empty.
   JSON format of the file::
   
   	{
   		"users": [
   			{
   				"username": "user1",
   				"password": "pass1"
   			},
   			{
   				"username": "user2",
   				"password": "pass2"
   			}
   		]
   	}
   
.. confval:: MAX_SIMULTANEOUS_LAUNCHES

   Maximum number of simultaneous VM launch operations.
   In some versions of python (prior to 2.7.5 or 3.3.2) it can raise an error 
   ('Thread' object has no attribute '_children'). See https://bugs.python.org/issue10015.
   In this case set this value to 1
   
   The default value is 1.
 
.. confval:: MAX_VM_FAILS

   Number of attempts to launch a virtual machine before considering it
   an error.
   The default value is 3.

.. confval:: VM_INFO_UPDATE_FREQUENCY

   Maximum frequency to update the VM info (in secs)
   The default value is 10.
   
.. confval:: VM_INFO_UPDATE_ERROR_GRACE_PERIOD

   Maximum time that a VM status maintains the current status in case of connection failure with the 
   Cloud provider (in secs). If the time is over this value the status is set to 'unknown'. 
   This value must be always higher than VM_INFO_UPDATE_FREQUENCY.
   The default value is 120.

.. confval:: WAIT_RUNNING_VM_TIMEOUT

   Timeout in seconds to get a virtual machine in running state.
   The default value is 1800.

.. confval:: LOG_FILE

   Full path to the log file.
   The default value is :file:`/var/log/im/inf.log`.

.. confval:: LOG_FILE_MAX_SIZE

   Maximum size in KiB of the log file before being rotated.
   The default value is 10485760.

.. _options-default-vm:

Default Virtual Machine Options
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. confval:: DEFAULT_VM_MEMORY 

   Default principal memory assigned to a virtual machine.
   The default value is 512.

.. confval:: DEFAULT_VM_MEMORY_UNIT 

   Unit used in :confval:`DEFAULT_VM_MEMORY`.
   Allowed values: ``K`` (KiB), ``M`` (MiB) and ``G`` (GiB).
   The default value is ``M``.

.. confval:: DEFAULT_VM_CPUS 

   Default number of CPUs assigned to a virtual machine.
   The default value is 1.

.. confval:: DEFAULT_VM_CPU_ARCH 

   Default CPU architecture assigned to a virtual machine.
   Allowed values: ``i386`` and ``x86_64``.
   The default value is ``x86_64``.

.. confval:: DEFAULT_VM_NAME 

   Default name of virtual machines.
   The default value is ``vnode-#N#``.

.. confval:: DEFAULT_DOMAIN 

   Default domain assigned to a virtual machine.
   The default value is ``localdomain``.

.. _options-ctxt:

Contextualization
^^^^^^^^^^^^^^^^^

.. confval:: CONTEXTUALIZATION_DIR

   Full path to the IM contextualization files.
   The default value is :file:`/usr/share/im/contextualization`.

.. confval:: RECIPES_DIR 

   Full path to the Ansible recipes directory.
   The default value is :file:`CONTEXTUALIZATION_DIR/AnsibleRecipes`.

.. confval:: RECIPES_DB_FILE 

   Full path to the Ansible recipes database file.
   The default value is :file:`CONTEXTUALIZATION_DIR/recipes_ansible.db`.

.. confval:: MAX_CONTEXTUALIZATION_TIME 

   Maximum time in seconds spent on contextualize a virtual machine before
   throwing an error.
   The default value is 7200.
   
.. confval:: REMOTE_CONF_DIR 

   Directory to copy all the ansible related files used in the contextualization.
   The default value is :file:`/tmp/.im`.
   
.. confval:: PLAYBOOK_RETRIES 

   Number of retries of the Ansible playbooks in case of failure.
   The default value is 1.
   
.. confval:: CHECK_CTXT_PROCESS_INTERVAL

   Interval to update the state of the contextualization process in the VMs (in secs).
   Reducing this time the load of the IM service will decrease in contextualization steps,
   but may introduce some overhead time. 
   The default value is 5.

.. confval:: CONFMAMAGER_CHECK_STATE_INTERVAL
   
   Interval to update the state of the processes of the ConfManager (in secs).
   Reducing this time the load of the IM service will decrease in contextualization steps,
   but may introduce some overhead time.
   The default value is 5.

.. confval:: UPDATE_CTXT_LOG_INTERVAL

   Interval to update the log output of the contextualization process in the VMs (in secs).
   The default value is 20.

.. _options-xmlrpc:

XML-RPC API
^^^^^^^^^^^

.. confval:: XMLRCP_PORT

   Port number where IM XML-RPC API is available.
   The default value is 8899.
   
.. confval:: XMLRCP_ADDRESS

   IP address where IM XML-RPC API is available.
   The default value is 0.0.0.0 (all the IPs).

.. confval:: XMLRCP_SSL 

   If ``True`` the XML-RPC API is secured with SSL certificates.
   The default value is ``False``.

.. confval:: XMLRCP_SSL_KEYFILE 

   Full path to the private key associated to the SSL certificate to access
   the XML-RPC API.
   The default value is :file:`/etc/im/pki/server-key.pem`.

.. confval:: XMLRCP_SSL_CERTFILE 

   Full path to the public key associated to the SSL certificate to access
   the XML-RPC API.
   The default value is :file:`/etc/im/pki/server-cert.pem`.

.. confval:: XMLRCP_SSL_CA_CERTS 

   Full path to the SSL Certification Authorities (CA) certificate.
   The default value is :file:`/etc/im/pki/ca-chain.pem`.

.. _options-rest:

REST API
^^^^^^^^

.. confval:: ACTIVATE_REST 

   If ``True`` the REST API is activated.
   The default value is ``False``.

.. confval:: REST_PORT

   Port number where REST API is available.
   The default value is 8800.
   
.. confval:: REST_ADDRESS

   IP address where REST API is available.
   The default value is 0.0.0.0 (all the IPs).

.. confval:: REST_SSL 

   If ``True`` the REST API is secured with SSL certificates.
   The default value is ``False``.

.. confval:: REST_SSL_KEYFILE 

   Full path to the private key associated to the SSL certificate to access
   the REST API.
   The default value is :file:`/etc/im/pki/server-key.pem`.

.. confval:: REST_SSL_CERTFILE 

   Full path to the public key associated to the SSL certificate to access
   the REST API.
   The default value is :file:`/etc/im/pki/server-cert.pem`.

.. confval:: REST_SSL_CA_CERTS 

   Full path to the SSL Certification Authorities (CA) certificate.
   The default value is :file:`/etc/im/pki/ca-chain.pem`.

.. _options-ganglia:

GANGLIA INTEGRATION
^^^^^^^^^^^^^^^^^^^

.. confval:: GET_GANGLIA_INFO 

   Flag to enable the retrieval of the ganglia info of the VMs.
   The default value is ``False``.
   
.. confval:: GANGLIA_INFO_UPDATE_FREQUENCY 

   Maximum frequency to update the Ganglia info (in secs).
   The default value is ``30``.

NETWORK OPTIONS
^^^^^^^^^^^^^^^

.. confval:: PRIVATE_NET_MASKS 

   List of networks assumed as private. The IM use it to distinguish private from public networks.
   IM considers IPs not in these subnets as Public IPs.
   It must be a coma separated string of the network definitions (using CIDR) (without spaces).
   The default value is ``'10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,192.0.0.0/24,169.254.0.0/16,100.64.0.0/10,198.18.0.0/15'``.
   
OpenNebula connector Options
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The configuration values under the ``OpenNebula`` section:

.. confval:: TEMPLATE_CONTEXT 

   Text to add to the CONTEXT section of the ONE template (except SSH_PUBLIC_KEY)
   The default value is ``''``.

.. confval:: TEMPLATE_OTHER 

   Text to add to the ONE Template different to NAME, CPU, VCPU, MEMORY, OS, DISK and CONTEXT
   The default value is ``GRAPHICS = [type="vnc",listen="0.0.0.0"]``. 


Docker Image
============

A Docker image named `grycap/im` has been created to make easier the deployment of an IM service using the 
default configuration. Information about this image can be found here: https://registry.hub.docker.com/u/grycap/im/.

How to launch the IM service using docker::

  $ sudo docker run -d -p 8899:8899 --name im grycap/im

You can also specify an external MySQL server to store IM data using the IM_DATA_DB environment variable::
  
  $ sudo docker run -d -p 8899:8899 -e IM_DATA_DB=mysql://username:password@server/db_name --name im grycap/im 
