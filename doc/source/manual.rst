
IM Service Installation
=======================

Prerequisites
-------------

IM needs at least Python 2.4 to run, as well as the next libraries:

* `Python Lex & Yacc <http://www.dabeaz.com/ply/>`_, ssh2 protocol library for python.
* `paramiko <http://www.lag.net/paramiko/>`_, ssh2 protocol library for python.
* `PyYAML <http://pyyaml.org/>`_, a YAML parser.
* `SOAPpy <http://pywebsvcs.sourceforge.net/>`_, a full-featured SOAP library
  (we know it is not actively supported by upstream anymore).

Also, IM uses `Ansible <http://www.ansible.com>`_ (1.4.2 or later) to configure the
infrastructure nodes.
 
These components are usually available from the distribution repositories. To
install them in Debian and Ubuntu based distributions, do::

   $ apt-get install python-ply python-paramiko python-yaml python-soappy ansible

In Red Hat based distributions (RHEL, CentOS, Amazon Linux, Oracle Linux,
Fedora, etc.), do::

   $ yum install python-ply python-paramiko PyYAML SOAPpy ansible

Finally, check the next values in the Ansible configuration file
:file:`ansible.cfg`, (usually found in :file:`/etc/ansible`)::

   host_key_checking = False
   transport = paramiko
   record_host_keys = False

Optional Packages
-----------------

* `apache-libcloud <http://libcloud.apache.org/>`_ 0.15 or later is used in the
  LibCloud connector.
* `boto <http://boto.readthedocs.org>`_ 2.19.0 or later is used as interface to
  Amazon EC2. It is available as package named ``python-boto`` in Debian based
  distributions. It can also be downloaded from `boto GitHub repository <https://github.com/boto/boto>`_.
  Download the file and copy the boto subdirectory into the IM install path.
* `Spring Python <http://springpython.webfactional.com/>`_ framework is needed
  if the access to XML-RPC API is secured with SSL certificates (see
  :confval:`XMLRCP_SSL`).
  The Debian package is named ``python-springpython``.
* `CherryPy <http://cherrypy.org>`_ is needed if needed to secure the REST API
  with SSL certificates (see :confval:`REST_SSL`).
  The Debian package is named ``python-cherrypy3``.

Installation
------------

Form Pip
^^^^^^^^^^^

You only have to call the install command of the pip tool with the IM package::

**WARNING: In some linux distributions (REL 6 or equivalents) you must unistall
the packages python-paramiko and python-crypto before installing the IM with pip.**

   $ pip install IM

Finally you must set the executable permissions on the init script::

   $ chmod +x /etc/init.d/im

Form Source
^^^^^^^^^^^

Once the dependences are installed, just download the tarball of *IM Service*
from `Download <http://www.grycap.upv.es/im/download.php>`_, extract the
content and move the extracted directory to the installation path (for instance
:file:`/usr/local` or :file:`/opt`)::

   $ tar xvzf IM-0.1.tar.gz
   $ sudo chown -R root:root IM-0.1.tar.gz
   $ sudo mv IM-0.1 /usr/local

Finally you must copy (or link) $IM_PATH/im file to /etc/init.d directory::

   $ sudo ln -s /usr/local/IM-0.1/im /etc/init.d

Configuration
-------------

If you want the IM Service to be started at boot time, do

1. Update the value of the variable ``IMDAEMON`` in :file:`/etc/init.d/im` file to
   the installation path::

   $ sudo sed -i 's/`IMDAEMON=.*/`IMDAEMON=/usr/local/IM-0.1/im_service.py'/etc/init.d/im

3. Register the service.

To do the last step on a Debian based distributions, execute::

   $ sudo update-rc.d im start 99 2 3 4 5 . stop 05 0 1 6 .

or the next command on Red Hat based::

   $ sudo chkconfig im on

Alternatively, it can be done manually::

   $ ln -s /etc/init.d/im /etc/rc2.d/S99im
   $ ln -s /etc/init.d/im /etc/rc3.d/S99im
   $ ln -s /etc/init.d/im /etc/rc5.d/S99im
   $ ln -s /etc/init.d/im /etc/rc1.d/K05im
   $ ln -s /etc/init.d/im /etc/rc6.d/K05im

IM reads the configuration from :file:`$IM_PATH/etc/im.cfg`, and if it is not
available, does from ``/etc/im/im.cfg``. There is a template of :file:`im.cfg`
at the directory :file:`etc` on the tarball. The options are explained next.

Basic Options
^^^^^^^^^^^^^

.. confval:: DATA_FILE

   Full path to the data file.
   The default value is :file:`/etc/im/inf.dat`.

.. confval:: MAX_VM_FAILS

   Number of attempts to launch a virtual machine before considering it
   an error.
   The default value is 3.

.. confval:: WAIT_RUNNING_VM_TIMEOUT

   Timeout in seconds to get a virtual machine in running state.
   The default value is 1800.

.. confval:: LOG_FILE

   Full path to the log file.
   The default value is :file:`/var/log/im/inf.log`.

.. confval:: LOG_FILE_MAX_SIZE

   Maximum size in KiB of the log file before being rotated.
   The default value is 10485760.

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

.. confval:: DEFAULT_MASTERVM_NAME 

   Default name of virtual machine with the *master* role.
   The default value is ``vmmaster``.

.. confval:: DEFAULT_DOMAIN 

   Default domain assigned to a virtual machine.
   The default value is ``localdomain``.

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

.. _options-xmlrpc:

XML-RPC API
^^^^^^^^^^^

.. confval:: XMLRCP_PORT

   Port number where IM XML-RPC API is available.
   The default value is 8899.

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



