.. _launch_im:

IM Docker Image (Recommended Option)
====================================

The recommended option to use the Infrastructure Manager service is using the available docker image.
A Docker image named `grycap/im` has been created to make easier the deployment of an IM service using the 
default configuration. Information about this image can be found here: `https://registry.hub.docker.com/u/grycap/im/ <https://registry.hub.docker.com/u/grycap/im/>`_.
It is also available in Github Container registry ghcr.io/grycap/im: `https://github.com/grycap/im/pkgs/container/im <https://github.com/grycap/im/pkgs/container/im>`_.

How to launch the IM service using docker::

  $ sudo docker run -d -p 8899:8899 -p 8800:8800 --name im grycap/im

To make the IM data persistent you also have to specify a persistent location for the IM database using
the IM_DATA_DB environment variable and adding a volume::

  $ sudo docker run -d -p 8899:8899 -p 8800:8800 -v "/some_local_path/db:/db" -e IM_DATA_DB=/db/inf.dat --name im grycap/im

You can also specify an external MySQL server to store IM data using the IM_DATA_DB environment variable::
  
  $ sudo docker run -d -p 8899:8899 -e IM_DATA_DB=mysql://username:password@server/db_name --name im grycap/im 

Or you can also add a volume with all the IM configuration::

  $ sudo docker run -d -p 8899:8899 -p 8800:8800 -v "/some_local_path/im.cfg:/etc/im/im.cfg" --name im grycap/im


Kubernetes Helm Chart
=====================

The IM service and web interface can be installed on top of Kubernetes using Helm.

How to install the IM chart:

First add the GRyCAP repo::

  $ helm repo add grycap https://grycap.github.io/helm-charts/

Then install the IM chart (with Helm v3)::

  $ helm install --namespace=im --create-namespace im  grycap/IM

All the information about this chart is available at the `IM chart README <https://github.com/grycap/helm-charts/blob/master/IM/README.md>`_.


Configuration
=============

IM reads the configuration from :file:`$IM_PATH/etc/im.cfg`, and if it is not
available, does from ``/etc/im/im.cfg``. There is a template of :file:`im.cfg`
at the directory :file:`etc` on the tarball. The IM reads the values of the ``im``
section. The options are explained next.

.. _options-basic:

Basic Options
^^^^^^^^^^^^^

.. confval:: DATA_FILE

   Full path to the data file.
   (**Removed in version IM version 1.5.0. Use only DATA_DB.**) 
   The default value is :file:`/etc/im/inf.dat`.

.. confval:: DATA_DB

   The URL to access the database to store the IM data.
   It can be a MySQL DB: 'mysql://username:password@server/db_name', 
   SQLite: 'sqlite:///etc/im/inf.dat' or
   MongoDB: 'mongodb://username:password@server/db_name', 
   The default value is ``sqlite:///etc/im/inf.dat``.
   
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

.. confval:: WAIT_SSH_ACCCESS_TIMEOUT

   (**New in version IM version 1.5.1.**)
   Timeout in seconds to wait a virtual machine to get the SSH access active once it is in running state.
   The default value is 300.

.. confval:: LOG_FILE

   Full path to the log file.
   The default value is :file:`/var/log/im/inf.log`.

.. confval:: LOG_FILE_MAX_SIZE

   Maximum size in KiB of the log file before being rotated.
   The default value is 10485760.

.. confval:: BOOT_MODE

   This flag set the IM boot mode. 
   It can be: 0 (Normal) standard IM operation, 1 (ReadOnly) only read operations are allowed,
   2 (ReadDelete) only read and delete operations are allowed.
   The default value is 0.

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

.. confval:: VERIFI_SSL 

   Verify SSL hosts in CloudConnectors connections If you set it to True you must assure
   the CA certificates are installed correctly
   The default value is ``False``.

.. _options-ctxt:

Contextualization
^^^^^^^^^^^^^^^^^

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
   
.. confval:: VM_NUM_USE_CTXT_DIST

   Number of VMs in an infrastructure that will use the distributed version of the Ctxt Agent
   The default value is 30.

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

.. confval:: VMINFO_JSON

	Return the VM information of function GetVMInfo in RADL JSON instead of plain RADL
	(**Added in IM version 1.5.2**) 
	The default value is ``False``.

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

OPENID CONNECT OPTIONS
^^^^^^^^^^^^^^^^^^^^^^

.. confval:: OIDC_ISSUERS

   List of OIDC issuers supported.
   It must be a coma separated string of OIDC issuers URLs.
   The default value is ``''``.

.. confval:: OIDC_AUDIENCE

   If set the IM will check that the string defined here appear in the "aud" claim of the OpenID access token
   The default value is ``''``.

.. confval:: OIDC_CLIENT_ID

   OIDC client ID of the IM service. Only needed in case of setting OIDC_SCOPES.
   The default value is ``''``.

.. confval:: OIDC_CLIENT_SECRET

   OIDC secret of the IM service. Only needed in case of setting OIDC_SCOPES.
   The default value is ``''``.

.. confval:: OIDC_SCOPES

   List of scopes that must appear in the token request to access the IM service.
   Client ID and Secret must be provided to make it work.
   The default value is ``''``.

.. confval:: OIDC_GROUPS

   List of OIDC groups supported.
   It must be a coma separated string of group names.
   (see the `AARC guidelines for group names <https://aarc-community.org/guidelines/AARC-G069/>`_).
   The default value is ``''``.

.. confval:: FORCE_OIDC_AUTH

   If ``True`` the IM will force the users to pass a valid OIDC token.
   The default value is ``False``.

NETWORK OPTIONS
^^^^^^^^^^^^^^^

.. confval:: PRIVATE_NET_MASKS 

   List of networks assumed as private. The IM use it to distinguish private from public networks.
   IM considers IPs not in these subnets as Public IPs.
   It must be a coma separated string of the network definitions (using CIDR) (without spaces).
   The default value is ``'10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,192.0.0.0/24,169.254.0.0/16,100.64.0.0/10,198.18.0.0/15'``.
   
HA MODE OPTIONS
^^^^^^^^^^^^^^^

.. confval:: INF_CACHE_TIME

   Time (in seconds) the IM service will maintain the information of an infrastructure
   in memory. Only used in case of IM in HA mode. This value has to be set to a similar value set in the ``expire`` value
   in the ``stick-table`` in the HAProxy configuration.

OpenNebula connector Options
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The configuration values under the ``OpenNebula`` section:

.. confval:: TEMPLATE_CONTEXT 

   Text to add to the CONTEXT section of the ONE template (except SSH_PUBLIC_KEY)
   The default value is ``''``.

.. confval:: TEMPLATE_OTHER 

   Text to add to the ONE Template different to NAME, CPU, VCPU, MEMORY, OS, DISK and CONTEXT
   The default value is ``GRAPHICS = [type="vnc",listen="0.0.0.0"]``. 


.. _logging:

Logging Configuration
^^^^^^^^^^^^^^^^^^^^^

IM uses Python logging library (see the `documentation <https://docs.python.org/2/howto/logging.html>`_).
You have two options to configure it: use the configuration variables at the IM configuration file or
use the file ``/etc/im/logging.conf``.

The configuration variables are the following:

.. confval:: LOG_LEVEL 

   Set the level of the log messages: DEBUG, INFO, WARNING, ERROR, CRITICAL
   The default value is ``'INFO'``.

.. confval:: LOG_FILE

   Set the destination file of the log messages.
   The default value is ``'/var/log/im/im.log'``.

.. confval:: LOG_FILE_MAX_SIZE 

   Set the maximum file size of the log file. It will be rotated when size exceed this size,
   with a default depth of 3 files.
   The default value is ``'10485760'``.

If you need to specify more advanced details of the logging configuration you have to use the file
``/etc/im/logging.conf``. For example to set a syslogd server as the destination of the log messages::

	[handler_fileHandler]
	class=logging.handlers.SysLogHandler
	level=INFO
	formatter=simpleFormatter
	args=(('<syslog_ip>', 514),)
	[formatter_simpleFormatter]
	format=%(asctime)s - %(hostname)s - %(name)s - %(levelname)s - %(message)s
	datefmt=

.. _vault-creds:

Vault Configuration
^^^^^^^^^^^^^^^^^^^^

From version 1.10.7 the IM service supports reading authorization data from a Vault server.
These values are used by the REST API enabling to use ``Bearer`` authentication header and
get the all the credential values from the configured Vault server.

.. confval:: VAULT_URL 

   URL to the Vault server API.
   The default value is ``''``.

.. confval:: VAULT_PATH 

   Configured path of the KV (ver 1) secret.
   This field has one special substitution value: ``#USER_SUB#`` that is replaced by the user
   ID obtained from the OpenID token provided.
   The default value is ``vault_entity_id``.

.. confval:: VAULT_MOUNT_POINT

   Configured mount point of the KV (ver 1) secret.
   The default value is ``'credentials/'``.

.. confval:: VAULT_ROLE 
   
   Configured role with the correct permissions to read the credentials secret store.
   There is no default value, so the default value configured in the JWT authentication
   method will be used.

Vault server must configured with the JWT authentication method enabled, setting
you OIDC issuer, e.g. using the EGI Checkin issuer, and setting ``im`` as the default
role::

   vault write auth/jwt/config \
      oidc_discovery_url="https://aai.egi.eu/oidc/" \
      default_role="im"

A KV (v1) secret store must be enabled setting the desired path. In this example the 
default vaule ``credentials`` is used::

   vault secrets enable -version=1 -path=credentials kv

Also a policy must be created to enable the users to manage only their own credentials::

   vault policy write manage-imcreds - <<EOF
   path "credentials/{{identity.entity.id}}" {
   capabilities = [ "create", "read", "update", "delete", "list" ]
   }
   EOF

And finally the ``im`` role to assign the policy to the JWT users::

   vault write auth/jwt/role/im - <<EOF
   {
   "role_type": "jwt",
   "policies": ["manage-imcreds"],
   "token_explicit_max_ttl": 60,
   "user_claim": "sub",
   "bound_claims": {
      "sub": "*"
   },
   "bound_claims_type": "glob"
   }
   EOF

These set of commands are only an example of how to configure the Vault server to be
accesed by the IM. Read `Vault documentation <https://www.vaultproject.io/docs>`_ for more details.

The authentication data must be stored using one item per line in the :ref:`auth-file`, setting as
key value the ``id`` of the item and all the auth line (in JSON format) as the value, e.g. An auth
line like that::

   id = one; type = OpenNebula; host = oneserver:2633; username = user; password = pass

Must be stored in the vault KV secrect, setting ``one`` as key and this content as value::

   {"id": "one", "type": "OpenNebula", "host": "oneserver:2633", "username": "user", "password": "pass"}

In all the auth lines where an access token is needed it must not be set and the IM will replace it with
then access token used to authenticate with the IM itself.

Virtual Machine Tags
^^^^^^^^^^^^^^^^^^^^^

Name of the tags that IM will add in the VMs with username, infrastructure ID, URL of the IM service,
and IM name comment or leave empty not to set them

.. confval:: VM_TAG_USERNAME

   Name of the tag to set the IM username as tag in the IM created VMs.

.. confval:: VM_TAG_INF_ID

   Name of the tag to set the IM infrastructure ID as tag in the IM created VMs.

.. confval:: VM_TAG_IM_URL

   Name of the tag to set the IM URL as tag in the IM created VMs.

.. confval:: VM_TAG_IM

   Name of the tag to set the IM string (``'es.grycap.upv.im'```) as tag in the IM created VMs.

OAI-PMH Support and restrict templates
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Variables to configure the OAI-PMH repository and restrict the templates that will be deployed
by the IM service.

.. confval:: OAIPMH_REPO_BASE_IDENTIFIER_URL

   If this value is set the IM service will restrict the templates that can be deployed to the ones
   available in the repository with the base URL set in this value. Currently it must be a Github
   repository URL. To activate the OAI-PMH support this value must be set.

.. confval:: OAIPMH_REPO_NAME

   Tne name of the OAI-PMH repository. To activate the OAI-PMH support this value must be set.

.. confval:: OAIPMH_REPO_DESCRIPTION

   The description of the OAI-PMH repository. To activate the OAI-PMH support this value must be set.

.. confval:: OAIPMH_REPO_ADMIN_EMAIL

   The email of the repository administrator.

Admin user support
^^^^^^^^^^^^^^^^^^

Configure IM admin users. It will be able to manage all the infrastructures in the service.
But it should also provide correct credentials to access cloud providers, if not cloud resources
will not be able to be managed.

.. confval:: ADMIN_USER

   Configure a set of admin users with user and password::

      ADMIN_USER = [{"username": "user", "password": "pass"},
                    {"username": "user2", "password": "pass2"}]

   In case of OIDC users, use this format::

      ADMIN_USER = [{"username": "__OPENID__username", "password": "https://some_issuer.com/user_sub", "token": ""},
                    {"username": "__OPENID__username2", "password": "https://some_issuer.com/user_sub2", "token": ""}]]

.. confval:: OIDC_ADMIN_GROUPS

   To set as admin all the users of an OIDC group::

      OIDC_ADMIN_GROUPS = [{"issuer": "https://some_issuer.com/", "group": "group_name"}]

.. _options-ha:

IM in high availability mode
============================

From version 1.5.0 the IM service can be launched in high availability (HA) mode using a set of IM instances
behind a `HAProxy <http://www.haproxy.org/>`_ load balancer. Currently only the REST API can be used in HA mode.
It is a experimental issue currently it is not intended to be used in a production installation.

This is an example of the HAProxy configuration file::

    global
        tune.bufsize 131072
    defaults
        timeout connect 600s
        timeout client 600s
        timeout server 600s

	frontend http-frontend
	    mode http
	    bind *:8800
	    default_backend imbackend
	
	backend imbackend
	    mode http
	    balance roundrobin
	    option httpchk GET /version
	    stick-table type string len 32 size 30k expire 60m
	    stick store-response hdr(InfID)
	    acl inf_id path -m beg /infrastructures/
	    stick on path,field(3,/) if inf_id

        server im-8801 10.0.0.1:8801 check
        server im-8802 10.0.0.1:8802 check
        ...

See more details of HAProxy configuration at `HAProxy Documentation <https://cbonte.github.io/haproxy-dconv/>`_.

Also the ``INF_CACHE_TIME`` variable of the IM config file must be set to a time in seconds lower or equal to the time
set in the stick-table ``expire`` value (in the example 60m). So for this example INF_CACHE_TIME must be set to less
than or equals to 3600.

Purgue IM DB
============

The IM service does not remove deleted infrastructures from DB for provenance purposes.
In case that you want to remove old deleted infrastructures from the DB to reduce its size
you can use the ``delete_old_infs`` script. It will delete from DB all the infrastructures
created before a specified date::

  python delete_old_infs.py <date>

Add new Cloud Connectors
========================

To add a new Cloud Connector you have to create a new Python file in the directory
``IM/connectors/`` of the IM source code. The file must have a class with the same
name as the file that inherits from the `CloudConnector <https://github.com/grycap/im/blob/master/IM/connectors/CloudConnector.py>`_
class. This class must implement all the abstract methods of the ``CloudConnector``
class. The new connector must implement at least the following methods:

- ``concrete_system``: Return a list of compatible systems with the cloud provider.
- ``updateVMInfo``: Updates the information of a VM.
- ``launch``: Launch a set of VMs to the Cloud provider.
- ``finalize``: Terminates a VM and all the associated resources.

To have full support you have to implement the following methods:

- ``alterVM``: Modifies/resizes the features of a VM.
- ``start``: Starts a (previously stopped) VM.
- ``stop``: Stops (but not finalizes) a VM.
- ``reboot``: Reboots a VM.
- ``list_images``: Get a list of images on the cloud provider using IM URI format.
- ``get_quotas``: Get the number of used and available resources in the cloud provider

The new connector must be added to the ``__all__`` variable in ``__init__.py`` file 
of the ``IM/connectors/``

Cloud Providers Configuration
==============================

The IM tries to select the most appropriate resources to launch the VMs. But sometimes it may select
the wrong resources. To avoid this situation you can set some tags in the cloud provider configuration
to help the IM to select the correct resources.

OpenStack
^^^^^^^^^

In case that there are more that one private or public network in the OpenStack cloud provider
to enable the IM to select the correct network to launch the VMs you can set a ``default`` tag
in the network that you want to use as the default network. The IM will use this network to launch
the VMs if the network is not specified in the RADL file (from version 1.17.0).

The IM expects as default network configuration having one or more private networks and one or more
floating IP networks. The private networks are used to launch the VMs and the floating IP networks
are used to assign a public IP to the VMs. The IM will use the first private network found as the
default network to launch the VMs and the first floating IP network found as the default network to
assign the public IP to the VMs.

In case that your site does not have this configuration and it does not uses floating IPs, the IM
by default will avoid to attach two NICs to the VMs. So the VMs will have only one NIC attached to
either to the public or private network. To enable the IM to attach two NICs to the VMs
you have to set a tag  ``enable_two_nics`` to some of the networks of the site. In this case the IM
will attach two NICs to the VMs, one to the private network and the other to the public network, if
it is required by the RADL file (from version 1.18.0).

OpenNebula
^^^^^^^^^^

Similar to OpenStack, in case that there are more that one private or public network in the OpenNebula cloud provider
to enable the IM to select the correct network to launch the VMs you can set a ``DEFAULT`` attribute in the network
definition in the OpenNebula template. The IM will use this network to launch the VMs if the network is not specified
(from version 1.18.0).