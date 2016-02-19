IM Command-line Interface (CLI)
===============================

The :program:`im_client` is a CLI client that uses XML-RPC API of IM Server.

Prerequisites
-------------

The :program:`im_client` needs at least Python 2.4 to run. If the XML-RPC API
is secured with SSL certificates (see :confval:`XMLRCP_SSL`),
`Spring Python <http://springpython.webfactional.com/>`_ should be installed.
The Debian package is named ``python-springpython``.

Invocation
----------

The :program:`im_client` is called like this::

   $ im_client.py [-u|--xmlrpc-url url] [-a|--auth_file filename] operation op_parameters

.. program:: im_client

.. option:: -u|--xmlrpc-url url

   URL to the XML-RPC service.
   The default value is ``http://localhost:8888``.

   .. todo::

      Change the default value of the port to XMLRCP_PORT.

.. option:: -a|--auth_file filename

   Path to the authorization file, see :ref:`auth-file`.
   This option is compulsory.

.. option:: operation

   ``list``
      List the infrastructure IDs created by the user.

   ``create radlfile``
      Create an infrastructure using RADL specified in the file with path
      ``radlfile``.

   ``destroy infId``
      Destroy the infrastructure with ID ``infId``.

   ``getinfo infId``
      Show the information about all the virtual machines associated to the
      infrastructure with ID ``infId``.

   ``getcontmsg infId``
      Show the contextualization message of the infrastructure with ID ``id``.
      
   ``getstate infId``
      Show the state of the infrastructure with ID ``id``.

   ``getvminfo infId vmId``
      Show the information associated to the virtual machine with ID ``vmId``
      associated to the infrastructure with ID ``infId``.

   ``getvmcontmsg infId vmId``
      Show the contextualization message of the virtual machine with ID ``vmId``
      associated to the infrastructure with ID ``infId``.

   ``addresource infId radlfile ctxt_flag``
      Add to infrastructure with ID ``infId`` the resources specifies in the
      RADL file with path ``radlfile``. The ``ctxt_flag`` parameter is optional
      and is a flag to specify if the contextualization step will be launched
      just after the VM addition. If not specified the contextualization step
      will be launched. 

   ``removeresource infId vmId ctxt_flag``
      Destroy the virtual machine with ID ``vmId`` in the infrastructure with
      ID ``infId``. The ``ctxt_flag`` parameter is optional
      and is a flag to specify if the contextualization step will be launched
      just after the VM addition. If not specified the contextualization step
      will be launched.

   ``start infId``
      Resume all the virtual machines associated to the infrastructure with ID
      ``infId``, stopped previously by the operation ``stop``.

   ``stop infId``
      Stop (but not remove) the virtual machines associated to the
      infrastructure with ID ``infId``.

   ``alter infId vmId radlfile``
      Modify the specification of the virtual machine with ID ``vmId``
      associated to the infrastructure with ID ``vmId``, using the RADL
      specification in file with path ``radlfile``.

   ``reconfigure infId vm_list``
      Reconfigure the infrastructure with ID ``infId`` and also update the
      configuration data. The last  ``vm_list`` parameter is optional
      and is a list integers specifying the IDs of the VMs to reconfigure.
      If not specified all the VMs will be reconfigured. 
      
   ``startvm infId vmId``
      Resume the specified virtual machine ``vmId`` associated to the infrastructure with ID
      ``infId``, stopped previously by the operation ``stop``.

   ``stopvm infId vmId``
      Stop (but not remove) the specified virtual machine ``vmId`` associated to the infrastructure with ID
      infrastructure with ID ``infId``.
      
   ``sshvm infId vmId``
      Connect with SSH with the specified virtual machine ``vmId`` associated to the infrastructure with ID
      infrastructure with ID ``infId``.

.. _auth-file:

Authorization File
------------------

The authorization file stores in plain text the credentials to access the
cloud providers, the IM service and the VMRC service. Each line of the file
is composed by pairs of key and value separated by semicolon, and refers to a
single credential. The key and value should be separated by " = ", that is
**an equals sign preceded and followed by one white space at least**, like
this::

   id = id_value ; type = value_of_type ; username = value_of_username ; password = value_of_password 

Values can contain "=", and "\\n" is replaced by carriage return. The available
keys are:

* ``type`` indicates the service that refers the credential. The services
  supported are ``InfrastructureManager``, ``VMRC``, ``OpenNebula``, ``EC2``,, ``FogBow``, 
  ``OpenStack``, ``OCCI``, ``LibCloud``, ``Docker``, ``GCE``, ``Azure``, ``Kubernetes`` and ``LibVirt``.

* ``username`` indicates the user name associated to the credential. In EC2
  it refers to the *Access Key ID*. In Azure it refers to the user 
  Subscription ID. In GCE it refers to *Service Account’s Email Address*. 

* ``password`` indicates the password associated to the credential. In EC2
  it refers to the *Secret Access Key*. In GCE it refers to *Service 
  Private Key*. See how to get it and how to extract the private key file from
  `here info <https://cloud.google.com/storage/docs/authentication#service_accounts>`_).

* ``tenant`` indicates the tenant associated to the credential.
  This field is only used in the OpenStack plugin.

* ``host`` indicates the address of the access point to the cloud provider.
  This field is not used in IM and EC2 credentials.
  
* ``proxy`` indicates the content of the proxy file associated to the credential.
  To refer to a file you must use the function "file(/tmp/proxyfile.pem)" as shown in the example.
  This field is only used in the OCCI plugin.
  
* ``project`` indicates the project name associated to the credential.
  This field is only used in the GCE plugin.
  
* ``public_key`` indicates the content of the public key file associated to the credential.
  To refer to a file you must use the function "file(cert.pem)" as shown in the example.
  This field is only used in the Azure plugin. See how to get it
  `here <https://msdn.microsoft.com/en-us/library/azure/gg551722.aspx>`_

* ``private_key`` indicates the content of the private key file associated to the credential.
  To refer to a file you must use the function "file(key.pem)" as shown in the example.
  This field is only used in the Azure plugin. See how to get it
  `here <https://msdn.microsoft.com/en-us/library/azure/gg551722.aspx>`_

* ``id`` associates an identifier to the credential. The identifier should be
  used as the label in the *deploy* section in the RADL.
  
OpenStack addicional fields
^^^^^^^^^^^^^^^^^^^^^^^^^^^

OpenStack has a set of addicional fields to access a cloud site:

* ``auth_version`` the auth version used to connect with the Keystone server.
  The possible values are: ``2.0_password`` or ``3.X_password``. The default value is ``2.0_password``.

* ``base_url`` base URL to the OpenStack API endpoint. By default, the connector obtains API endpoint URL from the 
  server catalog, but if this argument is provided, this step is skipped and the provided value is used directly.
  The value is: http://cloud_server.com:8774/v2/<tenant_id>.
  
* ``service_region`` the region of the cloud site (case sensitive). It is used to obtain  the API 
  endpoint URL. The default value is: ``RegionOne``.

* ``service_name`` the service name used to obtain the API endpoint URL. The default value is: ``Compute``.

* ``auth_token`` token which is used for authentication. If this argument is provided, normal authentication 
  flow is skipped and the OpenStack API endpoint is directly hit with the provided token. Normal authentication 
  flow involves hitting the auth service (Keystone) with the provided username and password and requesting an
  authentication token.

An example of the auth file::

   id = one; type = OpenNebula; host = osenserver:2633; username = user; password = pass
   id = ost; type = OpenStack; host = https://ostserver:5000; username = user; password = pass; tenant = tenant
   id = im; type = InfrastructureManager; username = user; password = pass
   id = vmrc; type = VMRC; host = http://server:8080/vmrc; username = user; password = pass
   id = ec2; type = EC2; username = ACCESS_KEY; password = SECRET_KEY
   id = gce; type = GCE; username = username.apps.googleusercontent.com; password = pass; project = projectname
   id = docker; type = Docker; host = http://host:2375
   id = occi; type = OCCI; proxy = file(/tmp/proxy.pem); host = https://fc-one.i3m.upv.es:11443
   id = azure; type = Azure; username = subscription-id; public_key = file(cert.pem); private_key = file(key.pem)
   id = kub; type = Kubernetes; host = http://server:8080; username = user; password = pass
   

IM Server does not store the credentials used in the creation of
infrastructures. Then the user has to provide them in every call of
:program:`im_client`.
