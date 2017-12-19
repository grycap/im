IM Command-line Interface (CLI)
===============================

The :program:`im_client` is a CLI client that uses XML-RPC API of IM Server.

Prerequisites
-------------

The :program:`im_client` needs at least Python 2.4 to run.

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

   ``reconfigure radl_file infId vm_list``
      Reconfigure the infrastructure with ID ``infId`` and also update the
      configuration data specified in the optional ``radl_file``. The last  ``vm_list`` 
      parameter is optional and is a list integers specifying the IDs of the VMs to reconfigure.
      If not specified all the VMs will be reconfigured. 
      
   ``startvm infId vmId``
      Resume the specified virtual machine ``vmId`` associated to the infrastructure with ID
      ``infId``, stopped previously by the operation ``stop``.

   ``stopvm infId vmId``
      Stop (but not remove) the specified virtual machine ``vmId`` associated to the infrastructure with ID
      infrastructure with ID ``infId``.
      
   ``sshvm infId vmId [show_only]``
      Connect with SSH with the specified virtual machine ``vmId`` associated to the infrastructure with ID
      infrastructure with ID ``infId``. The ``show_only`` parameter is optional and is a flag to specify if ssh
      command will only be shown in stdout instead of executed.

   ``export infId delete``
      Export the data of the infrastructure with ID ``infId``. The ``delete`` parameter is optional
      and is a flag to specify if the infrastructure will be deleted from the IM service (the VMs are not
      deleted).

   ``import json_file``  
      Import the data of an infrastructure previously exported with the previous function.
      The ``json_file`` is a file with the data generated with the  ``export`` function.

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

Values can contain "=", and "\\n" is replaced by carriage return. 
You can also delimit the values using single or double quotes (e.g. if a semicolon or some quote character
 appear in a value)(from version 1.6.6)::

   id = id_value ; type = value_of_type ; username = value_of_username ; password = 'some;"password'
   id = id_value ; type = value_of_type ; username = value_of_username ; password = "some;'password"

The available keys are:

* ``type`` indicates the service that refers the credential. The services
  supported are ``InfrastructureManager``, ``VMRC``, ``OpenNebula``, ``EC2``,, ``FogBow``, 
  ``OpenStack``, ``OCCI``, ``LibCloud``, ``Docker``, ``GCE``, ``Azure``, ``AzureClassic`` and ``Kubernetes``.

* ``username`` indicates the user name associated to the credential. In EC2
  it refers to the *Access Key ID*. In GCE it refers to *Service Account’s Email Address*. 

* ``password`` indicates the password associated to the credential. In EC2
  it refers to the *Secret Access Key*. In GCE it refers to *Service  Private Key*
  (either in JSON or PKCS12 formats). See how to get it and how to extract the private key file from
  `here info <https://cloud.google.com/storage/docs/authentication#service_accounts>`_).

* ``tenant`` indicates the tenant associated to the credential.
  This field is only used in the OpenStack plugin.

* ``host`` indicates the address of the access point to the cloud provider.
  This field is not used in IM, GCE, Azure, and EC2 credentials.
  
* ``proxy`` indicates the content of the proxy file associated to the credential.
  To refer to a file you must use the function "file(/tmp/proxyfile.pem)" as shown in the example.
  This field is used in the OCCI and OpenStack plugins. 
  
* ``project`` indicates the project name associated to the credential.
  This field is only used in the GCE or OCCI (from version 1.6.3) plugins.
  
* ``public_key`` indicates the content of the public key file associated to the credential.
  To refer to a file you must use the function "file(cert.pem)" as shown in the example.
  This field is used in the Azure Classic and Docker plugins. For Azure Classic see how to get it
  `here <https://msdn.microsoft.com/en-us/library/azure/gg551722.aspx>`_

* ``private_key`` indicates the content of the private key file associated to the credential.
  To refer to a file you must use the function "file(key.pem)" as shown in the example.
  This field is used in the Azure Classic and Docker plugins. For Azure Classic see how to get it
  `here <https://msdn.microsoft.com/en-us/library/azure/gg551722.aspx>`_

* ``id`` associates an identifier to the credential. The identifier should be
  used as the label in the *deploy* section in the RADL.

* ``subscription_id`` indicates the subscription_id name associated to the credential.
  This field is only used in the Azure and Azure Classic plugins. To create a user to use the Azure (ARM)
  plugin check the documentation of the Azure python SDK:
  `here <https://azure-sdk-for-python.readthedocs.io/en/latest/quickstart_authentication.html#using-ad-user-password>`_

* ``token`` indicates the OpenID token associated to the credential. This field is used in the OCCI plugin (from version 1.6.2). 

OpenStack additional fields
^^^^^^^^^^^^^^^^^^^^^^^^^^^

OpenStack has a set of additional fields to access a cloud site:

* ``domain`` the domain name associated to the credential. The default value is: ``Default``.

* ``auth_version`` the auth version used to connect with the Keystone server.
  The possible values are: ``2.0_password``, ``2.0_voms``, ``3.x_password`` or ``3.x_oidc_access_token``.
  The default value is ``2.0_password``.

* ``base_url`` base URL to the OpenStack API endpoint. By default, the connector obtains API endpoint URL from the 
  server catalog, but if this argument is provided, this step is skipped and the provided value is used directly.
  The value is: http://cloud_server.com:8774/v2/<tenant_id>.
  
* ``service_region`` the region of the cloud site (case sensitive). It is used to obtain the API 
  endpoint URL. The default value is: ``RegionOne``.

* ``service_name`` the service name used to obtain the API endpoint URL. The default value is: ``Compute``.
  From version 1.5.3 a special name ``None`` can be used to use a ``Null\None`` value as the service name
  as it is used for example in the Open Telekom Cloud. 

* ``auth_token`` token which is used for authentication. If this argument is provided, normal authentication 
  flow is skipped and the OpenStack API endpoint is directly hit with the provided token. Normal authentication 
  flow involves hitting the auth service (Keystone) with the provided username and password and requesting an
  authentication token.

Open Telekom Cloud
++++++++++++++++++

The Open Telekom Cloud (OTC) is the cloud provided by T-Systems. It is based on OpenStack and it can be accessed
using the OpenStack IM connector using an authorization line similar to the following example:

id = otc; type = OpenStack; host = https://iam.eu-de.otc.t-systems.com:443 ; username = user; password = pass; tenant = tenant; domain = domain; auth_version = 3.x_password; service_name = None; service_region = eu-de

You can get the username, password, tenant and domain values from the ``My Credentials`` section of your OTC access. 

Examples
^^^^^^^^

An example of the auth file::

   # OpenNebula site
   id = one; type = OpenNebula; host = osenserver:2633; username = user; password = pass
   # OpenStack site using standard user, password, tenant format
   id = ost; type = OpenStack; host = https://ostserver:5000; username = user; password = pass; tenant = tenant
   # OpenStack site using VOMS proxy authentication
   id = ostvoms; type = OpenStack; proxy = file(/tmp/proxy.pem); host = https://keystone:5000; tenant = tname
   # IM auth data 
   id = im; type = InfrastructureManager; username = user; password = pass
   # VMRC auth data
   id = vmrc; type = VMRC; host = http://server:8080/vmrc; username = user; password = pass
   # EC2 auth data
   id = ec2; type = EC2; username = ACCESS_KEY; password = SECRET_KEY
   # Google compute auth data
   id = gce; type = GCE; username = username.apps.googleusercontent.com; password = pass; project = projectname
   # Docker site with certificates
   id = docker; type = Docker; host = http://host:2375; public_key = file(/tmp/cert.pem); private_key = file(/tmp/key.pem)
   # Docker site without SSL security
   id = docker; type = Docker; host = http://host:2375
   # OCCI VOMS site auth data
   id = occi; type = OCCI; proxy = file(/tmp/proxy.pem); host = https://server.com:11443
   # OCCI OIDC site auth data
   id = occi; type = OCCI; token = token; host = https://server.com:11443
   # Azure (RM) site auth data
   id = azure; type = Azure; subscription_id = subscription-id; username = user@domain.com; password = pass
   # Kubernetes site auth data
   id = kub; type = Kubernetes; host = http://server:8080; username = user; password = pass
   # FogBow auth data
   id = fog; type = FogBow; host = http://server:8182; proxy = file(/tmp/proxy.pem)
   # Azure Classic auth data
   id = azurecla; type = AzureClassic; subscription_id = subscription_id; public_key = file(/tmp/cert.pem); private_key = file(/tmp/key.pem)
   

IM Server does not store the credentials used in the creation of
infrastructures. Then the user has to provide them in every call of
:program:`im_client`.

INDIGO IAM specific parameters
...............................

To use the INDIGO IAM to authenticate with a Keystone server properly configured following this 
`guidelines <https://indigo-dc.gitbooks.io/openid-keystone/content/indigo-configuration.html>`_, some of 
the previous parameters has a diferent meaning:

* username: Specifies the identity provider. It must be: ``indigo-dc``.
* tenant: Specifies the authentication protocol to use. It must be: ``oidc``.
* password: Specifies the INDIGO IAM token.

So the auth line will be like that::

   id = ost; type = OpenStack; host = https://ostserver:5000; username = indigo-dc; tenant = oidc; password = iam_token_value; auth_version = 3.x_oidc_access_token

