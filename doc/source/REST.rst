IM REST API
===========

Optionally, IM Service can be accessed through a REST(ful) API. The port number
and the security settings are controlled by the options listed in
:ref:`options-rest`.

In the following link you can follow the **IM REST API in Swaggerhub**: 
`Swagger API <https://app.swaggerhub.com/apis-docs/grycap/InfrastructureManager/>`_.

Every HTTP request must be accompanied by the header ``AUTHORIZATION`` with
the content of the :ref:`auth-file`, but putting all the elements in one line
using "\\n" as separator. If the content cannot be parsed successfully, or the user and
password are not valid, it is returned the HTTP error code 401. In case that Vault
support has been configured (:ref:`vault-creds`) also a Bearer authorization header
is supported, using the same access token to authenticate with the Vault server.

In case of using EGI Check-in authentication, see :ref:`egi-auth` to know how to get
a valid token.

Next tables summaries the resources and the HTTP methods available.

+-------------+------------------------------------+------------------------------------+-------------------------------------------+
| HTTP method | /infrastructures                   | /infrastructures/<infId>           | /infrastructures/<infId>/vms/<vmId>       |
+=============+====================================+====================================+===========================================+
| **GET**     | | **List** the infrastructure IDs. | | **List** the virtual machines    | | **Get** information associated to the   |
|             |                                    | | in the infrastructure ``infId``  | | virtual machine ``vmId`` in ``infId``.  |
+-------------+------------------------------------+------------------------------------+-------------------------------------------+
| **POST**    | | **Create** a new infrastructure  | | **Add or Remove** virtual        | | **Modify** the virtual machine based on |
|             | | based on the RADL or TOSCA       | | machines based on the RADL       | | the RADL or TOSCA posted.               |
|             | | posted.                          | | or TOSCA posted.                 |                                           |
+-------------+------------------------------------+------------------------------------+-------------------------------------------+
| **PUT**     | | **Import** an infrastructure     |                                    |                                           |
|             | | from another IM instance         |                                    |                                           |
+-------------+------------------------------------+------------------------------------+-------------------------------------------+
| **DELETE**  |                                    | | **Undeploy** all the virtual     | | **Undeploy** the virtual machine.       |
|             |                                    | | machines in the infrastructure.  |                                           |
+-------------+------------------------------------+------------------------------------+-------------------------------------------+
 
+-------------+--------------------------------+---------------------------------+---------------------------------------+
| HTTP method | /infrastructures/<infId>/stop  | /infrastructures/<infId>/start  | /infrastructures/<infId>/reconfigure  |
+=============+================================+=================================+=======================================+
| **PUT**     | | **Stop** the infrastructure. | | **Start** the infrastructure. | | **Reconfigure** the infrastructure. |
+-------------+--------------------------------+---------------------------------+---------------------------------------+

+-------------+------------------------------------------------------+------------------------------------------------------+
| HTTP method | /infrastructures/<infId>/vms/<vmId>/<property_name>  | /infrastructures/<infId>/<property_name>             |
+=============+======================================================+======================================================+
| **GET**     | | **Get** the specified property ``property_name``   | | **Get** the specified property ``property_name``   |
|             | | associated to the machine ``vmId`` in ``infId``.   | | associated to the infrastructure ``infId``.        |
|             | | It has one special property: ``contmsg``.          | | It has six properties: ``contmsg``, ``radl``,      |
|             | |                                                    | | ``state``, ``outputs``, ``tosca``, ``data`` and    |
|             | |                                                    | | ``authorization``.                                 |
+-------------+------------------------------------------------------+------------------------------------------------------+
| **POST**    |                                                      | | **Modify** the specified property ``property_name``|
|             |                                                      | | associated to the infrastructure ``infId``.        |
|             |                                                      | | only ``authorization`` property is valid.          |
+-------------+------------------------------------------------------+------------------------------------------------------+


+-------------+-----------------------------------------------+------------------------------------------------+------------------------------------------------+
| HTTP method | /infrastructures/<infId>/vms/<vmId>/stop      | /infrastructures/<infId>/vms/<vmId>/start      | /infrastructures/<infId>/vms/<vmId>/reboot     |
+=============+===============================================+================================================+================================================+
| **PUT**     | | **Stop** the machine ``vmId`` in ``infId``. | | **Start** the machine ``vmId`` in ``infId``. | | **Reboot** the machine ``vmId`` in ``infId``.|
+-------------+-----------------------------------------------+------------------------------------------------+------------------------------------------------+

+-------------+--------------------------------------------------------------+
| HTTP method | /infrastructures/<infId>/vms/<vmId>/disks/<diskNum>/snapshot |
+=============+==============================================================+
| **PUT**     | | **Create** an snapshot of the disk ``diskNum`` of the      |
|             | | machine ``vmId`` in ``infId``.                             |
+-------------+--------------------------------------------------------------+

+-------------+---------------------------------------+---------------------------------------------+
| HTTP method | /clouds/<cloudId>/images                | /clouds/<cloudId>/quotas                  | 
+=============+=======================================+=============================================+
| **GET**     | | **List** the available images       | | **Get** the used and available resources  |
|             | | in the ``cloudId`` provider.        | | in the ``cloudId`` provider.              |
+-------------+---------------------------------------+---------------------------------------------+

+-------------+----------------------------------------+
| HTTP method | /oai                                   |
+=============+========================================+
| **GET**     | | **OAI-PMH** REST API about available |
|             | | TOSCA templates.                     |
+-------------+----------------------------------------+

The error message returned by the service will depend on the ``Accept`` header of the request:

* text/plain: (default option).
* application/json: The request has a "Accept" header with value "application/json". In this case the format will be::

    {
      "message": "Error message text",
      "code" : 400
     }
     
* text/html: The request has a "Accept" with value to "text/html". 

GET ``http://imserver.com/infrastructures``
   :Response Content-type: text/uri-list or application/json
   :input fields: ``filter`` (optional)
   :ok response: 200 OK
   :fail response: 401, 400

   Return a list of URIs referencing the infrastructures associated to the IM
   user. In case of using a filter it will be used as a regular expression to
   search in the RADL or TOSCA used to create the infrastructure.
   The result is JSON format has the following format::

    {
      "uri-list": [
         { "uri" : "http://server.com:8800/infrastructures/inf_id1" },
         { "uri" : "http://server.com:8800/infrastructures/inf_id2" }
       ] 
    }

POST ``http://imserver.com/infrastructures``
   :body: ``RADL or TOSCA document``
   :body Content-type: text/plain, application/json or text/yaml
   :input fields: ``async`` (optional), ``dry_run`` (optional)
   :Response Content-type: text/uri-list
   :ok response: 200 OK
   :fail response: 401, 400, 415

   Create and configure an infrastructure with the requirements specified in
   the RADL (in plain RADL or in JSON formats) or TOSCA document of the body contents.
   
   The ``async`` parameter is optional and is a flag to specify if the call will not wait the VMs
   to be created. Acceptable values: yes, no, true, false, 1 or 0. If not specified the flag is set to False.
   
   If success, it is returned the URI of the new infrastructure.  
   The result is JSON format has the following format::

    {
      "uri" : "http://server.com:8800/infrastructures/inf_id
    }

   The ``dry_run`` parameter is optional and is a flag to specify if the call will not create the VMs
   and will only return the ammount of resources needed to deploy the infrastructure.
   Acceptable values: yes, no, true, false, 1 or 0. If not specified the flag is set to False.
   In this case no infrastructure ID is returned, only the ammount of resources needed to deploy
   the infrastructure with the following format (memory unit MB, disk and storage unit GB)::

    {
       "ost1": {
          "cloudType": "OpenStack",
          "cloudEndpoint": "http://openstack.example.com:5000",

          "compute": [
                {
                   "cpuCores": 2,
                   "memoryInMegabytes": 4096,
                   "diskSizeInGigabytes": 20,
                   "publicIP": 1,
                   "GPU": 1
                },
                {
                   "cpuCores": 1,
                   "memoryInMegabytes": 2048,
                   "diskSizeInGigabytes": 10
                }
          ],
          "storage": [
                   {"sizeInGigabytes": 100, "type": "ceph"},
                   {"sizeInGigabytes": 100}
          ]
       }
    }

PUT ``http://imserver.com/infrastructures``
   :body: ``JSON data of the infrastructure``
   :body Content-type: application/json
   :Response Content-type: text/uri-list
   :ok response: 200 OK
   :fail response: 401, 400, 415

   Take control of the infrastructure serialized in in the body and return
   the ID associated in the server. (See GET /infrastructures/<infId>/data).
   
   If success, it is returned the URI of the new infrastructure.  
   The result is JSON format has the following format::

    {
      "uri" : "http://server.com:8800/infrastructures/inf_id
    }

GET ``http://imserver.com/infrastructures/<infId>``
   :Response Content-type: text/uri-list or application/json
   :ok response: 200 OK
   :fail response: 401, 403, 404, 400

   Return a list of URIs referencing the virtual machines associated to the infrastructure with ID ``infId``.
   The result is JSON format has the following format::

    {
      "uri-list": [
         { "uri" : "http://server.com:8800/infrastructures/inf_id/vms/0" },
         { "uri" : "http://server.com:8800/infrastructures/inf_id/vms/1" }
       ] 
    }
    
GET ``http://imserver.com/infrastructures/<infId>/<property_name>``
   :Response Content-type: text/plain or application/json
   :ok response: 200 OK
   :input fields: ``headeronly`` (optional)
   :fail response: 401, 404, 400, 403

   Return property ``property_name`` associated to the infrastructure with ID ``infId``. It has the following properties::
      :``outputs``: in case of TOSCA documents it will return a JSON object with the outputs of the TOSCA document. 
      :``contmsg``: a string with the contextualization message. In case of ``headeronly`` flag is set to 'yes',
                    'true' or '1' only the initial part of the infrastructure contextualization log will be
                    returned (without any VM contextualization log).
      :``radl``: a string with the original specified RADL of the infrastructure.
      :``tosca``: a string with the TOSCA representation of the infrastructure. 
      :``data``: a string with the JSOMN serialized data of the infrastructure. In case of ``delete`` flag is set to 'yes',
                 'true' or '1' the data not only will be exported but also the infrastructure will be set deleted
                 (the virtual infrastructure will not be modified).
      :``authorization``: a list of strings with the current owners of the infrastructure. 
      :``state``: a JSON object with two elements:
      
         :``state``: a string with the aggregated state of the infrastructure (see list of valid states in :ref:`IM-States`).
         :``vm_states``: a dict indexed with the VM ID and the value the VM state (see list of valid states in :ref:`IM-States`).

   The result is JSON format has the following format::
   
    {
      ["radl"|"tosca"|"state"|"contmsg"|"outputs"|"data"|"authorization"]: <property_value>
    }

POST ``http://imserver.com/infrastructures/<infId>/authorization``
   :Response Content-type: text/plain or application/json
   :body Content-type: application/json
   :input fields: ``overwrite`` (optional)
   :ok response: 200 OK
   :fail response: 401, 404, 400, 403

   Change the authorization data of the infrastructure with ID ``infId``. using
   the authorization data provided in the body call. The ``overwrite`` parameter is
   optional and is a flag to specify if the authorization data will be overwrited or
   will be appended. Acceptable values: yes, no, true, false, 1 or 0. If not specified
   the flag is set to True.

   The body JSON format has the following format::

      {
         "username": "new_username",
         "password": "new_password"
      }

   or::

      {
         "token": "valid_oidc_access_token"
      }


POST ``http://imserver.com/infrastructures/<infId>``
   :body: ``RADL or TOSCA document``
   :body Content-type: text/plain, application/json or text/yaml
   :input fields: ``context`` (optional)
   :Response Content-type: text/uri-list
   :ok response: 200 OK
   :fail response: 401, 403, 404, 400, 415

   Add the resources specified in the body contents (in TOSCA, RADL plain or in JSON formats)
   to the infrastructure with ID ``infId``. 
   Using RADL the RADL restrictions are the same as in :ref:`RPC-XML AddResource <addresource-xmlrpc>`.
   
   Using TOSCA as input this method can be used to add or remove resources depending on the number of
   resources specified in the new TOSCA document sent. If new nodes are added in the body compared with the
   last TOSCA sent to the IM, these new nodes will be added. For example an infrastructure has been created
   with this TOSCA document: `tosca_create.yml <https://github.com/grycap/im/blob/master/test/files/tosca_create.yml>`_
   it launches one DB server and one Web server. If this TOSCA document is sent as body of this POST function: 
   `tosca_add.yml <https://github.com/grycap/im/blob/master/test/files/tosca_add.yml>`_, a new web server will be
   added as the number of web servers has been increased to two (``count`` parameter of ``scalable`` capability).
   However if this document is sent after the node addition (the number of web servers will be two):
   `tosca_remove.yml <https://github.com/grycap/im/blob/master/test/files/tosca_remove.yml>`_
   , a web server (the VM with the ID ``2`` as specified in the ``removal_list`` parameter) will be removed.

   If success, it is returned a list of URIs of the new virtual machines. The ``context`` parameter is
   optional and is a flag to specify if the contextualization step will be launched just after the VM
   addition. Acceptable values: yes, no, true, false, 1 or 0. If not specified the flag is set to True. 
   The result is JSON format has the following format::

    {
      "uri-list": [
         { "uri" : "http://server.com:8800/infrastructures/inf_id/vms/2" },
         { "uri" : "http://server.com:8800/infrastructures/inf_id/vms/3" }
       ] 
    }

PUT ``http://imserver.com/infrastructures/<infId>/stop``
   :Response Content-type: text/plain or application/json
   :ok response: 200 OK
   :fail response: 401, 403, 404, 400

   Perform the ``stop`` action in all the virtual machines in the
   the infrastructure with ID ``infID``. If the operation has been performed 
   successfully the return value is an empty string.
   
PUT ``http://imserver.com/infrastructures/<infId>/start``
   :Response Content-type: text/plain or application/json
   :ok response: 200 OK
   :fail response: 401, 403, 404, 400

   Perform the ``start`` action in all the virtual machines in the
   the infrastructure with ID ``infID``. If the operation has been performed 
   successfully the return value is an empty string.
   
PUT ``http://imserver.com/infrastructures/<infId>/reconfigure``
   :body: ``RADL document``
   :body Content-type: text/plain or application/json
   :input fields: ``vm_list`` (optional)
   :Response Content-type: text/plain
   :ok response: 200 OK
   :fail response: 401, 403, 404, 400, 415

   Perform the ``reconfigure`` action in all the virtual machines in the
   the infrastructure with ID ``infID``. It updates the configuration 
   of the infrastructure as indicated in the body contents (in plain RADL or in JSON formats). 
   The RADL restrictions are the same as in :ref:`RPC-XML Reconfigure <reconfigure-xmlrpc>`. If no
   RADL are specified, the contextualization process is stated again.
   The ``vm_list`` parameter is optional and is a coma separated list of
   IDs of the VMs to reconfigure. If not specified all the VMs will be reconfigured. 
   If the operation has been performed successfully the return value is an empty string.

DELETE ``http://imserver.com/infrastructures/<infId>``
   :input fields: ``force`` (optional), ``async`` (optional)
   :Response Content-type: text/plain or application/json
   :ok response: 200 OK
   :fail response: 401, 403, 404, 400

   Undeploy the virtual machines associated to the infrastructure with ID
   ``infId``. If the operation has been performed successfully 
   The ``force`` parameter is optional and is a flag to specify that the infra
   will be from the IM although not all resources are deleted.
   The return value is an empty string. If ``async`` is set to ``True``
   the call will not wait the infrastructure to be deleted.

GET ``http://imserver.com/infrastructures/<infId>/vms/<vmId>``
   :Response Content-type: text/plain or application/json
   :ok response: 200 OK
   :fail response: 401, 403, 404, 400

   Return information about the virtual machine with ID ``vmId`` associated to
   the infrastructure with ID ``infId``. The returned string is in RADL format,
   either in plain RADL or in JSON formats.
   See more the details of the output in :ref:`GetVMInfo <GetVMInfo-xmlrpc>`.
   The result is JSON format has the following format::
   
    {
      "radl": "<radl_in_json>"
    }

PUT ``http://imserver.com/infrastructures/<infId>/vms/<vmId>``
   :body: ``RADL document``
   :body Content-type: text/plain or application/json
   :Response Content-type: text/plain or application/json
   :ok response: 200 OK
   :fail response: 401, 403, 404, 400, 415

   Change the features of the virtual machine with ID ``vmId`` in the
   infrastructure with with ID ``infId``, specified by the RADL ``radl``.
   Return then information about the nodified virtual machine. The returned string is in RADL format,
   either in plain RADL or in JSON formats.
   See more the details of the output in :ref:`GetVMInfo <GetVMInfo-xmlrpc>`.
   The result is JSON format has the following format::
 
    {
      "radl": "<radl_in_json>"
    }

GET ``http://imserver.com/infrastructures/<infId>/vms/<vmId>/<property_name>``
   :Response Content-type: text/plain or application/json
   :ok response: 200 OK
   :fail response: 401, 403, 404, 400

   Return property ``property_name`` from to the virtual machine with ID 
   ``vmId`` associated to the infrastructure with ID ``infId``. It also has one
   special property ``contmsg`` that provides a string with the contextualization message
   of this VM. The result is JSON format has the following format::

    {
      "<property_name>": "<property_value>"
    }

DELETE ``http://imserver.com/infrastructures/<infId>/vms/<vmId>``
   :input fields: ``context`` (optional)
   :Response Content-type: text/plain
   :ok response: 200 OK
   :fail response: 401, 403, 404, 400

   Undeploy the virtual machine with ID ``vmId`` associated to the
   infrastructure with ID ``infId``. If  ``vmId`` is a comma separated list of 
   VM IDs, all the VMs of this list will be undeployed.  The ``context`` parameter is optional and 
   is a flag to specify if the contextualization step will be launched just after the VM
   addition. Acceptable values: yes, no, true, false, 1 or 0. If not specified the flag is set to True.
   If the operation has been performed successfully the return value is an empty string.

PUT ``http://imserver.com/infrastructures/<infId>/vms/<vmId>/start``
   :Response Content-type: text/plain or application/json
   :ok response: 200 OK
   :fail response: 401, 403, 404, 400

   Perform the ``start`` action in the virtual machine with ID 
   ``vmId`` associated to the infrastructure with ID ``infId``.
   If the operation has been performed successfully the return value is an empty string.

PUT ``http://imserver.com/infrastructures/<infId>/vms/<vmId>/stop``
   :Response Content-type: text/plain or application/json
   :ok response: 200 OK
   :fail response: 401, 403, 404, 400

   Perform the ``stop`` action in the virtual machine with ID 
   ``vmId`` associated to the infrastructure with ID ``infId``.
   If the operation has been performed successfully the return value is an empty string.

PUT ``http://imserver.com/infrastructures/<infId>/vms/<vmId>/reboot``
   :Response Content-type: text/plain or application/json
   :ok response: 200 OK
   :fail response: 401, 403, 404, 400

   Perform the ``reboot`` action in the virtual machine with ID
   ``vmId`` associated to the infrastructure with ID ``infId``.
   If the operation has been performed successfully the return value is an empty string.

GET ``http://imserver.com/version``
   :Response Content-type: text/plain or application/json
   :ok response: 200 OK
   :fail response: 400

   Return the version of the IM service. The result is JSON format has the following format::

    {
      "version": "1.4.4"
    }

PUT ``http://imserver.com/infrastructures/<infId>/vms/<vmId>/disks/<diskNum>/snapshot``
   :Response Content-type: text/plain or application/json
   :ok response: 200 OK
   :input fields: ``image_name`` (mandatory), ``auto_delete`` (optional)
   :fail response: 401, 403, 404, 400

   Create a snapshot of the specified ``diskNum`` in the VM ``vmId``
   of the infrastructure with ID ``infId``. 

   The ``autoDelete`` flag specifies that the snapshot will be deleted when
   the infrastructure is destroyed (default value false). If the operation has been performed
   successfully the return value is the image url of the new created image in
   IM format (see disk.<diskId>.image.url format in RADL).

GET ``http://imserver.com/clouds/<cloudId>/images``
   :Response Content-type: application/json
   :ok response: 200 OK
   :input fields: ``filters`` (optional)
   :fail response: 401, 400

   Return a list of URIs referencing the images available in the specified
   cloud provider ``cloudId``.
   The optional filters parameter enables filterin the list of images. It is
   a comma separated list of keypair values (``key1=val1,key2=value2``).
   This field is cloud provider specific (e.g. ``region=region_name`` for
   Amazon EC2, GCE or Azure).
   The id ``cloudId`` is relative to the id field in the AUTHORIZATION header.
   The result is JSON format has the following format::

   {
      "images":
         [
            {
               "uri" : "ost://hostname/image-id1",
               "name" : "Image Name1"
            },
            {
               "uri" : "ost://hostname/image-id2",
               "name" : "Image Name2"
            }
         ]
   }

GET ``http://imserver.com/clouds/<cloudId>/quotas``
   :Response Content-type: application/json
   :ok response: 200 OK
   :fail response: 401, 400

   Get the used and available resources in the specified
   cloud provider ``cloudId``.
   The id ``cloudId`` is relative to the id field in the AUTHORIZATION header.
   The result is JSON format has the following format::

    {
      "quotas": {
         "cores": {"used": 1, "limit": 10},
         "ram": {"used": 1, "limit": 10},
         "instances": {"used": 1, "limit": 10},
         "floating_ips": {"used": 1, "limit": 10},
         "security_groups": {"used": 1, "limit": 10}
      }
    }

GET ``http://imserver.com/stats``
   :Response Content-type: application/json
   :ok response: 200 OK
   :input fields: ``init_date`` (optional)
   :input fields: ``end_date`` (optional)
   :fail response: 401, 400

   Return the stats of the current user in the IM service.
   Return all the infrastructures deployed by the user showing some
   aggregated information. In JSON format::

    {
      "stats": [
                  {"creation_date": "2022-03-07 13:16:14",
                  "tosca_name": "kubernetes",
                  "vm_count": 2,
                  "cpu_count": 4,
                  "memory_size": 1024,
                  "cloud_type": "OSCAR",
                  "cloud_host": "server.com",
                  "hybrid": false,
                  "deleted": false,
                  "im_user": "username",
                  "inf_id": "1",
                  "last_date": "2022-03-23"}
      ]
    }

GET ``http://imserver.com/oai``
   :Response Content-type: text/xml
   :ok response: 200 OK

   Return the OAI-PMH REST API about available TOSCA templates in the IM service.
   See more details in `OAI-PMH spec <https://www.openarchives.org/pmh/>`_..
